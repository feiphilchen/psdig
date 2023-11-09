#!/usr/bin/python3
# vim: set filetype=python
import os
import sys
import re
import json
import subprocess
import time
import random
import shutil
import logging
import traceback
import pkgutil
import threading
from .schema import EventSchema
from .conf import LOGGER_NAME

class TracePoint(object):
    def __init__(self, pid_filter=[], 
                       uid_filter=[], 
                       ignore_self=True, 
                       obj_dir='/var/tmp/psdig',
                       obj_cache=True):
        self.event_handlers = {}
        self.set_logger()
        self.obj_dir = obj_dir
        self.obj_cache = obj_cache
        self.trace_event_elf = os.path.join(self.obj_dir, "trace_event")
        self.trace_event_c = os.path.join(self.obj_dir, "trace_event.c")
        self.trace_bpf_o = []
        self.schema_h = os.path.join(self.obj_dir, "event_schema.h")
        self.schema = EventSchema()
        self.proc = None
        self.pid_filter = pid_filter
        self.uid_filter = uid_filter
        self.ignore_self = ignore_self
        self.pid = os.getpid()
        self.init_obj_dir()
        self.callout_thread_running = False
        self.callout_thread = None
        self.event_bucket = {}
        self.event_mutex = threading.Lock()
        self.loading = 0
        self.loaded = 0

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def init_obj_dir(self):
        if not os.path.exists(self.obj_dir):
            os.makedirs(self.obj_dir)

    def add_event_watch(self, event, func, arg=None):
        handler = func,arg
        if event in self.event_handlers and self.event_handlers[event] != None:
            self.event_handlers[event].append(handler)
        else:
            self.event_handlers[event] = [handler]

    def delete_event_watch(self, event, handler):
        pass

    def get_event_list(self):
        events = []
        for event in self.event_handlers.keys():
            events.append(event)
        return events

    def get_event_id(self, event):
        event_id = event.replace('/', '_')
        event_id = event_id.lower()
        return event_id

    def build_bpf_c(self, event):
        event_id = event.replace('/', '_')
        event_id = event_id.lower()
        bpf_c_file = os.path.join(self.obj_dir, f"{event_id}.bpf.c")
        event_func = f"func_{event_id}"
        event_schema = self.schema.get_event_schema_name(event)
        content="""#include "trace_event.bpf.c"
EVENT_TRACE_FUNC("tracepoint/%s", %s, %s)
""" % (event, event_func, event_schema)
        with open(bpf_c_file, 'w') as fp:
            fp.write(content)
        return bpf_c_file

    def build_bpf_o(self, event):
        event_id = event.replace('/', '_')
        event_id = event_id.lower()
        bpf_o = os.path.join(self.obj_dir, f"{event_id}.bpf.o")
        if self.obj_cache and os.path.exists(bpf_o):
            self.trace_bpf_o.append(bpf_o)
            return
        bpf_c = self.build_bpf_c(event)
        cmd = f"clang -I/usr/local/share/psdig/usr/include -O2 -target bpf -c {bpf_c} -o {bpf_o}"
        #os.popen(cmd)
        subprocess.run(cmd, shell=True)
        self.trace_bpf_o.append(bpf_o)

    def copy_from_pkg(self, src, dst):
        data = pkgutil.get_data(__package__, src)
        with open(dst, 'wb') as fd:
            fd.write(data)

    def build_trace_objs(self):
        events = self.get_event_list()
        self.loading = len(events)
        self.logger.info('building schema ...')
        self.schema.build(events, self.schema_h)
        dst_file = os.path.join(self.obj_dir, 'trace_event.bpf.c')
        self.copy_from_pkg('trace_event/trace_event.bpf.c', dst_file)
        dst_file = os.path.join(self.obj_dir, 'event.h')
        self.copy_from_pkg('trace_event/event.h', dst_file)
        dst_file = os.path.join(self.obj_dir, 'trace_event.c')
        self.copy_from_pkg('trace_event/trace_event.c', dst_file)
        self.trace_bpf_o = []
        for event in events:
            self.logger.info('building event %s' % str(event))
            self.build_bpf_o(event)
            self.loaded += 1
        cmd = f"gcc {self.trace_event_c} -g -I/usr/local/share/psdig/usr/include -L/usr/local/share/psdig/usr/lib64/ -l:libbpf.a -ljson-c -lelf -lz -lpthread -o {self.trace_event_elf}"
        #os.popen(cmd)
        subprocess.run(cmd, shell=True)

    def call_event_handlers(self, event_obj):
        event = event_obj['event']
        if self.ignore_self:
            if self.pid == event_obj['pid']:
                return
            if event_obj['comm'] == 'trace_event':
                return
        if event in self.event_handlers:
            for handler in self.event_handlers[event]:
                func,arg = handler
                if arg == None:
                    func(event_obj)
                else:
                    func(event_obj, arg)

    def loading_status(self):
        return self.loading,self.loaded

    def events_callout(self, events):
        events.sort(key=lambda x: x['ktime_ns'], reverse=False)
        for event_obj in events:
            self.call_event_handlers(event_obj)

    def callout(self):
        while self.callout_thread_running:
            time_now = time.time()
            to_delete = []
            with self.event_mutex:
                for key in sorted(self.event_bucket):
                    if time_now - self.event_bucket[key]['last_updated'] > 1:
                        self.events_callout(self.event_bucket[key]['events'])
                        to_delete.append(key)
                for key in to_delete:
                    del self.event_bucket[key]
            time.sleep(0.1)

    def start_callout_thread(self):
        self.callout_thread_running = True
        self.callout_thread = threading.Thread(target = self.callout, args = (), daemon=True)
        self.callout_thread.start()

    def event_obj_enqueue(self, event_obj):
        ktime_ns = event_obj['ktime_ns']
        bucket_key = int(ktime_ns/1000000000)
        time_now = time.time()
        with self.event_mutex:
            if bucket_key not in self.event_bucket:
                self.event_bucket[bucket_key] = {"last_updated":time_now, "events":[]}
            self.event_bucket[bucket_key]['last_updated'] = time_now
            self.event_bucket[bucket_key]['events'].append(event_obj)

    def start(self, compile_only=False):
        try:
            self.build_trace_objs()
        except:
            self.logger.error('error building trace objects')
            self.logger.error(traceback.format_exc())
        time.sleep(1)
        cmd = [self.trace_event_elf]
        for obj in self.trace_bpf_o:
            cmd.append("-o")
            cmd.append(obj)
        for pid in self.pid_filter:
            cmd.append("-p")
            cmd.append(str(pid))
        for uid in self.uid_filter:
            cmd.append("-u")
            cmd.append(str(uid))
        cmd_str = " ".join(cmd)
        self.logger.info('starting event trace ...')
        self.logger.info(f'{cmd_str}')
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        if compile_only:
            return
        self.logger.info('running now')
        self.start_callout_thread()
        json_str = None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                break
            try:
                line = line.decode()
            except:
                continue
            if json_str == None:
                if line == "{\n":
                    json_str = line
            elif line == "}\n":
                json_str += line
                event_obj = json.loads(json_str)
                #self.call_event_handlers(event_obj)
                self.event_obj_enqueue(event_obj)
                json_str = None
            else:
                json_str += line
        self.logger.info('trace_event exiting')
        if self.callout_thread:
            self.callout_thread_running = False
            self.callout_thread.join()
            self.callout_thread = None
        self.proc = None

    def stop(self):
        self.logger.info('trace collect is being stopped ...')
        if self.proc != None:
            self.proc.terminate()


