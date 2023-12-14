# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com
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
from .data_type import *
from .schema import EventSchema
from .conf import LOGGER_NAME

class TracePoint(object):
    type_mapping = {
       "ptr": Pointer,
       "bytes": Bytes,
       "sockaddr":SockAddr
    }
    def __init__(self, pid_filter=[], 
                       uid_filter=[], 
                       comm_filter=[],
                       ignore_self=True, 
                       obj_cache=True):
        self.event_handlers = {}
        self.syscall_handlers = {}
        self.syscall_events = {}
        self.set_logger()
        self.obj_cache = obj_cache
        self.trace_bpf_o = []
        self.schema = EventSchema()
        self.proc = None
        self.pid_filter = pid_filter
        self.uid_filter = uid_filter
        self.comm_filter = comm_filter
        self.ignore_self = ignore_self
        self.pid = os.getpid()
        self.callout_thread_running = False
        self.callout_thread = None
        self.collect_thread_running = False
        self.collect_thread = None
        self.event_bucket = {}
        self.event_mutex = threading.Lock()
        self.loading = 0
        self.loaded = 0

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def init_obj_dir(self, obj_dir):
        self.obj_dir = obj_dir
        self.trace_event_elf = os.path.join(self.obj_dir, "trace_event")
        self.trace_event_c = os.path.join(self.obj_dir, "trace_event.c")
        self.schema_h = os.path.join(self.obj_dir, "event_schema.h")
        if not os.path.exists(self.obj_dir):
            os.makedirs(self.obj_dir)

    def add_event_watch(self, event, func, arg=None):
        handler = func,arg
        if event in self.event_handlers and self.event_handlers[event] != None:
            self.event_handlers[event].append(handler)
        else:
            self.event_handlers[event] = [handler]

    def add_syscall_watch(self, syscall, events, func, arg=None):
        handler = func,arg
        enter_event = events[0]
        if enter_event in self.syscall_handlers and self.syscall_handlers[enter_event] != None:
            self.syscall_handlers[enter_event].append(handler)
        else:
            self.syscall_handlers[enter_event] = [handler]
        self.syscall_events[syscall] = events

    def delete_event_watch(self, event, handler):
        pass

    def get_event_list(self):
        events = []
        for event in self.event_handlers.keys():
            events.append(event)
        for syscall in self.syscall_events:
            events += self.syscall_events[syscall]
        return list(set(events))

    def get_event_id(self, event):
        event_id = event.replace('/', '_')
        event_id = event_id.lower()
        return event_id

    def build_event_bpf_c(self, event):
        event_id = event.replace('/', '_')
        event_id = event_id.lower()
        bpf_c_file = os.path.join(self.obj_dir, f"event_{event_id}.bpf.c")
        event_func = f"func_{event_id}"
        event_schema = self.schema.get_event_schema_name(event)
        content="""#include "trace_event.bpf.c"
EVENT_TRACE_FUNC("tracepoint/%s", %s, %s)
""" % (event, event_func, event_schema)
        with open(bpf_c_file, 'w') as fp:
            fp.write(content)
        return bpf_c_file

    def build_event_bpf_o(self, event):
        event_id = event.replace('/', '_')
        event_id = event_id.lower()
        bpf_o = os.path.join(self.obj_dir, f"event_{event_id}.bpf.o")
        if self.obj_cache and os.path.exists(bpf_o):
            self.trace_bpf_o.append(bpf_o)
            return
        bpf_c = self.build_event_bpf_c(event)
        cmd = f"clang -I/usr/local/share/psdig/usr/include -O2 -target bpf -c {bpf_c} -o {bpf_o}"
        #os.popen(cmd)
        subprocess.run(cmd, shell=True)
        self.trace_bpf_o.append(bpf_o)

    def build_syscall_bpf_c(self, events):
        enter_event_id = events[0].replace('/', '_')
        enter_event_id = enter_event_id.lower()
        bpf_c_file = os.path.join(self.obj_dir, f"syscall_{enter_event_id}.bpf.c")
        enter_event_func = f"func_{enter_event_id}"
        content = "#include \"trace_event.bpf.c\"\n"
        enter_schema = self.schema.get_event_schema_name(events[0])
        if len(events) > 1:
            exit_schema = self.schema.get_event_schema_name(events[1])
            exit_event_id = events[1].replace('/', '_')
            exit_event_id = exit_event_id.lower()
            exit_event_func = f"func_{exit_event_id}"
        else:
            exit_schema = None
        if exit_schema != None:
            content += "SYSCALL_START_FUNC(\"tracepoint/%s\", %s, %s, 0)\n" % (events[0], enter_event_func, enter_schema)
            content += "SYSCALL_FINISH_FUNC(\"tracepoint/%s\", %s, %s, %s)\n" % (events[1], exit_event_func, enter_schema, exit_schema)
        else:
            content += "SYSCALL_START_FUNC(\"tracepoint/%s\", %s, %s, 1)\n" % (events[0], enter_event_func, enter_schema)
        with open(bpf_c_file, 'w') as fp:
            fp.write(content)
        return bpf_c_file
 
    def build_syscall_bpf_o(self, syscall):
        events = self.syscall_events[syscall]
        event_id = events[0].replace('/', '_')
        event_id = event_id.lower()
        bpf_o = os.path.join(self.obj_dir, f"syscall_{event_id}.bpf.o")
        if self.obj_cache and os.path.exists(bpf_o):
            self.trace_bpf_o.append(bpf_o)
            return
        bpf_c = self.build_syscall_bpf_c(events)
        cmd = f"clang -I/usr/local/share/psdig/usr/include -O2 -target bpf -c {bpf_c} -o {bpf_o}"
        #os.popen(cmd)
        subprocess.run(cmd, shell=True)
        self.trace_bpf_o.append(bpf_o)

    def copy_from_pkg(self, src, dst):
        data = pkgutil.get_data(__package__, src)
        with open(dst, 'wb') as fd:
            fd.write(data)

    def build_schema(self, events):
        if self.obj_cache and os.path.exists(self.schema_h):
            return
        self.logger.info('building schema ...')
        self.schema.build(events, self.schema_h)

    def build_trace_event(self):
        if self.obj_cache and os.path.exists(self.trace_event_elf):
            return
        cmd = f"gcc {self.trace_event_c} -g -I/usr/local/share/psdig/usr/include -L/usr/local/share/psdig/usr/lib64/ -L/usr/local/share/psdig/usr/lib -l:libbpf.a -l:libjson-c.a -lelf -lz -lpthread -o {self.trace_event_elf}"
        subprocess.run(cmd, shell=True)
 
    def build_trace_objs(self):
        events = self.get_event_list()
        self.loading = len(self.syscall_events) + len(self.event_handlers)
        self.build_schema(events)
        dst_file = os.path.join(self.obj_dir, 'trace_event.bpf.c')
        self.copy_from_pkg('trace_event/trace_event.bpf.c', dst_file)
        dst_file = os.path.join(self.obj_dir, 'event.h')
        self.copy_from_pkg('trace_event/event.h', dst_file)
        dst_file = os.path.join(self.obj_dir, 'trace_event.c')
        self.copy_from_pkg('trace_event/trace_event.c', dst_file)
        self.trace_bpf_o = []
        for event in self.event_handlers.keys():
            self.logger.debug('building bpf object for event %s' % str(event))
            self.build_event_bpf_o(event)
            self.loaded += 1
        for syscall in self.syscall_events:
            self.logger.debug('building bpf object for syscall %s' % str(syscall))
            self.build_syscall_bpf_o(syscall)
            self.loaded += 1
        self.build_trace_event()

    def params_type_convert(self, event_obj):
        if 'schema' in event_obj:
            for arg in event_obj['schema']:
                arg_type = event_obj['schema'][arg]
                if arg_type in self.type_mapping:
                    cls = self.type_mapping[arg_type]
                    new_value = cls(event_obj['parameters'][arg])
                    event_obj['parameters'][arg] = new_value

    def call_event_handlers(self, event_obj):
        event = event_obj['event']
        self.params_type_convert(event_obj)
        if event in self.event_handlers:
            for handler in self.event_handlers[event]:
                func,arg = handler
                try:
                    if arg == None:
                        func(event_obj)
                    else:
                        func(event_obj, arg)
                except:
                    self.logger.error(traceback.format_exc())

    def call_syscall_handlers(self, event_obj):
        event = event_obj['event']
        self.params_type_convert(event_obj)
        if event in self.syscall_handlers:
            for handler in self.syscall_handlers[event]:
                func,arg = handler
                try:
                    if arg == None:
                        func(event_obj)
                    else:
                        func(event_obj, arg)
                except:
                    self.logger.error(traceback.format_exc())

    def loading_status(self):
        return self.loading,self.loaded

    def events_callout(self, events):
        events.sort(key=lambda x: x['ktime_ns'], reverse=False)
        for event_obj in events:
            is_syscall = event_obj.get('syscall', False)
            if not is_syscall:
                self.call_event_handlers(event_obj)
            else:
                self.call_syscall_handlers(event_obj)

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

    def collect(self):
        json_str = None
        self.collect_thread_running = True
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
        for comm in self.comm_filter:
            cmd.append("-c")
            cmd.append(str(comm))
        cmd.append('-x')
        cmd.append(str(self.pid))
        cmd_str = " ".join(cmd)
        self.logger.debug(f'{cmd_str}')
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        while self.collect_thread_running:
            line = self.proc.stdout.readline()
            if not line:
                break
            try:
                #line = line.decode('unicode_escape')
                line = line.decode(errors='ignore')
            except:
                self.logger.error(str(line))
                self.logger.error(traceback.format_exc())
                continue
            if json_str == None:
                if line == "{\n":
                    json_str = line
            elif line == "}\n":
                json_str += line
                try:
                    event_obj = json.loads(json_str, strict=False)
                except:
                    self.logger.error(json_str)
                    self.logger.error(traceback.format_exc())
                    json_str = None
                    continue
                #self.call_event_handlers(event_obj)
                self.event_obj_enqueue(event_obj)
                json_str = None
            else:
                json_str += line
        if self.callout_thread:
            self.callout_thread_running = False
            self.callout_thread.join()
            self.callout_thread = None
        self.proc = None

    def start_collect_thread(self):
        self.collect_thread_running = True
        self.collect_thread = threading.Thread(target = self.collect, args = (), daemon=True)
        self.collect_thread.start()

    def start(self, compile_only=False, async_collect=False, obj_dir="/var/tmp"):
        self.init_obj_dir(obj_dir)
        try:
            self.build_trace_objs()
        except:
            self.logger.error('error building trace objects')
            self.logger.error(traceback.format_exc())
        time.sleep(1)
        if compile_only:
            return
        self.logger.info('running now')
        self.start_callout_thread()
        if not async_collect:
            self.collect()
        else:
            self.start_collect_thread()

    def stop(self):
        self.logger.info('tracepoint is being stopped ...')
        self.collect_thread_running = False
        self.callout_thread_running = False
        if self.proc != None:
            self.proc.terminate()


