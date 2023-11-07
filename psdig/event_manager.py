#!/usr/bin/python3
# vim: set filetype=python
import os
import sys
import re
import json
import subprocess
import time
import logging
import traceback
import psutil
from .tracepoint import TracePoint
from .event_tcp import EventTcpRecvRst,EventTcpSendRst
from .event_buffer import EventBuffer
from .syscall import Syscall
from .event_syscall import predefined_syscall_events
from .conf import LOGGER_NAME

predefined_events = [
    EventTcpRecvRst,
    EventTcpSendRst
]

class EventManager(object):
    def __init__(self, pid_filter=[], uid_filter=[]):
        self.set_logger()
        self.tp = TracePoint(pid_filter=pid_filter, uid_filter=uid_filter)
        self.syscall = Syscall(self.tp)
        self.stats = {}
        self.callback = None
        self.event_objs = []
        self.init_event_syscall()
        self.init_event_class()
        self.pi_cache = {}
        self.evt_id = 0

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def init_event_class(self):
        for cls in predefined_events:
            try:
                event_obj = cls(self)
            except:
                self.logger.error(traceback.format_exc())
            else:
                self.logger.info("added event:%s" % event_obj.event_name)
            self.event_objs.append(event_obj)

    def init_event_syscall(self):
        for evt in predefined_syscall_events:
            event_name = evt['event']
            syscall_name = evt['syscall']
            self.event_register(event_name)
            self.syscall.add(syscall_name, self.syscall_event_handler, evt)

    def get_process_info(self, pid, cmd):
        key = f"{pid}/{cmd}"
        if key in self.pi_cache:
            return self.pi_cache[key]
        ps = psutil.Process(pid)
        exe = ps.exe()
        pid = ps.ppid()
        parent_process = []
        while pid != 0:
            ps = psutil.Process(pid)
            name = ps.name()
            pp = f"{pid}/{name}"
            parent_process.append(pp)
            pid = ps.ppid()
        self.pi_cache[key] = exe,parent_process
        return exe,parent_process

    def syscall_event_handler(self, name, metadata, args, ret, ctx):
        try:
            event_def = ctx
            detail_fmt = event_def.get('detail_fmt')
            detail_lambda = event_def.get('detail_lambda')
            if detail_fmt:
                detail = detail_fmt.format(name=name, metadata=metadata, args=args, ret=ret)
            elif detail_lambda:
                detail_func = lambda name,metadata,args,ret:eval(detail_lambda)
                detail = detail_func(name, metadata, args, ret)
            else:
                detail = ""
            event_name = event_def['event']
            result_check = lambda ret: eval(event_def['result'])
            syscall_ok = result_check(ret)
            extend = {}
            extend['syscall name'] = name
            extend['syscall no.'] = metadata['syscall_nr']
            arg_list = [f"{k}={args[k]}" for k in args]
            extend['arguments'] = "\n".join(arg_list)
            extend['return code'] = ret
            extend['latency(ns)'] = metadata['latency']
            extend['cpu id'] = metadata['cpuid']
            extend['process'] = "%d/%s" % (metadata["pid"], metadata["comm"])
            try:
                elf,parent_proc = self.get_process_info(metadata["pid"], metadata["comm"])
            except:
                pass
            else:
                extend['elf'] = elf
                extend['parent processes'] = "\n".join(parent_proc)
            event = {
               "name": event_name,
               "comm": metadata["comm"],
               "pid":  metadata["pid"],
               "uid":  metadata["uid"],
               "detail": detail,
               "ok": syscall_ok,
               "extend":extend
            }
            self.event_send(event)
        except:
            self.logger.error(f'error processing syscall:{name} ' + \
                f'args={args} metadata={metadata} ret={ret}')
            self.logger.error(traceback.format_exc())

    def event_register(self, event_name):
        self.stats[event_name] = 0

    def event_send(self, args):
        name = args['name']
        if 'extend' not in args:
            args['extend'] = {}
        if name in self.stats:
            self.stats[name] += 1
        else:
            self.stats[name] = 1
        if self.callback:
            args['id'] = self.evt_id
            self.callback(args)
        self.evt_id += 1
        
    def event_watch(self, event, callback):
        self.tp.add_event_watch(event, callback)

    def collect(self, callback):
        self.callback = callback
        self.logger.info("tracepoint start to run")
        self.tp.start()

    def file_read(self, event_file, callback):
        eb = EventBuffer(file_path=event_file, persist=True)
        event_nb = eb.length()
        for pos in range(0, event_nb):
            event = eb.read(pos)
            name = event['name']
            if name in self.stats:
                self.stats[name] += 1
            else:
                self.stats[name] = 1
            callback(event)
        return event_nb

    def stop(self):
        self.tp.stop()

    def get_stats(self):
        return self.stats

    def loading_status(self):
        return self.tp.loading_status()

