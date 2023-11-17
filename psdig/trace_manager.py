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
from .trace_buffer import TraceBuffer
from .syscall import Syscall
from .event import Event
from .predefined_traces import predefined_traces
from .conf import LOGGER_NAME,BPF_OBJ_DIR
from .lambda_helper import *

predefined_trace_class = [
]

class TraceManager(object):
    def __init__(self, pid_filter=[], uid_filter=[]):
        self.set_logger()
        self.tp = TracePoint(pid_filter=pid_filter, uid_filter=uid_filter, obj_dir=BPF_OBJ_DIR)
        self.syscall = Syscall(self.tp)
        self.event = Event(self.tp)
        self.stats = {}
        self.callback = None
        self.trace_objs = []
        self.init_predefined_traces()
        self.init_trace_class()
        self.pi_cache = {}
        self.trace_id = 0
        self.collecting = False

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def init_trace_class(self):
        for cls in predefined_trace_class:
            try:
                trace_obj = cls(self)
            except:
                self.logger.error(traceback.format_exc())
            else:
                self.logger.info("added event:%s" % trace_obj.event_name)
            self.trace_objs.append(trace_obj)

    def init_predefined_traces(self):
        for ent in predefined_traces:
            name = ent['name']
            trigger = ent['trigger']
            trigger_type = trigger.split(':', 1)[0]
            trigger_value = trigger.split(':', 1)[1]
            if trigger_type == 'syscall':
                self.trace_register(name)
                syscall_name = trigger_value
                self.syscall.add(syscall_name, self.syscall_event_handler, ent)
            elif trigger_type == 'event':
                self.trace_register(name)
                event_name = trigger_value
                self.event.add(event_name, self.raw_event_handler, ent)

    def get_process_info(self, pid):
        key = f"{pid}"
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
            trace_name = event_def['name']
            level_lambda = event_def.get('level_lambda')
            if level_lambda:
                level_check = lambda metadata,args,ret: eval(level_lambda)
                level = level_check(metadata, args, ret)
            else:
                level = event_def.get('level', 'INFO')
            extend = {}
            syscall_info = "%d/%s" % (metadata['syscall_nr'], name)
            extend['syscall'] = syscall_info
            arg_list = [f"{k}={args[k]}" for k in args]
            extend['arguments'] = "\n".join(arg_list)
            extend['return code'] = ret
            extend['latency(ns)'] = metadata['latency']
            extend['cpu id'] = metadata['cpuid']
            extend['process'] = "%d/%s" % (metadata["pid"], metadata["comm"])
            try:
                elf,parent_proc = self.get_process_info(metadata["pid"])
            except:
                pass
            else:
                extend['elf'] = elf
                extend['parent processes'] = parent_proc
            trace = {
               "name": trace_name,
               "comm": metadata["comm"],
               "pid":  metadata["pid"],
               "uid":  metadata["uid"],
               "detail": detail,
               "level": level,
               "extend":extend
            }
            self.trace_send(trace)
        except:
            self.logger.error(f'error processing syscall:{name} ' + \
                f'args={args} metadata={metadata} ret={ret}')
            self.logger.error(traceback.format_exc())

    def raw_event_handler(self, name, metadata, args, ctx):
        try:
            event_def = ctx
            detail_fmt = event_def.get('detail_fmt')
            detail_lambda = event_def.get('detail_lambda')
            if detail_fmt:
                detail = detail_fmt.format(name=name, metadata=metadata, args=args)
            elif detail_lambda:
                detail_func = lambda name,metadata,args:eval(detail_lambda)
                detail = detail_func(name, metadata, args)
            else:
                detail = ""
            trace_name = event_def['name']
            level_lambda = event_def.get('level_lambda')
            if level_lambda:
                level_check = lambda metadata,args: eval(level_lambda)
                level = level_check(metadata,args)
            else:
                level = event_def.get('level', 'INFO')
            extend = {}
            extend['event'] = name
            arg_list = [f"{k}={args[k]}" for k in args]
            extend['arguments'] = "\n".join(arg_list)
            extend['cpu id'] = metadata['cpuid']
            extend['process'] = "%d/%s" % (metadata["pid"], metadata["comm"])
            try:
                elf,parent_proc = self.get_process_info(metadata["pid"])
            except:
                pass
            else:
                extend['elf'] = elf
                extend['parent processes'] = parent_proc
            trace = {
               "name": trace_name,
               "comm": metadata["comm"],
               "pid":  metadata["pid"],
               "uid":  metadata["uid"],
               "detail": detail,
               "level": level,
               "extend":extend
            }
            self.trace_send(trace)
        except:
            self.logger.error(f'error processing event:{name} ' + \
                f'args={args} metadata={metadata}')
            self.logger.error(traceback.format_exc())


    def trace_register(self, trace_name):
        self.stats[trace_name] = 0

    def trace_send(self, args):
        name = args['name']
        if 'extend' not in args:
            args['extend'] = {}
        if name in self.stats:
            self.stats[name] += 1
        else:
            self.stats[name] = 1
        if self.callback:
            args['id'] = self.trace_id
            self.callback(args)
        self.trace_id += 1
        
    def event_watch(self, event, callback):
        self.tp.add_event_watch(event, callback)

    def collect(self, callback):
        self.callback = callback
        self.logger.info("tracepoint start to run")
        self.tp.start(async_collect=True)
        self.collecting = True
        while self.collecting:
            time.sleep(1)

    def compile(self):
        self.logger.info("tracepoint start to compile objects ...")
        self.tp.start(compile_only=True)

    def file_read(self, event_file, callback):
        eb = TraceBuffer(file_path=event_file, persist=True)
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
        self.collecting = False

    def get_stats(self):
        return self.stats

    def loading_status(self):
        return self.tp.loading_status()

