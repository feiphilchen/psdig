#!/usr/bin/python3
# vim: set filetype=python
import os
import sys
import re
import subprocess
import time
import logging
import traceback
import psutil
import tempfile
from .tracepoint import TracePoint
from .event_tcp import EventTcpRecvRst,EventTcpSendRst
from .trace_buffer import TraceBuffer
from .syscall import Syscall
from .event import Event
from .uprobe import Uprobe
from .predefined_traces import predefined_traces
from .conf import LOGGER_NAME,BPF_OBJ_DIR
from .lambda_helper import *

predefined_trace_class = [
]

class TraceManager(object):
    def __init__(self, pid_filter=[], 
                      uid_filter=[],
                      trace_def=None,
                      tmp_dir='/var/tmp'):
        self.set_logger()
        self.tmp_dir = tmp_dir
        self.tp = TracePoint(pid_filter=pid_filter, uid_filter=uid_filter)
        self.uprobe = Uprobe(pid_filter=pid_filter, uid_filter=uid_filter)
        self.syscall = Syscall(self.tp)
        self.event = Event(self.tp)
        self.stats = {}
        self.callback = None
        self.trace_objs = []
        self.init_traces(trace_def)
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

    def init_traces(self, trace_def):
        if trace_def == None:
            trace_definition = predefined_traces
        else:
            trace_definition = trace_def
        for ent in trace_definition:
            name = ent['name']
            trigger = ent['trigger']
            trigger_type = trigger.split(':', 1)[0]
            if trigger_type == 'syscall':
                self.trace_register(name)
                syscall_name = trigger.split(':', 1)[1]
                self.syscall.add(syscall_name, self.syscall_event_handler, ent)
            elif trigger_type == 'event':
                self.trace_register(name)
                event_name = trigger.split(':', 1)[1]
                self.event.add(event_name, self.raw_event_handler, ent)
            elif trigger_type == 'uprobe':
                self.trace_register(name)
                elf = ent.get('elf')
                function = ent.get('function')
                ret = ent.get('return', False)
                sym = ent.get('sym')
                self.uprobe.add(elf, function, self.uprobe_handler, not ret, ent, sym)

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
            detail_def = event_def.get('detail')
            detail = None
            if detail_def:
                if isinstance(detail_def, str):
                    detail_fmt = detail_def
                    detail = detail_fmt.format(name=name, metadata=metadata, args=args, ret=ret)
                elif isinstance(detail_def, dict):
                    detail_lambda = detail_def.get('lambda')
                    if detail_lambda:
                        detail_func = lambda name,metadata,args,ret:eval(detail_lambda)
                        detail = detail_func(name, metadata, args, ret)
            if detail == None:
                default_lambda = "','.join([ f'{key}={val}' for key,val in args.items()])"
                detail_func =  lambda name,metadata,args,ret:eval(default_lambda)
                detail = detail_func(name, metadata, args, ret)
            level_def = event_def.get('level')
            level = None
            if level_def:
                if isinstance(level_def, str):
                    level = level_def
                elif isinstance(level_def, dict):
                    level_lambda = level_def.get('lambda')
                    if level_lambda:
                        level_check = lambda name,metadata,args,ret: eval(level_lambda)
                        level = level_check(name, metadata, args, ret)
            if level == None:
                level = 'INFO'
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
            trace_name = event_def['name']
            trace = {
               "name": trace_name,
               "comm": metadata["comm"],
               "pid":  metadata["pid"],
               "uid":  metadata["uid"],
               "timestamp":  metadata["timestamp"],
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
            detail_def = event_def.get('detail')
            detail = None
            if detail_def:
                if isinstance(detail_def, str):
                    detail_fmt = detail_def
                    detail = detail_fmt.format(name=name, metadata=metadata, args=args)
                elif isinstance(detail_def, dict):
                    detail_lambda = detail_def.get('lambda')
                    if detail_lambda:
                        detail_func = lambda name,metadata,args:eval(detail_lambda)
                        detail = detail_func(name, metadata, args)
            if detail == None:
                default_lambda = "','.join([ f'{key}={val}' for key,val in args.items()])"
                detail_func =  lambda name,metadata,args:eval(default_lambda)
                detail = detail_func(name, metadata, args)
            level_def = event_def.get('level')
            level = None
            if level_def:
                if isinstance(level_def, str):
                    level = level_def
                elif isinstance(level_def, dict):
                    level_lambda = level_def.get('lambda')
                    if level_lambda:
                        level_check = lambda name,metadata,args: eval(level_lambda)
                        level = level_check(name, metadata, args)
            if level == None:
                level = 'INFO'
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
            trace_name = event_def['name']
            trace = {
               "name": trace_name,
               "comm": metadata["comm"],
               "pid":  metadata["pid"],
               "uid":  metadata["uid"],
               "timestamp":  metadata["timestamp"],
               "detail": detail,
               "level": level,
               "extend":extend
            }
            self.trace_send(trace)
        except:
            self.logger.error(f'error processing event:{name} ' + \
                f'args={args} metadata={metadata}')
            self.logger.error(traceback.format_exc())

    def uprobe_handler(self, function, metadata, args, ret, ctx):
        try:
            event_def = ctx
            detail_def = event_def.get('detail')
            detail = None
            if detail_def:
                if isinstance(detail_def, str):
                    detail_fmt = detail_def
                    detail = detail_fmt.format(metadata=metadata, function=function, args=args, ret=ret)
                elif isinstance(detail_def, dict):
                    detail_lambda = detail_def.get('lambda')
                    if detail_lambda:
                        detail_func = lambda function,metadata,args,ret:eval(detail_lambda)
                        detail = detail_func(function, metadata, args, ret)
            if detail == None:
                default_lambda = "function_format(function, args, ret)"
                detail_func =  lambda function,metadata,args,ret:eval(default_lambda)
                detail = detail_func(function, metadata, args, ret)
            level_def = event_def.get('level')
            level = None
            if level_def:
                if isinstance(level_def, str):
                    level = level_def
                elif isinstance(level_def, dict):
                    level_lambda = level_def.get('lambda')
                    if level_lambda:
                        level_check = lambda function,metadata,args,ret: eval(level_lambda)
                        level = level_check(function, metadata, args, ret)
            if level == None:
                level = 'INFO'
            trace_name = event_def.get('name')
            extend = {}
            extend['function'] = function
            if args:
                arg_list = [f"{k}={args[k]}" for k in args]
                extend['arguments'] = "\n".join(arg_list)
            if ret:
                extend['return'] = ret
            extend['cpu id'] = metadata['cpuid']
            extend['process'] = "%d/%s" % (metadata["pid"], metadata["comm"])
            trace = {
               "name": trace_name,
               "comm": metadata["comm"],
               "pid":  metadata["pid"],
               "uid":  metadata["uid"],
               "timestamp":  metadata["timestamp"],
               "detail": detail,
               "level": level,
               "extend":extend
            }
            self.trace_send(trace)
        except:
            self.logger.error(f'error processing uprobe:{function} ' + \
                f'args={args} ret={ret} metadata={metadata}')
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
        self.logger.info("uprobe start to run")
        self.uprobe.start(obj_dir=self.tmp_dir, async_collect=True)
        self.tp.start(obj_dir=BPF_OBJ_DIR, async_collect=True)
        self.collecting = True
        while self.collecting:
            time.sleep(1)

    def compile(self):
        self.logger.info("tracepoint start to compile objects ...")
        self.tp.start(obj_dir=BPF_OBJ_DIR, compile_only=True)

    def file_read(self, event_file, callback):
        eb = TraceBuffer(file_path=event_file)
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

