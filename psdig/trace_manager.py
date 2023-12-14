# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com
import os
import sys
import re
import subprocess
import time
import logging
import traceback
try:
    import psutil
except:
    pass
import tempfile
from .tracepoint import TracePoint
from .event_tcp import EventTcpRecvRst,EventTcpSendRst
from .trace_buffer import TraceBuffer
from .syscall import Syscall
from .event import Event
from .uprobe import Uprobe
from .conf import LOGGER_NAME,BPF_OBJ_DIR
from .lambda_helper import *

class TraceManager(object):
    def __init__(self, pid_filter=[], 
                      uid_filter=[],
                      comm_filter=[],
                      conf=None,
                      tmp_dir='/var/tmp'):
        self.set_logger()
        self.tmp_dir = tmp_dir
        self.tp = TracePoint(pid_filter=pid_filter, uid_filter=uid_filter, comm_filter=comm_filter)
        self.uprobe = Uprobe(pid_filter=pid_filter, uid_filter=uid_filter, comm_filter=comm_filter)
        self.syscall = Syscall(self.tp)
        self.event = Event(self.tp)
        self.stats = {}
        self.callback = None
        self.trace_objs = []
        self.init_traces(conf)
        self.pi_cache = {}
        self.trace_id = 0
        self.collecting = False

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def init_traces(self, trace_conf):
        if trace_conf == None:
            return
        for syscall in trace_conf.iter_syscall():
            self.trace_register(syscall.name)
            self.syscall.add(syscall.syscall, self.syscall_event_handler, syscall) 
        for event in trace_conf.iter_event():
            self.trace_register(event.name)
            self.event.add(event.event, self.raw_event_handler, event)
        for uprobe in trace_conf.iter_uprobe():
            self.trace_register(uprobe.name)
            self.uprobe.add(uprobe.elf, uprobe.function, 
                  self.uprobe_handler, True, uprobe, uprobe.sym)
        for uretprobe in trace_conf.iter_uretprobe():
            self.trace_register(uretprobe.name)
            self.uprobe.add(uretprobe.elf, uretprobe.function, 
               self.uprobe_handler, False, uretprobe, uretprobe.sym)

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

    def syscall_event_handler(self, syscall, metadata, args, ret, ctx):
        try:
            syscall_trace = ctx
            trace_name = syscall_trace.name
            syscall_trace.eval_processors(metadata, syscall, args, ret)
            valid = syscall_trace.eval_filter(metadata, syscall, args, ret)
            if not valid:
                return
            detail = syscall_trace.eval_detail(metadata, syscall, args, ret)
            level = syscall_trace.eval_level(metadata, syscall, args, ret)
            extend = {}
            syscall_info = "%d/%s" % (metadata['syscall_nr'], syscall)
            extend['syscall'] = syscall_info
            arg_list = [f"{k}={args[k]}" for k in args]
            extend['arguments'] = "\n".join(arg_list)
            extend['return code'] = ret
            if 'latency' in metadata:
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
               "timestamp":  metadata["timestamp"],
               "detail": detail,
               "level": level,
               "extend":extend
            }
            self.trace_send(trace)
        except:
            self.logger.error(f'error processing syscall:{syscall} ' + \
                f'args={args} metadata={metadata} ret={ret}')
            self.logger.error(traceback.format_exc())

    def raw_event_handler(self, name, metadata, args, ctx):
        try:
            event_trace = ctx
            trace_name = event_trace.name
            event_trace.eval_processors(metadata, name, args)
            valid = event_trace.eval_filter(metadata, name, args)
            if not valid:
                return
            detail = event_trace.eval_detail(metadata, name, args)
            level = event_trace.eval_level(metadata, name, args)
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
            uprobe_trace = ctx
            uprobe_trace.eval_processors(metadata, function, args, ret)
            valid = uprobe_trace.eval_filter(metadata, function, args, ret)
            if not valid:
                return
            detail = uprobe_trace.eval_detail(metadata, function, args, ret)
            level = uprobe_trace.eval_level(metadata, function, args, ret)
            trace_name = uprobe_trace.name
            extend = {}
            extend['function'] = function['name']
            extend['elf'] = function['elf']
            extend['address'] = function['addr']
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
        self.logger.info(f'{event_nb} trace readed')
        return self.stats

    def stop(self):
        self.tp.stop()
        self.uprobe.stop()
        self.collecting = False

    def get_stats(self):
        return self.stats

    def loading_status(self):
        return self.tp.loading_status()

