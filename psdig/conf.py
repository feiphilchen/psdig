import os
import sys
import logging
import json
import pkgutil
from importlib import import_module
from .lambda_helper import *

LOGGER_NAME="psdig"
BPF_OBJ_DIR="/usr/local/share/psdig/bpf"
TRACEFS="/sys/kernel/debug/tracing/events"

class TraceConf(object):
    name = None
    level = None
    detail = None
    def __init__(self, name, level, detail, filter):
        self.name = name
        self.detail = detail
        self.level = level
        self.filter = filter

class SyscallTraceConf(TraceConf):
    syscall = None
    processors=None
    def __init__(self, name=None,
                       detail=None,
                       level=None,
                       filter=None,
                       syscall=None,
                       processors=None): 
        super().__init__(name, level, detail, filter)
        self.syscall = syscall
        self.processors = processors

    def eval_detail(self, metadata, name, args, ret):
        detail_def = self.detail
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
        return detail

    def eval_level(self, metadata, name, args, ret):
        level_def = self.level
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
        return level

    def eval_processors(self, metadata, name, args, ret):
        if self.processors == None:
            return
        for p in self.processors:
            if hasattr(p, "syscall"):
                p.syscall(metadata, name, args, ret)

class EventTraceConf(TraceConf):
    event = None
    processors=None
    def __init__(self, name=None,
                       detail=None,
                       level=None,
                       filter=None,
                       event=None,
                       processors=None):
        super().__init__(name, level, detail, filter)
        self.event = event
        self.processors = processors

    def eval_detail(self, metadata, name, args):
        detail_def = self.detail
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
        return detail

    def eval_level(self, metadata, name, args):
        level_def = self.level
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
        return level

    def eval_processors(self, metadata, name, args):
        if self.processors == None:
            return
        for p in self.processors:
            if hasattr(p, "event"):
                p.event(metadata, name, args)

class UprobeTraceConf(TraceConf):
    elf = None
    function = None
    sym = None
    processors=None
    def __init__(self, name=None,
                       detail=None,
                       level=None,
                       filter=None,
                       elf=None,
                       function=None,
                       sym=None,
                       processors=None):
        super().__init__(name, level, detail, filter)
        self.elf = elf
        self.function = function
        self.sym = sym
        self.processors = processors

    def eval_detail(self, metadata, function, args, ret):
        detail = None
        detail_def = self.detail
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
            default_lambda = "uprobe_format(function, args, ret, metadata, brief=True)"
            detail_func =  lambda function,metadata,args,ret:eval(default_lambda)
            detail = detail_func(function, metadata, args, ret)
        return detail

    def eval_level(self, metadta, function, args, ret):
        level_def = self.level
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
        return level

    def eval_processors(self, metadata, function, args, ret):
        if self.processors == None:
            return
        for p in self.processors:
            if hasattr(p, "uprobe"):
                p.uprobe(metadata, function, args, ret)

class TraceConfFile(object):
    trace_type = ["syscall", "event", "uprobe", "uretprobe"]
    def __init__(self, fd=None):
        if fd != None:
            self.content = fd.read()
        else:
            self.content = self.read_default_conf()
        self.event = []
        self.syscall = []
        self.uprobe = []
        self.uretprobe = []
        self.processors = {}

    def read_default_conf(self):
        content = pkgutil.get_data(__package__, "predefined_traces.json")
        if isinstance(content, bytes):
            return content.decode()
        else:
            return content

    def load_processors(self, processors):
        pobjs = []
        for p in processors:
            if p in self.processors:
                pobjs.append(self.processors[p])
                continue
            try:
                m,cls_name = p.rsplit('.', 1)
                mod = import_module(m)
                cls = getattr(mod, cls_name)
                self.processors[p] = cls()
            except:
                raise ValueError(f"error loading processor {p}")
            else:
                pobjs.append(self.processors[p])
        return pobjs

    def load(self):
        try:
            json_conf = json.loads(self.content)
        except:
            return "not a JSON format file"
        trace_def = json_conf.get("traces", [])
        for conf in trace_def:
            conf_str = json.dumps(conf, indent=3)
            trace_type = conf['type']
            if trace_type not in self.trace_type:
                return f"invalid trace type: {trace_type}\n{conf_str}"
            name = conf.get('name')
            if name == None:
                return f"name is mandatory for trace definition\n{conf_str}"
            param = conf.get('parameters')
            if param == None:
                return f"no parameters specified for trace\n{conf_str}"
            try:
                processors = conf.get('processor')
                if processors != None:
                    pobjs = self.load_processors(processors)
                else:
                    pobjs = None
                if trace_type == "syscall":
                    syscall = SyscallTraceConf(name=name, processors=pobjs, **param)
                    self.syscall.append(syscall)
                elif trace_type == "event":
                    event = EventTraceConf(name=name, processors=pobjs, **param)
                    self.event.append(event)
                elif trace_type == "uprobe":
                    uprobe = UprobeTraceConf(name=name, processors=pobjs, **param)
                    self.uprobe.append(uprobe)
                elif trace_type == "uretprobe":
                    uretprobe = UprobeTraceConf(name=name, processors=pobjs, **param)
                    self.uretprobe.append(uretprobe)
            except ValueError as e:
                return f"{e}\n{conf_str}"
        return None

    def iter_syscall(self):
        for syscall in self.syscall:
            yield syscall

    def iter_event(self):
        for event in self.event:
            yield event

    def iter_uprobe(self):
        for uprobe in self.uprobe:
            yield uprobe

    def iter_uretprobe(self):
        for uretprobe in self.uretprobe:
            yield uretprobe

    def read(self):
        return json.loads(self.content)

