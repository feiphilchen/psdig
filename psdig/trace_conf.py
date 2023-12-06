import os
import sys
import logging
import json
import pkgutil
from importlib import import_module
from .lambda_helper import *
from .dwarf import Dwarf
from .syscall import Syscall
from .event import Event
from .conf import LOGGER_NAME

class TraceConf(object):
    name = None
    level = None
    detail = None
    filter = None
    level_enum = ["DEBUG", "INFO", "WARNING", "ERROR"]
    def __init__(self, name, level, detail, filter):
        self.name = name
        self.detail = detail
        self.level = level
        self.filter = filter
        self.logger = logging.getLogger(LOGGER_NAME)

    def validate(self):
        if self.name == None:
            raise ValueError("trace name should not be null")
        if not isinstance(self.name, str):
            raise ValueError("trace name should be a string")
        if self.detail and not isinstance(self.detail, str) and not isinstance(self.detail, dict):
            raise ValueError("detail should be a string or dict")
        if self.level and not isinstance(self.level, str) and not isinstance(self.level, dict):
            raise ValueError("level should be a string or dict")
        if self.filter and not isinstance(self.filter, bool) and not isinstance(self.filter, dict):
            raise ValueError("filter should be a boolean or dict")
        if isinstance(self.detail, dict) and "lambda" not in self.detail:
            raise ValueError("no lambda expression in detail")
        if isinstance(self.level, dict) and "lambda" not in self.level:
            raise ValueError("no lambda expression in level")
        if isinstance(self.filter, dict) and "lambda" not in self.filter:
            raise ValueError("no lambda expression in filter")
        if isinstance(self.level, str) and self.level not in self.level_enum:
            raise ValueError(f"level string should be one of {self.level_enum}")

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
        self.validate()

    def validate(self):
        super().validate()
        if self.syscall == None:
            raise ValueError("need to specify syscall parameter")
        if not isinstance(self.syscall, str) or self.syscall not in Syscall.get_all():
            raise ValueError("invalid syscall parameter")

    def eval_detail(self, metadata, syscall, args, ret):
        detail_def = self.detail
        detail = None
        if detail_def:
            if isinstance(detail_def, str):
                detail_fmt = detail_def
                detail = detail_fmt.format(syscall=syscall, metadata=metadata, args=args, ret=ret)
            elif isinstance(detail_def, dict):
                detail_lambda = detail_def.get('lambda')
                if detail_lambda:
                    detail_func = lambda syscall,metadata,args,ret:eval(detail_lambda)
                    detail = detail_func(syscall, metadata, args, ret)
        if detail == None:
            default_lambda = "' '.join([ f'{key}={val}' for key,val in args.items()]) + (f' ret={ret}' if ret != None else '') "
            detail_func =  lambda syscall,metadata,args,ret:eval(default_lambda)
            detail = detail_func(syscall, metadata, args, ret)
        return detail

    def eval_level(self, metadata, syscall, args, ret):
        level_def = self.level
        level = None
        if level_def:
            if isinstance(level_def, str):
                level = level_def
            elif isinstance(level_def, dict):
                level_lambda = level_def.get('lambda')
                if level_lambda:
                    level_check = lambda syscall,metadata,args,ret: eval(level_lambda)
                    level = level_check(syscall, metadata, args, ret)
        if level == None:
            level = 'INFO'
        return level

    def eval_filter(self, metadata, syscall, args, ret):
        filter_def = self.filter
        if filter_def != None:
            if isinstance(filter_def, bool):
                return filter_def
            elif isinstance(filter_def, dict):
                filter_lambda = filter_def.get('lambda')
                if filter_lambda:
                    filter_check = lambda syscall,metadata,args,ret: eval(filter_lambda)
                    return filter_check(syscall, metadata, args, ret)
        return True

    def eval_processors(self, metadata, syscall, args, ret):
        if self.processors == None:
            return
        for p in self.processors:
            if hasattr(p, "syscall"):
                p.syscall(metadata, syscall, args, ret)

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
        self.validate()

    def validate(self):
        super().validate()
        if self.event == None:
            raise ValueError("need to specify event parameter")
        if not isinstance(self.event, str) or self.event not in Event.get_all():
            raise ValueError("invalid event parameter")

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

    def eval_filter(self, metadata, name, args):
        filter_def = self.filter
        if filter_def != None:
            if isinstance(filter_def, bool):
                return filter_def
            elif isinstance(filter_def, dict):
                filter_lambda = filter_def.get('lambda')
                if filter_lambda:
                    filter_check = lambda name,metadata,args: eval(filter_lambda)
                    return filter_check(name, metadata, args)
        return True

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
        self.validate()

    def validate(self):
        super().validate()
        if self.elf == None or self.function == None:
            raise ValueError(f"uprobe need to specify elf/function parameters")
        if not os.path.exists(self.elf):
            raise ValueError(f"{self.elf} does not exist")
        if self.sym and not os.path.exists(self.sym):
            raise ValueError(f"{self.sym} does not exist")
        if self.sym:
            dwarf = Dwarf(self.sym)
        else:
            dwarf = Dwarf(self.elf)
        function_instance = dwarf.resolve_function(self.function)
        if function_instance == None or len(function_instance) == 0:
            raise ValueError(f"unable to resolve address of function {self.function}")

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
            default_lambda = "uprobe_format(function, args, ret, metadata)"
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

    def eval_filter(self, metadata, function, args, ret):
        filter_def = self.filter
        if filter_def != None:
            if isinstance(filter_def, bool):
                return filter_def
            elif isinstance(filter_def, dict):
                filter_lambda = filter_def.get('lambda')
                if filter_lambda:
                    filter_check = lambda function,metadata,args,ret: eval(filter_lambda)
                    return filter_check(function, metadata, args, ret)
        return True

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
            except TypeError as e:
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

