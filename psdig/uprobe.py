# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com

import os
import sys
import re
import json
import logging
import traceback
import pkgutil
import threading
import hashlib
import time
import subprocess
import platform
from .dwarf import Dwarf
from .data_type import *
from .backtrace import Backtrace
from .conf import LOGGER_NAME,DEFAULT_CLANG

class Uprobe(object):
    type_mapping = {
       "ptr": Pointer,
       "bytes": Bytes,
       "sockaddr":SockAddr
    }
    def __init__(self, pid_filter=[], 
                       uid_filter=[], 
                       comm_filter=[],
                       symbols={}, 
                       ignore_self=True,
                       ustack=False,
                       kstack=False):
        self.set_logger()
        self.probe_index = {}
        self.functions = {}
        self.proc = None
        self.pid_filter = pid_filter
        self.uid_filter = uid_filter
        self.comm_filter = comm_filter
        self.kstack = kstack
        self.ustack = ustack
        self.pid = os.getpid()
        self.event_bucket = {}
        self.event_mutex = threading.Lock()
        self.loading = 0
        self.loaded = 0
        self.probe_handlers = {}
        self.bind_queue = {}
        self.symbols = symbols
        self.ignore_self = ignore_self
        self.pid = os.getpid()
        self.callout_thread_running = False
        self.callout_thread = None
        self.collect_thread_running = False
        self.collect_thread = None
        self.boot_ts = float("%.6f" % (time.time() - time.monotonic()))
        self.backtrace = Backtrace()
        self.set_clang()
        self.set_arch()

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def set_arch(self):
        machine = platform.machine()
        if machine == 'aarch64' or machine == 'arm64':
            self.arch = 'arm64'
        elif machine == 'ppc64' or machine == 'ppc':
            self.arch = 'powerpc'
        elif machine == 'mips':
            self.arch = 'mips'
        elif machine == 'sparc64':
            self.arch = 'sparc'
        else:
            self.arch = 'x86'

    def set_clang(self):
        for clang in DEFAULT_CLANG:
            if os.path.exists(clang):
                self.clang = clang
                return
        self.clang = 'clang'

    def kernel_ns_to_timestamp(self, ktime_ns):
        elapsed =  float("%.6f" % (ktime_ns/1000000000))
        return self.boot_ts + elapsed

    def probe_id(self, elf_path, function, addr, enter):
        if enter:
            probe_str = f"{elf_path}:{function}:{addr}:enter"
        else:
            probe_str = f"{elf_path}:{function}:{addr}:ret"
        id_str = hashlib.md5(probe_str.encode('utf-8')).hexdigest()[0:8]
        return int(id_str, 16)

    def add(self, elf_path, function, callback, enter=True, arg=None, sym=None, bind=False):
        elf_path = os.path.abspath(elf_path)
        if sym:
            self.symbols[elf_path] = sym
        if enter:
            probe_type = "uprobe"
        else:
            probe_type = "uretprobe"
        probe_key = f"{function}:{elf_path}"
        new_probe = {"type":probe_type, "function": function, "elf": elf_path, "callbacks":[]}
        if elf_path not in self.probe_index:
            self.probe_index[elf_path] = {}
        if function not in self.probe_index[elf_path]:
            self.probe_index[elf_path][function] = {}
        if probe_type not in self.probe_index[elf_path][function]:
            self.probe_index[elf_path][function][probe_type] = new_probe
        cb = callback,arg,bind
        self.probe_index[elf_path][function][probe_type]['callbacks'].append(cb)

    def resolve_functions(self):
        for elf in self.probe_index:
            for function in self.probe_index[elf]:
                if self.symbols and elf in self.symbols:
                    sym = self.symbols[elf]
                else:
                    sym = elf
                self.dwarf = Dwarf(sym)
                instances = self.dwarf.resolve_function(function)
                if len(instances) == 0:
                    raise Exception(f"fail to resolve function {function} in {sym}")
                for instance in instances:
                    instance['elf'] = elf
                self.probe_index[elf][function]['instances'] = instances

    def _add_handler(self, probe_id, handler):
        if probe_id in self.probe_handlers and self.probe_handlers[probe_id] != None:
            self.probe_handlers[probe_id].append(handler)
        else:
            self.probe_handlers[probe_id] = [handler]

    def add_handler(self, probe_id, peer_id, probe, instance):
        elf = probe['elf']
        function_name = instance['function']
        addr = instance['addr']
        function = {"name":function_name,"elf":elf, "addr":addr}
        name = probe['type']
        for cb in probe['callbacks']:
            callback,arg,bind = cb
            handler = name,function,callback,arg,bind,peer_id
            self._add_handler(probe_id, handler)
        if elf not in self.functions:
            self.functions[elf] = {}
        self.functions[elf][addr] = instance

    def get_function_arg_type(self, elf, addr, name):
        function = self.functions.get(elf, {}).get(addr)
        if function == None:
            return None
        for arg in function['args']:
            if name == arg['name']:
                return arg['type']
        return None

    def get_function_return_type(self, elf, addr):
        function = self.functions.get(elf, {}).get(addr)
        if function == None:
            return None
        return function['ret']

    def init_obj_dir(self, obj_dir):
        self.obj_dir = obj_dir
        self.trace_uprobe_elf = os.path.join(self.obj_dir, "trace_uprobe")
        self.trace_uprobe_c = os.path.join(self.obj_dir, "trace_uprobe.c")
        if not os.path.exists(self.obj_dir):
            os.makedirs(self.obj_dir)

    def uint_args(self, size):
        size_mapping =  {
           1:"__u8",
           2:"__u16",
           4:"__u32",
           8:"__u64"
        }
        if size in size_mapping:
            return size_mapping[size]
        else:
            return None

    def get_enter_arg_decl(self, args):
        decls = ["uprobe_enter"]
        for arg in args:
            decl = []
            name = arg['name']
            base = False
            for t in arg['type']:
                if t['type'] == 'ptr':
                    decl.insert(0, '*')
                elif t['type'] == 'enum':
                    uint_type = self.uint_args(t['size'])
                    decl.insert(0, uint_type)
                    base = True
                elif t['type'] == 'base':
                    uint_type = self.uint_args(t['size'])
                    decl.insert(0, uint_type)
                    base = True
            if not base:
                if len(decl) > 0:
                    decl.insert(0, 'void')
                else:
                    decl = ["void", "*"]
            decl.append(name)
            decl_str = " ".join(decl)
            decls.append(decl_str)
        return ",".join(decls)
                    
    def get_return_arg_decl(self, return_type):
        decl = []
        base = False
        for t in return_type:
            if t['type'] == 'ptr':
                decl.insert(0, '*')
            elif t['type'] == 'enum':
                uint_type = self.uint_args(t['size'])
                decl.insert(0, uint_type)
                base = True
            elif t['type'] == 'base':
                uint_type = self.uint_args(t['size'])
                decl.insert(0, uint_type)
                base = True
        if not base and len(decl) > 0:
            decl.insert(0, 'void')
        if len(decl) > 0:
             decl.append('ret')
             decl_str = " ".join(decl)
             return f"uprobe_exit,{decl_str}"
        else:
             return "uprobe_exit"

    def function_arg_is_str(self, elf, addr, name):
        type_list= self.get_function_arg_type(elf, addr, name)
        if type_list == None:
            return False
        return self.arg_is_str(type_list)

    def arg_is_str(self, type_list):
        if len(type_list) != 2:
            return False
        if type_list[0]['type'] != 'ptr':
            return False
        if type_list[1]['type'] != 'base':
            return False
        base_types = type_list[1]['name'].split()
        if 'char' in base_types:
            return True
        else:
            return False

    def arg_is_ptr(self, type_list):
        if len(type_list) == 0:
            return False
        if type_list[0]['type'] != 'ptr':
            return False
        return True

    def arg_is_class(self, type_list):
        if len(type_list) == 0:
            return False
        if type_list[0]['type'] != 'class':
            return False
        return True

    def arg_is_struct(self, type_list):
        if len(type_list) == 0:
            return False
        if type_list[0]['type'] != 'struct':
            return False
        return True

    def arg_is_union(self, type_list):
        if len(type_list) == 0:
            return False
        if type_list[0]['type'] != 'union':
            return False
        return True

    def arg_is_unsigned(self, type_list):
        if len(type_list) == 0:
            return False
        if type_list[0]['type'] != 'base':
            return False
        base_types = type_list[0]['name'].split()
        if 'unsigned' in base_types:
            return True
        else:
            return False

    def arg_is_float(self, type_list):
        if len(type_list) == 0:
            return False
        if type_list[0]['type'] != 'base':
            return False
        base_types = type_list[0]['name'].split()
        if 'float' in base_types or 'double' in base_types:
            return True
        else:
            return False

    def get_arg_read_insts(self, args):
        insts = []
        for arg in args:
            decl = []
            name = arg['name']
            size = arg['type'][0]['size']
            if self.arg_is_str(arg['type']):
                inst = f'read_str(t, {name}, "{name}")'
            elif self.arg_is_ptr(arg['type']) or  \
                self.arg_is_class(arg['type']) or \
                self.arg_is_struct(arg['type']) or \
                self.arg_is_union(arg['type']) :
                inst = f'read_ptr(t, &{name}, "{name}")'
            elif self.arg_is_float(arg['type']):
                inst = f'read_float(t, &{name}, {size}, "{name}")'
            elif self.arg_is_unsigned(arg['type']):
                inst = f'read_uint(t, &{name}, {size}, "{name}")'
            else:
                inst = f'read_int(t, &{name}, {size}, "{name}")'
            insts.append(inst)
        return insts

    def get_ret_read_insts(self, type_list):
        insts = []
        if len(type_list) == 0:
            return insts
        name = 'ret'
        size = type_list[0]['size']
        if self.arg_is_str(type_list):
            inst = f'read_str(t, {name}, "{name}")'
        elif self.arg_is_ptr(type_list):
            inst = f'read_ptr(t, &{name}, "{name}")'
        elif self.arg_is_float(type_list):
            inst = f'read_float(t, &{name}, {size}, "{name}")'
        elif self.arg_is_unsigned(type_list):
            inst = f'read_uint(t, &{name}, {size}, "{name}")'
        else:
            inst = f'read_int(t, &{name}, {size}, "{name}")'
        insts.append(inst)
        return insts

    def build_bpf_c(self, instance, enter_id, ret_id):
        return self.__build_bpf_c(instance, enter_id, ret_id)

    def __build_bpf_c(self, function, enter_id, ret_id):
        if enter_id:
            uprobe_enter = True
        else:
            uprobe_enter = False
            enter_id = 0
        if ret_id:
            uprobe_ret = True
        else:
            uprobe_ret = False
            ret_id = 0
        func_name = function['function']
        enter_args = self.get_enter_arg_decl(function['args'])
        exit_arg = self.get_return_arg_decl(function['ret'])
        insts = self.get_arg_read_insts(function['args'])
        num_insts = len(insts)
        insts = [f"trace_add_obj(t, {num_insts})"] + insts
        inst_str = ";\n    ".join(insts)
        content = ""
        if self.ustack:
            content += "#define __PSDIG_USTACK__\n"
        if self.kstack:
            content += "#define __PSDIG_KSTACK__\n"
        content += '#include "trace_uprobe.bpf.c"\n'
        if uprobe_enter:
            uprobe_enter_str="""
SEC("uprobe/uprobe_enter")
int BPF_KPROBE(%s)
{
    uprobe_enter_start(%d);
    %s;
    uprobe_enter_finish();
    return 0;
}
""" % (enter_args, enter_id, inst_str)
            content += uprobe_enter_str
        insts = self.get_ret_read_insts(function['ret'])
        num_insts = len(insts)
        insts = [f"trace_add_obj(t, {num_insts})"] + insts
        inst_str = ";\n    ".join(insts)
        if uprobe_ret:
            uprobe_ret_str ="""
SEC("uretprobe/uprobed_exit")
int BPF_KRETPROBE(%s)
{
    uprobe_ret_start(%d);
    %s;
    uprobe_ret_finish();
    return 0;
}
""" % (exit_arg, ret_id, inst_str)
            content += uprobe_ret_str
        func_addr = function['addr']
        bpf_c_file = os.path.join(self.obj_dir, f"{func_name}_{func_addr}_{enter_id}_{ret_id}.bpf.c")
        with open(bpf_c_file, 'w') as fp:
            fp.write(content)
        return bpf_c_file

    def build_bpf_o(self, instance, uprobe_id, uretprobe_id):
        bpf_c = self.build_bpf_c(instance, uprobe_id, uretprobe_id)
        bname = os.path.basename(bpf_c)
        bpf_o = os.path.join(self.obj_dir, f"{bname}.o")
        cmd = f"{self.clang} -I/usr/local/share/psdig/usr/include -O2 -D__TARGET_ARCH_{self.arch} -target bpf -c {bpf_c} -o {bpf_o}"
        subprocess.run(cmd, shell=True)
        offset = instance['addr']
        elf = instance['elf']
        self.uprobe_bpf_o.append(f"{bpf_o},{offset},{elf}")
        return uprobe_id,uretprobe_id

    def copy_from_pkg(self, src, dst):
        data = pkgutil.get_data(__package__, src)
        with open(dst, 'wb') as fd:
            fd.write(data)

    def build_uprobe_objs(self):
        self.resolve_functions()
        dst_file = os.path.join(self.obj_dir, 'trace_uprobe.bpf.c')
        self.copy_from_pkg('trace_uprobe/trace_uprobe.bpf.c', dst_file)
        dst_file = os.path.join(self.obj_dir, 'uprobe.h')
        self.copy_from_pkg('trace_uprobe/uprobe.h', dst_file)
        dst_file = os.path.join(self.obj_dir, 'trace_uprobe.c')
        self.copy_from_pkg('trace_uprobe/trace_uprobe.c', dst_file)
        self.uprobe_bpf_o = []
        for elf in self.probe_index:
            for function in self.probe_index[elf]:
                self.logger.info(f'building uprobe {elf}:{function}')
                func_probe = self.probe_index[elf][function]
                for instance in self.probe_index[elf][function]['instances']:
                    uprobe_id = None
                    uretprobe_id = None
                    addr = instance['addr']
                    if 'uprobe' in func_probe:
                        uprobe_id = self.probe_id(elf, function, addr, True)
                        self.add_handler(uprobe_id, uretprobe_id, func_probe['uprobe'], instance)
                    if 'uretprobe' in func_probe:
                        uretprobe_id = self.probe_id(elf, function, addr, False)
                        self.add_handler(uretprobe_id, uprobe_id, func_probe['uretprobe'], instance)
                    self.build_bpf_o(instance, uprobe_id, uretprobe_id)
                self.loaded += 1
        cmd = f"gcc {self.trace_uprobe_c} -g -I/usr/local/share/psdig/usr/include -L/usr/local/share/psdig/usr/lib64/ -L/usr/local/share/psdig/usr/lib/ -l:libbpf.a -l:libjson-c.a -lelf -lz -lpthread -o {self.trace_uprobe_elf}"
        subprocess.run(cmd, shell=True)

    def parse_uprobe_trace(self, event_obj):
        metadata = event_obj.copy()
        ktime_ns = event_obj['ktime_ns']
        metadata['timestamp'] = self.kernel_ns_to_timestamp(ktime_ns)
        if 'parameters' in event_obj:
            args = event_obj['parameters']
            del metadata['parameters']
        else:
            args = {}
        return metadata,args

    def params_type_convert(self, event_obj):
        if 'schema' in event_obj:
            for arg in event_obj['schema']:
                arg_type = event_obj['schema'][arg]
                if arg_type in self.type_mapping:
                    cls = self.type_mapping[arg_type]
                    new_value = cls(event_obj['parameters'][arg])
                    event_obj['parameters'][arg] = new_value
        if 'ustack' in event_obj:
            event_obj['ustack'] = self.backtrace.resolve_ustack(event_obj['pid'], event_obj['ustack'])

    def bind_probe_push(self, uprobe_id, metadata, args):
        tid = metadata['tid']
        if uprobe_id not in self.bind_queue:
            self.bind_queue[uprobe_id] = {}
        if tid not in self.bind_queue[uprobe_id]:
            self.bind_queue[uprobe_id][tid] = []
        bind_probe = metadata,args
        self.bind_queue[uprobe_id][tid].append(bind_probe)

    def bind_probe_pop(self, uprobe_id, metadata):
        tid = metadata['tid']
        if uprobe_id not in self.bind_queue:
            return None,None
        if tid not in self.bind_queue[uprobe_id]:
            return None,None
        if len(self.bind_queue[uprobe_id][tid]) == 0:
            return None,None
        enter_metadata,args = self.bind_queue[uprobe_id][tid].pop(-1)
        if len(self.bind_queue[uprobe_id][tid]) == 0:
            del self.bind_queue[uprobe_id][tid]
        if len(self.bind_queue[uprobe_id]) == 0:
            del self.bind_queue[uprobe_id]
        metadata['latency'] = metadata['ktime_ns'] - enter_metadata['ktime_ns']
        return metadata,args

    def call_probe_handlers(self, event_obj):
        uprobe_id = event_obj['id']
        self.params_type_convert(event_obj)
        if uprobe_id in self.probe_handlers:
            metadata,args = self.parse_uprobe_trace(event_obj)
            for handler in self.probe_handlers[uprobe_id]:
                name,func,callback,ctx,bind,peer_id = handler
                if name == 'uretprobe':
                    metadata['enter'] = False
                    ret = args.get('ret')
                    args = None
                else:
                    metadata['enter'] = True
                    ret = None
                if bind:
                    if metadata['enter'] == True:
                        self.bind_probe_push(uprobe_id, metadata, args)
                        return
                    else:
                        metadata,args = self.bind_probe_pop(peer_id, metadata)
                if ctx == None:
                    callback(func, metadata, args, ret)
                else:
                    callback(func, metadata, args, ret, ctx)

    def events_callout(self, events):
        events.sort(key=lambda x: x['ktime_ns'], reverse=False)
        for event_obj in events:
            self.call_probe_handlers(event_obj)

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
        cmd = [self.trace_uprobe_elf]
        for obj in self.uprobe_bpf_o:
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
                self.event_obj_enqueue(event_obj)
                json_str = None
            else:
                json_str += line
        self.logger.info('trace_uprobe exiting')
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
            self.build_uprobe_objs()
        except:
            raise
        if compile_only:
            return
        time.sleep(1)
        if len(self.probe_index) == 0:
            self.logger.info('no uprobes')
            return
        self.logger.info('starting uprobe ...')
        self.logger.info('uprobe running now')
        self.start_callout_thread()
        if not async_collect:
            self.collect()
        else:
            self.start_collect_thread()

    def stop(self):
        self.logger.info('uprobe is being stopped ...')
        self.collect_thread_running = False
        self.callout_thread_running = False
        if self.proc != None:
            self.proc.terminate()

