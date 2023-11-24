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
from .dwarf import Dwarf
from .conf import LOGGER_NAME

class Uprobe(object):
    def __init__(self, pid_filter=[], uid_filter=[], symbols={}, ignore_self=True):
        self.set_logger()
        self.probes = []
        self.proc = None
        self.pid_filter = pid_filter
        self.uid_filter = uid_filter
        self.pid = os.getpid()
        self.event_bucket = {}
        self.event_mutex = threading.Lock()
        self.loading = 0
        self.loaded = 0
        self.probe_handlers = {}
        self.symbols = symbols
        self.ignore_self = ignore_self
        self.pid = os.getpid()
        self.callout_thread_running = False
        self.callout_thread = None
        self.collect_thread_running = False
        self.collect_thread = None
        self.boot_ts = float("%.6f" % (time.time() - time.monotonic()))

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def kernel_ns_to_timestamp(self, ktime_ns):
        elapsed =  float("%.6f" % (ktime_ns/1000000000))
        return self.boot_ts + elapsed

    def probe_id(self, elf_path, function, enter):
        if enter:
            probe_str = f"{elf_path}:{function}:enter"
        else:
            probe_str = f"{elf_path}:{function}:ret"
        id_str = hashlib.md5(probe_str.encode('utf-8')).hexdigest()[0:8]
        return int(id_str, 16)

    def add(self, elf_path, function, callback, enter=True, arg=None, sym=None):
        elf_path = os.path.abspath(elf_path)
        probe_id = self.probe_id(elf_path, function, enter)
        if enter:
            name = "uprobe"
        else:
            name = "uretprobe"
        if sym:
            self.symbols[elf_path] = sym
        handler = name,function,callback,arg
        if probe_id in self.probe_handlers and self.probe_handlers[probe_id] != None:
            self.probe_handlers[probe_id].append(handler)
        else:
            self.probe_handlers[probe_id] = [handler]
        for p in self.probes:
            if p['function'] == function and p['elf'] == elf_path:
                if enter:
                    p['enter_id'] = probe_id
                else:
                    p['ret_id'] = probe_id
                return
        if enter:
            probe = {"function": function, "elf": elf_path, "enter_id": probe_id}
        else:
            probe = {"function": function, "elf": elf_path, "ret_id": probe_id}
        self.probes.append(probe)

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

    def get_arg_read_insts(self, args):
        insts = []
        for arg in args:
            decl = []
            name = arg['name']
            size = arg['type'][0]['size']
            if self.arg_is_str(arg['type']):
                inst = f'read_str(t, {name}, "{name}")'
            elif self.arg_is_ptr(arg['type']) or self.arg_is_class(arg['type']):
                inst = f'read_ptr(t, &{name}, "{name}")'
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
        elif self.arg_is_unsigned(type_list):
            inst = f'read_uint(t, &{name}, {size}, "{name}")'
        else:
            inst = f'read_int(t, &{name}, {size}, "{name}")'
        insts.append(inst)
        return insts

    def build_bpf_c(self, probe):
        elf_path = probe['elf']
        func_name = probe['function']
        enter_id = probe.get('enter_id')
        ret_id = probe.get('ret_id')
        if self.symbols and elf_path in self.symbols:
            sym = self.symbols[elf_path]
        else:
            sym = elf_path
        dwarf = Dwarf(sym)
        functions = dwarf.resolve_function(func_name)
        result = []
        for func in functions:
            bpf_c_file,addr = self.__build_bpf_c(func, enter_id, ret_id)
            result.append((bpf_c_file,addr))
        return result

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
        content = '#include "trace_uprobe.bpf.c"\n'
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
        return bpf_c_file,func_addr

    def build_bpf_o(self, probe):
        elf = probe['elf']
        result = self.build_bpf_c(probe)
        for bpf_c,offset in result:
            bname = os.path.basename(bpf_c)
            bpf_o = os.path.join(self.obj_dir, f"{bname}.o")
            cmd = f"clang -I/usr/local/share/psdig/usr/include -O2 -D__TARGET_ARCH_x86 -target bpf -c {bpf_c} -o {bpf_o}"
            subprocess.run(cmd, shell=True)
            self.uprobe_bpf_o.append(f"{bpf_o},{offset},{elf}")

    def copy_from_pkg(self, src, dst):
        data = pkgutil.get_data(__package__, src)
        with open(dst, 'wb') as fd:
            fd.write(data)

    def build_uprobe_objs(self):
        dst_file = os.path.join(self.obj_dir, 'trace_uprobe.bpf.c')
        self.copy_from_pkg('trace_uprobe/trace_uprobe.bpf.c', dst_file)
        dst_file = os.path.join(self.obj_dir, 'uprobe.h')
        self.copy_from_pkg('trace_uprobe/uprobe.h', dst_file)
        dst_file = os.path.join(self.obj_dir, 'trace_uprobe.c')
        self.copy_from_pkg('trace_uprobe/trace_uprobe.c', dst_file)
        self.uprobe_bpf_o = []
        for probe in self.probes:
            self.logger.info('building uprobe %s:%s' % (probe['elf'], probe['function']))
            self.build_bpf_o(probe)
            self.loaded += 1
        cmd = f"gcc {self.trace_uprobe_c} -g -I/usr/local/share/psdig/usr/include -L/usr/local/share/psdig/usr/lib64/ -l:libbpf.a -ljson-c -lelf -lz -lpthread -o {self.trace_uprobe_elf}"
        #os.popen(cmd)
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

    def call_probe_handlers(self, event_obj):
        uprobe_id = event_obj['id']
        if uprobe_id in self.probe_handlers:
            metadata,args = self.parse_uprobe_trace(event_obj)
            for handler in self.probe_handlers[uprobe_id]:
                name,func,callback,ctx = handler
                ret = None
                if name == 'uretprobe':
                    ret = args.get('ret')
                    args = None
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
            self.logger.error('error building uprobe objects')
            self.logger.error(traceback.format_exc())
        if compile_only:
            return
        time.sleep(1)
        if len(self.probes) == 0:
            self.logger.info('no uprobes')
            return
        self.logger.info('starting uprobe ...')
        self.logger.info('running now')
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

