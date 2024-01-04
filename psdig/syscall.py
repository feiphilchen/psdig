# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com
import os
import sys
import re
import click
import logging
import time
import glob
from tabulate import tabulate
from .tracepoint import TracePoint
from .conf import LOGGER_NAME,TRACEFS
from .schema import EventSchema

class Syscall(object):
    syscall_not_return = ["sys_exit", "sys_exit_group", "sys_execve"]
    syscall_void_return = ["sys_exit", "sys_exit_group"]
    remove_args = ["common_type", "common_flags", "common_preempt_count", "common_pid", "__syscall_nr"]
    def __init__(self, tracepoint):
        self.set_logger()
        self.syscall_hash = {}
        self.callback = {}
        self.callback_arg = {}
        self.tracepoint = tracepoint
        self.boot_ts = float("%.6f" % (time.time() - time.monotonic()))

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    @classmethod
    def get_all(cls, patterns=None):
        path = os.path.join(TRACEFS, "syscalls/sys_enter*")
        syscalls = []
        for syscall_enter in glob.glob(path):
            event_name = os.path.basename(syscall_enter)
            hit = re.match('sys_enter_(.*)$', event_name)
            syscall = "sys_%s" % hit.group(1)
            if patterns != None:
                for pattern in patterns:
                    hit = re.match(pattern, syscall)
                    if hit:
                        syscalls.append(syscall)
            else:
                syscalls.append(syscall)
        syscalls = list(set(syscalls))
        return sorted(syscalls)

    @classmethod
    def table_print(cls, filters=None):
        path = os.path.join(TRACEFS, "syscalls/sys_enter*")
        syscalls = []
        for syscall_enter in glob.glob(path):
            event_name = os.path.basename(syscall_enter)
            hit = re.match('sys_enter_(.*)$', event_name)
            syscalls.append(hit.group(1))
        syscalls = sorted(syscalls)
        schema = EventSchema()
        table = [['SYSCALL', 'ARGUMENTS', 'RETURN']]
        for syscall in syscalls:
            full_name = f'sys_{syscall}'
            if filters != None:
                matched = False
                for f in filters:
                    hit = re.search(f, full_name)
                    if hit:
                       matched = True
                       break
                if not matched:
                    continue
            arg_fields = schema.parse_event_format(f'syscalls/sys_enter_{syscall}')
            ret_fields = schema.parse_event_format(f'syscalls/sys_exit_{syscall}')
            arg_field_str = cls.field_str(arg_fields)
            if full_name not in cls.syscall_void_return:
                ret_field_str = cls.field_str(ret_fields)
            else:
                ret_field_str = ""
            row = full_name,arg_field_str,ret_field_str
            table.append(row)
        print(tabulate(table, tablefmt='grid', headers="firstrow"))

    @classmethod
    def field_str(cls, fields):
        elems = []
        for field in fields:
            if field['name'] in cls.remove_args:
                continue
            elems.append("%s %s" % (field['type'], field['name']))
        return '\n'.join(elems)

    def add(self, syscall, callback, arg):
        short_name = syscall.replace("sys_", "")
        events = [f"syscalls/sys_enter_{short_name}"]
        if syscall not in self.syscall_not_return:
            events.append(f"syscalls/sys_exit_{short_name}")
        self.tracepoint.add_syscall_watch(short_name, events, self.syscall_done)
        self.callback[syscall] = callback
        self.callback_arg[syscall] = arg

    def kernel_ns_to_timestamp(self, ktime_ns):
        elapsed =  float("%.6f" % (ktime_ns/1000000000))
        return self.boot_ts + elapsed

    def syscall_done(self, event):
        event_name = event['event']
        hit = re.match('syscalls/sys_enter_(.*)$', event_name)
        if not hit:
            return
        syscall = "sys_%s" % hit.group(1)
        cb = self.callback.get(syscall)
        ctx = self.callback_arg.get(syscall)
        if not cb:
            return
        cpuid = event['cpuid']
        if 'ret' in event['parameters']:
            ret = event['parameters'].get('ret')
            del event['parameters']['ret']
        else:
            ret = None
        syscall_nr = event['parameters']['__syscall_nr']
        ktime_ns = event['ktime_ns']
        timestamp = self.kernel_ns_to_timestamp(ktime_ns)
        metadata = {}
        metadata['syscall_nr'] = syscall_nr
        metadata['cpuid'] = cpuid
        metadata['timestamp'] = timestamp
        metadata['latency'] = event['duration']
        metadata['pid'] = event['pid']
        metadata['uid'] = event['uid']
        metadata['comm'] = event["comm"]
        if 'ustack' in event:
            metadata['ustack'] = event["ustack"]
        for arg in self.remove_args:
            if arg in event['parameters']:
                del event['parameters'][arg]
        cb(syscall, metadata, event['parameters'], ret, ctx)

