#!/usr/bin/python3
# vim: set filetype=python
import os
import sys
import re
import click
import logging
import time
import glob
from .tracepoint import TracePoint
from .conf import LOGGER_NAME,TRACEFS

class Syscall(object):
    syscall_not_return = ["sys_exit", "sys_exit_group"]
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
    def get_all(cls):
        path = os.path.join(TRACEFS, "syscalls/sys_enter*")
        syscalls = []
        for syscall_enter in glob.glob(path):
            event_name = os.path.basename(syscall_enter)
            hit = re.match('sys_enter_(.*)$', event_name)
            syscall = "sys_%s" % hit.group(1)
            syscalls.append(syscall)
        return sorted(syscalls)

    def add(self, syscall, callback, arg):
        short_name = syscall.replace("sys_", "")
        enter_event = f"syscalls/sys_enter_{short_name}"
        self.tracepoint.add_event_watch(enter_event, self.syscall_enter)
        if syscall not in self.syscall_not_return:
            exit_event = f"syscalls/sys_exit_{short_name}"
            self.tracepoint.add_event_watch(exit_event, self.syscall_exit)
        self.callback[syscall] = callback
        self.callback_arg[syscall] = arg

    def kernel_ns_to_timestamp(self, ktime_ns):
        elapsed =  float("%.6f" % (ktime_ns/1000000000))
        return self.boot_ts + elapsed

    def syscall_enter(self, event):
        event_name = event['event']
        cpuid = event['cpuid']
        syscall_nr = event['parameters']['__syscall_nr']
        hit = re.match('syscalls/sys_enter_(.*)$', event_name)
        if not hit:
            return
        syscall = "sys_%s" % hit.group(1)
        if syscall not in self.syscall_not_return:
            if cpuid not in self.syscall_hash:
                self.syscall_hash[cpuid] = {}
            if syscall_nr not in self.syscall_hash[cpuid]:
                self.syscall_hash[cpuid][syscall_nr] = []
            self.syscall_hash[cpuid][syscall_nr].append(event)
        else:
            cb = self.callback.get(syscall)
            ctx = self.callback_arg.get(syscall)
            if not cb:
                return
            cpuid = event['cpuid']
            ktime_ns = event['ktime_ns']
            timestamp = self.kernel_ns_to_timestamp(ktime_ns)
            metadata = {}
            metadata['syscall_nr'] = syscall_nr
            metadata['cpuid'] = cpuid
            metadata['timestamp'] = timestamp
            metadata['pid'] = event['pid']
            metadata['uid'] = event['uid']
            metadata['comm'] = event["comm"]
            for arg in self.remove_args:
                if arg in event['parameters']:
                    del event['parameters'][arg]
            cb(syscall, metadata, event['parameters'], None, ctx)

    def syscall_exit(self, event):
        event_name = event['event']
        hit = re.match('syscalls/sys_exit_(.*)$', event_name)
        if not hit:
            return
        syscall = "sys_%s" % hit.group(1)
        cb = self.callback.get(syscall)
        ctx = self.callback_arg.get(syscall)
        if not cb:
            return
        cpuid = event['cpuid']
        syscall_nr = event['parameters']['__syscall_nr']
        ret = event['parameters']['ret']
        ktime_ns = event['ktime_ns']
        timestamp = self.kernel_ns_to_timestamp(ktime_ns)
        if cpuid in self.syscall_hash and syscall_nr in self.syscall_hash[cpuid]:
            try:
                event = self.syscall_hash[cpuid][syscall_nr].pop(0)
            except:
                return
            metadata = {}
            metadata['syscall_nr'] = syscall_nr
            metadata['cpuid'] = cpuid
            metadata['timestamp'] = timestamp
            metadata['latency'] = ktime_ns - event['ktime_ns']
            metadata['pid'] = event['pid']
            metadata['uid'] = event['uid']
            metadata['comm'] = event["comm"]
            if event:
                for arg in self.remove_args:
                    if arg in event['parameters']:
                        del event['parameters'][arg]
                cb(syscall, metadata, event['parameters'], ret, ctx)

