#!/usr/bin/python3
# vim: set filetype=python
import os
import sys
import re
import click
import logging
from .tracepoint import TracePoint
from .conf import LOGGER_NAME

class Syscall(object):
    def __init__(self, tracepoint):
        self.set_logger()
        self.syscall_hash = {}
        self.callback = {}
        self.callback_arg = {}
        self.tracepoint = tracepoint

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def add(self, syscall, callback, arg):
        enter_event = f"syscalls/sys_enter_{syscall}"
        exit_event = f"syscalls/sys_exit_{syscall}"
        self.tracepoint.add_event_watch(enter_event, self.syscall_enter)
        self.tracepoint.add_event_watch(exit_event, self.syscall_exit)
        self.callback[syscall] = callback
        self.callback_arg[syscall] = arg

    def syscall_enter(self, event):
        cpuid = event['cpuid']
        syscall_nr = event['parameters']['__syscall_nr']
        if cpuid not in self.syscall_hash:
            self.syscall_hash[cpuid] = {}
        if syscall_nr not in self.syscall_hash[cpuid]:
            self.syscall_hash[cpuid][syscall_nr] = []
        self.syscall_hash[cpuid][syscall_nr].append(event)

    def syscall_exit(self, event):
        event_name = event['event']
        remove_args = ["common_type", "common_flags", "common_preempt_count", "common_pid", "__syscall_nr"]
        hit = re.match('syscalls/sys_exit_(.*)$', event_name)
        if not hit:
            return
        syscall = hit.group(1)
        cb = self.callback.get(syscall)
        ctx = self.callback_arg.get(syscall)
        if not cb:
            return
        cpuid = event['cpuid']
        syscall_nr = event['parameters']['__syscall_nr']
        ret = event['parameters']['ret']
        ktime_ns = event['ktime_ns']
        if cpuid in self.syscall_hash and syscall_nr in self.syscall_hash[cpuid]:
            try:
                event = self.syscall_hash[cpuid][syscall_nr].pop(0)
            except:
                return
            metadata = {}
            metadata['syscall_nr'] = syscall_nr
            metadata['cpuid'] = cpuid
            metadata['latency'] = ktime_ns - event['ktime_ns']
            #if  ktime_ns - event['ktime_ns'] < 0:
            #    self.logger.error(f"error latentcy: {ktime_ns} {event['ktime_ns']}")
            #    self.logger.error(str(event))
            metadata['pid'] = event['pid']
            metadata['uid'] = event['uid']
            metadata['comm'] = event["comm"]
            if event:
                for arg in remove_args:
                    if arg in event['parameters']:
                        del event['parameters'][arg]
                cb(syscall, metadata, event['parameters'], ret, ctx)

