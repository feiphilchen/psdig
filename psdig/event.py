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

class Event(object):
    def __init__(self, tracepoint):
        self.set_logger()
        self.callback = {}
        self.callback_arg = {}
        self.tracepoint = tracepoint
        self.boot_ts = float("%.6f" % (time.time() - time.monotonic()))

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    @classmethod
    def get_all(cls):
        search = os.path.join(TRACEFS, '**/format')
        format_files = glob.glob(search, recursive=True)
        events = []
        for fl in format_files:
            dirname = os.path.dirname(fl)
            event = dirname.replace(TRACEFS, '')
            if event.startswith('/'):
                event = event[1:]
            events.append(event)
        return sorted(events)

    def add(self, event_name, callback, arg):
        self.tracepoint.add_event_watch(event_name, self.event_handler)
        self.callback[event_name] = callback
        self.callback_arg[event_name] = arg

    def kernel_ns_to_timestamp(self, ktime_ns):
        elapsed =  float("%.6f" % (ktime_ns/1000000000))
        return self.boot_ts + elapsed

    def event_handler(self, event):
        event_name = event['event']
        remove_args = ["common_type", "common_flags", "common_preempt_count", "common_pid", "__syscall_nr"]
        cb = self.callback.get(event_name)
        ctx = self.callback_arg.get(event_name)
        if not cb:
            return
        cpuid = event['cpuid']
        metadata = {}
        metadata['cpuid'] = cpuid
        metadata['pid'] = event['pid']
        metadata['uid'] = event['uid']
        metadata['comm'] = event["comm"]
        ktime_ns = event['ktime_ns']
        metadata['timestamp'] = self.kernel_ns_to_timestamp(ktime_ns)
        if event:
            for arg in remove_args:
                if arg in event['parameters']:
                    del event['parameters'][arg]
            cb(event_name, metadata, event['parameters'], ctx)

