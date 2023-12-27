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

class Event(object):
    remove_args = ["common_type", "common_flags", "common_preempt_count", "common_pid", "__syscall_nr"]
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
    def get_all(cls, patterns=None):
        search = os.path.join(TRACEFS, '**/format')
        format_files = glob.glob(search, recursive=True)
        events = []
        for fl in format_files:
            dirname = os.path.dirname(fl)
            event = dirname.replace(TRACEFS, '')
            if event.startswith('/'):
                event = event[1:]
            if patterns != None:
                for pattern in patterns:
                    hit = re.match(pattern, event)
                    if hit:
                        events.append(event)
            else:
                events.append(event)
        events = list(set(events))
        return sorted(events)

    @classmethod
    def table_print(cls, filters=None):
        events = cls.get_all()
        schema = EventSchema()
        table = [['EVENT', 'ARGUMENTS']]
        for event in events:
            if filters != None:
                matched = False
                for f in filters:
                    hit = re.search(f, event)
                    if hit:
                       matched = True
                       break
                if not matched:
                    continue
            arg_fields = schema.parse_event_format(event)
            arg_field_str = cls.field_str(arg_fields)
            row = event,arg_field_str
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

    def add(self, event_name, callback, arg):
        self.tracepoint.add_event_watch(event_name, self.event_handler)
        self.callback[event_name] = callback
        self.callback_arg[event_name] = arg

    def kernel_ns_to_timestamp(self, ktime_ns):
        elapsed =  float("%.6f" % (ktime_ns/1000000000))
        return self.boot_ts + elapsed

    def event_handler(self, event):
        event_name = event['event']
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
            for arg in self.remove_args:
                if arg in event['parameters']:
                    del event['parameters'][arg]
            cb(event_name, metadata, event['parameters'], ctx)

