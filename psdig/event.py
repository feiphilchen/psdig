#!/usr/bin/python3
# vim: set filetype=python
import os
import sys
import re
import click
import logging
from .tracepoint import TracePoint
from .conf import LOGGER_NAME

class Event(object):
    def __init__(self, tracepoint):
        self.set_logger()
        self.callback = {}
        self.callback_arg = {}
        self.tracepoint = tracepoint

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def add(self, event_name, callback, arg):
        self.tracepoint.add_event_watch(event_name, self.event_handler)
        self.callback[event_name] = callback
        self.callback_arg[event_name] = arg

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
        if event:
            for arg in remove_args:
                if arg in event['parameters']:
                    del event['parameters'][arg]
            cb(event_name, metadata, event['parameters'], ctx)

