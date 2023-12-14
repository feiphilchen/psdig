# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com
import logging
import traceback
from .database import TraceDB
from .conf import LOGGER_NAME

class TraceBuffer(object):
    def __init__(self, file_path=None):
        self.trace_db = TraceDB(file_path)
        self.rb = []
        self.rb_limit = 4096
        self.rb_start = 0
        self.wb = []
        self.wb_limit = 4096
        self.wb_start = self.trace_db.count()
        self.set_logger()

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def read_buffer_reload(self, pos):
        offset = pos & (self.rb_limit - 1)
        rb_start = pos - offset
        traces = self.trace_db.read(rb_start, self.rb_limit)
        if len(traces) > 0:
            self.rb = traces
            self.rb_start = rb_start

    def read(self, pos):
        wb_len = len(self.wb)
        if pos >= self.wb_start and pos < self.wb_start + wb_len:
            offset = pos - self.wb_start
            return self.wb[offset]
        rb_len = len(self.rb)
        if pos < self.rb_start or pos >= self.rb_start + rb_len:
            self.read_buffer_reload(pos)
        rb_len = len(self.rb)
        if pos >= self.rb_start and pos < self.rb_start + rb_len:
            offset = pos - self.rb_start
            return self.rb[offset]
        return None

    def write_buffer_flush(self):
        self.trace_db.write(self.wb)
        self.wb_start = self.trace_db.count()
        self.wb = []

    def append(self, trace):
        self.wb.append(trace)
        if len(self.wb) >= self.wb_limit:
            self.write_buffer_flush()

    def length(self):
        return len(self.wb) + self.wb_start

    def set(self, traces):
        self.trace_db.clear()
        self.wb = traces
        self.write_buffer_flush()
        self.rb = []
        self.rb_start = 0

    def filter(self, filter_text):
        self.write_buffer_flush()
        return self.trace_db.filter(filter_text)

    def close(self):
        self.write_buffer_flush()

    def __del__(self):
        pass

