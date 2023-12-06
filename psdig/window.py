import os
import sys
import time
import curses
import logging
import re
import traceback
from datetime import datetime
from curses import wrapper
from curses.textpad import Textbox,rectangle
import threading
from tabulate import tabulate
from .trace_buffer import TraceBuffer
from .conf import LOGGER_NAME

class CurseWin(object):
    def __init__(self, stdscr, width, height, x = 0, y = 0, title=None, text_mode=False):
        self.stdscr = stdscr
        self.width = width
        self.height = height
        self.x = x
        self.y = y
        self.textbox = None
        self.textinput = ""
        if text_mode:
            self.new_text_window()
        else:
            self.new_plain_window()
        self.title = title
        self.focused = False
        self.border_color_unfocus = curses.color_pair(2)
        self.border_color_focus = curses.color_pair(3)
        self.border_color = self.border_color_unfocus

    def new_plain_window(self):
        self.win = curses.newwin(self.height, self.width, self.y, self.x)

    def new_text_window(self):
        self.win = curses.newwin(self.height - 2, self.width - 2, self.y + 1, self.x + 1)
        self.textbox = Textbox(self.win, insert_mode=True)

    def curse_handle(self):
        return self.win

    def is_focused(self):
        return self.focused

    def is_text_mode(self):
        return self.textbox != None

    def edit(self):
        if self.textbox:
            self.textinput = self.textbox.edit()
            self.textinput = self.textinput.strip()
            return self.textinput
        else:
            return None

    def unfocus(self):
        self.focused = False
        self.border_color = self.border_color_unfocus

    def focus(self):
        self.focused = True
        self.border_color = self.border_color_focus

    def clear(self):
        self.win.erase()

    def display_plain_window(self):
        self.win.attron(self.border_color)
        self.win.border()
        self.win.attroff(self.border_color)
        if self.title != None:
            self.win.addstr(0, 2, self.title)
        self.win.refresh()

    def display_text_window(self):
        self.stdscr.attron(self.border_color)
        rectangle(self.stdscr, self.y, self.x, self.y + self.height - 1, self.x + self.width - 1)
        self.stdscr.attroff(self.border_color)
        if self.title != None:
            self.stdscr.addstr(self.y, self.x + 2, self.title)
        self.stdscr.refresh()
        self.win.erase()
        self.win.addstr(0, 0, self.textinput)
        self.win.refresh()

    def display(self):
        if self.textbox:
            self.display_text_window()
        else:
            self.display_plain_window()

class TagWin(CurseWin):
    def __init__(self, stdscr, width, height, x = 0, y = 0, title=None):
        super().__init__(stdscr, width, height, x, y, title)
        self.stats = None

    def stats_update(self, stats):
        self.stats = stats
        super().clear()
        if self.stats == None:
            return
        curse_win = super().curse_handle()
        row = 1
        for name in self.stats:
            count = self.stats[name]
            stat_str = "{:20s} {:6d}".format(name, count)
            curse_win.addstr(row, 1, stat_str)
            row +=1
        #curse_win.refresh()
        super().display()

    def display(self):
        super().clear()
        super().display()

class FilterWin(CurseWin):
    def __init__(self, stdscr, width, height, x = 0, y = 0, title=None):
        super().__init__(stdscr, width, height, x, y, title, text_mode=True)

class StatusWin(CurseWin):
    def __init__(self, stdscr, width, height, x = 0, y = 0, title=None):
        super().__init__(stdscr, width, height, x, y, title, text_mode=False)
        self.stats = None

    def update_stats(self, stats):
        self.stats = stats
        self.display()

    def display(self):
        super().clear()
        super().display()
        if self.stats == None:
            return
        curse_win = super().curse_handle()
        total = self.stats['total']
        display_start = self.stats['display_start']
        display_end = self.stats['display_end']
        reloaded = self.stats['reloaded']
        message = self.stats.get('message')
        filtered = self.stats.get('filtered')
        if filtered:
            filtered_text = f", filtered {filtered}"
        else:
            filtered_text = ""
        display_end = display_end - 1 if display_end > 0 else 0
        displaying = f", displaying from {display_start} to {display_end}"
        stat_str = f"Total traces:{total}{filtered_text}{displaying}. "
        curse_win.addstr(1, 1, stat_str, curses.A_BOLD)
        if message != None:
            curse_win.addstr(message, curses.A_REVERSE)

        curse_win.refresh()

class MainWin(CurseWin):
    def __init__(self, stdscr, width, height, x = 0, y = 0, title=None, event_file=None, tmp_dir="/var/tmp"):
        super().__init__(stdscr, width, height, x, y, title, text_mode=True)
        self.set_logger()
        self.tmp_dir = tmp_dir
        self.trace_buffer = TraceBuffer(self.filtered_trace_buffer())
        if event_file:
            self.all_traces = TraceBuffer(event_file)
        else:
            self.all_traces = TraceBuffer(self.all_trace_buffer())
        self.width = width
        self.height = height
        self.x = x
        self.y = y
        self.pad_width = width - 2
        self.pad_height = 4096
        self.pad_display_height = self.height - 3
        self.pad_count = 0
        self.pad_start = 0
        self.pad_end = 0
        self.display_start = 0
        self.display_end = 0
        self.reloaded = 0
        self.filter_text = None
        self.format_str = '{:8s} {:16s} {:16s} {:8s} {:8s} {:16s} {:8s} {:32s}'
        self.pad = curses.newpad(self.pad_height, self.pad_width)
        self.error_color = curses.color_pair(4)
        self.warn_color = curses.color_pair(4)
        self.hl_color = curses.color_pair(5)
        self.hdr_color = curses.color_pair(7)
        self.select_index = None
        self.first_ts = None
        self.pad_displaying = False

    def filtered_trace_buffer(self):
        return os.path.join(self.tmp_dir, "filtered_trace.db")

    def all_trace_buffer(self):
        return os.path.join(self.tmp_dir, "all_trace.db")

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def reset_buffer(self):
        self.pad_count = 0
        self.pad_start = 0
        self.pad_end = 0
        self.display_start = 0
        self.display_end = 0
        self.pad.clear()

    def apply_filter(self, filter_text):
        filter_text = filter_text.strip()
        if filter_text == "":
            filter_text = None
        if filter_text != self.filter_text:
            self.filter_text = filter_text
            filtered_events = self.get_filtered_events()
            del self.trace_buffer
            self.trace_buffer = TraceBuffer()
            self.trace_buffer.set(filtered_events)
            self.reset_buffer()
            self.scroll_to_bottom()
            self.pad_display()

    def get_filtered_events(self):
        filtered_events = self.all_traces.filter(self.filter_text)
        return filtered_events

    def filter_check(self, event):
        if self.filter_text == None or self.filter_text == "":
            return False
        filter_out = True
        for key in event:
            value = str(event[key])
            if re.search(self.filter_text, value):
                filter_out = False
                break
        return filter_out

    def event_update(self, event, refresh):
        if event:
            event_id = self.all_traces.length()
            event['id'] = event_id
            self.all_traces.append(event)
            if self.filter_text:
                filter_out = self.filter_check(event)
                if not filter_out:
                    self.trace_buffer.append(event)
            else:
                self.trace_buffer.append(event)
        if refresh:
            if not self.pad_displaying:
                self.pad_displaying = True
                t = threading.Timer(0.1, self.pad_defered_display)
                t.start()

    def pad_defered_display(self):
        self.select_index = None
        self.scroll_to_bottom()
        self.pad_display()
        self.pad_displaying = False

    def scroll_to_bottom(self):
        self.display_end = self.trace_buffer.length()
        self.display_start = self.display_end - self.pad_display_height
        if self.display_start < 0:
            self.display_start = 0

    def scroll_up(self, to):
        buf_count = self.trace_buffer.length()
        self.display_start = to
        self.display_end = self.display_start + self.pad_display_height
        if self.display_end >= buf_count:
            self.display_end = buf_count

    def scroll_down(self, to):
        self.display_end = to + 1
        self.display_start = self.display_end - self.pad_display_height
        if self.display_start < 0:
            self.display_start = 0

    def page_up(self):
        self.select_index = None
        self.display_start -= self.pad_display_height
        if self.display_start < 0:
            self.display_start = 0
        self.display_end = self.display_start + self.pad_display_height
        buf_count = self.trace_buffer.length()
        if self.display_end >= buf_count:
            self.display_end = buf_count
        self.pad_display()

    def page_down(self):
        self.select_index = None
        buf_count = self.trace_buffer.length()
        self.display_end += self.pad_display_height
        if self.display_end >= buf_count:
            self.display_end = buf_count
        self.display_start = self.display_end - self.pad_display_height
        if self.display_start < 0:
            self.display_start = 0
        self.pad_display()

    def pad_reload(self, afterward):
        load_count = int(self.pad_height/2)
        buf_count = self.trace_buffer.length()
        if afterward:
            pad_end = self.display_end + load_count
            if pad_end > buf_count:
                pad_end = buf_count
            if pad_end - self.pad_start >= self.pad_height:
                pad_start = pad_end - load_count
            else:
                pad_start = self.pad_start
        else:
            pad_start = self.display_start - load_count
            if pad_start < 0:
                pad_start = 0
            pad_end = pad_start + self.pad_height
            if pad_end > buf_count:
                pad_end = buf_count
        if self.pad_start != pad_start:
            self.pad.clear()
            self.reloaded += 1
        self.pad_count = 0
        self.pad_start = pad_start
        self.pad_end = pad_end
        for pos in range(self.pad_start, self.pad_end):
            event = self.trace_buffer.read(pos)
            if event:
                self.event_format_add(event)
            else:
                length = self.trace_buffer.length()
                self.logger.error(f"row {pos} is none, {length}!!")

    def pad_refresh(self):
        display_start = self.display_start - self.pad_start
        self.pad.refresh(display_start, 0, self.y + 2, self.x + 1, self.y + self.height - 2, self.x + self.width - 1)

    def pad_display(self, force_reload=False):
        if force_reload:
            self.pad_reload(True)
        if self.display_end > self.pad_end:
            self.pad_reload(True)
        if self.display_start < self.pad_start:
            self.pad_reload(False)
        self.pad_refresh()

    def get_relative_timestamp(self, timestamp):
        if self.first_ts == None:
            self.first_ts = timestamp
            return "0.000000"
        else:
            return "%.6f" % (timestamp - self.first_ts)

    def event_format_add(self, event):
        level = event['level']
        ts = event['timestamp']
        relative_ts = self.get_relative_timestamp(ts)
        row = self.format_str.format(str(event['id']), relative_ts, event['comm'], \
           str(event['pid']), str(event['uid']), event['name'], level, event['detail'])
        padding_width = "{:<%d}" % self.pad_width
        row = padding_width.format(row)
        pad_row = self.pad_start + self.pad_count
        if self.select_index == pad_row:
            self.pad.addstr(self.pad_count, 0, row, self.hl_color)
            self.pad_count += 1
        elif level == "ERROR":
            self.pad.addstr(self.pad_count, 0, row, self.error_color)
            self.pad_count += 1
        elif level == "WARNING":
            self.pad.addstr(self.pad_count, 0, row, self.warn_color)
            self.pad_count += 1
        else:
            self.pad.addstr(self.pad_count, 0, row)
            self.pad_count += 1

    def select_row(self, dir_up):
        buf_count = self.trace_buffer.length()
        if buf_count == 0:
            return
        if dir_up:
            if self.select_index == None:
                self.select_index = self.display_end - 1
            else:
                self.select_index -= 1
            if self.select_index < 0:
                self.select_index = 0
        else:
            if self.select_index == None:
                self.select_index = self.display_start
            else:
                self.select_index += 1
            if self.select_index >= buf_count:
                self.select_index = buf_count - 1
        if self.select_index < self.display_start:
            self.scroll_up(self.select_index)
        elif self.select_index >= self.display_end:
            self.scroll_down(self.select_index)
        self.pad_display(True)

    def get_stats(self):
        result = {
           "total": self.all_traces.length(),
           "display_start":self.display_start,
           "display_end":self.display_end,
           "reloaded":self.reloaded
        }
        if self.filter_text:
            result['filtered'] = self.trace_buffer.length()
        return result

    def get_selected_event(self):
        if self.select_index == None:
            return None
        else:
            return self.trace_buffer.read(self.select_index)

    def display(self):
        super().clear()
        super().display()
        header = self.format_str.format("NO.", "TIME", "COMMAND", "PID", "UID", "NAME", "LEVEL", "DETAIL")
        curse_win = super().curse_handle()
        padding_width = "{:<%d}" % self.pad_width
        header = padding_width.format(header)
        curse_win.addstr(0, 0, header, curses.A_BOLD |self.hdr_color)
        curse_win.refresh()

    def close(self):
        self.trace_buffer.close()
        self.all_traces.close()

    def __del__(self):
        pass

class ExtendWin(CurseWin):
    def __init__(self, stdscr, width, height, x = 0, y = 0, title=None):
        super().__init__(stdscr, width, height, x, y, title)
        self.width = width
        self.height = height
        self.x = x
        self.y = y
        self.pad_width = width - 2
        self.pad_height = 4096
        self.pad = curses.newpad(self.pad_height, self.pad_width)

    def display(self):
        super().clear()
        super().display()

    def show_event(self, event):
        super().clear()
        curse_win = super().curse_handle()
        name = event['name']
        extend = event['extend']
        table = []
        dt = datetime.fromtimestamp(event['timestamp'])
        dt_str = dt.strftime('%Y-%m-%d %H:%M:%S.%f')
        table.append(['Date time', dt_str])
        for k in extend:
            key_col = "{:24s}".format(k)
            row = [key_col, extend[k]]
            table.append(row)
        extend_info = tabulate(table, tablefmt="plain")
        super().display()
        self.pad.clear()
        self.pad.addstr(0, 0, extend_info)
        self.pad.refresh(0, 0, self.y + 1, self.x + 1, self.y + self.height - 2, self.x + self.width - 1)

