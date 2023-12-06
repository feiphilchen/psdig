#!/usr/bin/env python3
import os
import sys
import time
import curses
import logging
import re
import json
import traceback
from datetime import datetime
import time
from curses import wrapper
from curses.textpad import Textbox,rectangle
import threading
from .trace_manager import TraceManager
from .trace_conf import TraceConfFile
from .window import FilterWin,StatusWin,MainWin,TagWin,ExtendWin
from .conf import LOGGER_NAME

class PsWatch(object):
    def __init__(self, stdscr, 
               pid_filter=[], 
               uid_filter=[], 
               event_file=None,
               load_from=None,
               log_file=None,
               conf=None,
               tmp_dir="/var/tmp"):
        self.set_logger(log_file)
        self.win_list = []
        self.stdscr = stdscr
        self.focus_pos = None
        self.watch_thread = None
        self.stats_thread = None
        self.event_scroll = True
        self.headless = False
        self.filter_editing = False
        self.stats_running = False
        self.event_file = event_file
        self.tmp_dir = tmp_dir
        self.load_from = load_from
        self.conf = conf
        self.trace_mgr = TraceManager(pid_filter=pid_filter, uid_filter=uid_filter, conf=self.conf, tmp_dir=tmp_dir)
        self.running = False
        self.stopped = False
        self.ext_display = False
        self.help_info = True
        self.mutex = threading.Lock()

    def set_logger(self, logfile):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)
        if not logfile:
            logfile = "/dev/null"
        self.logger.setLevel(logging.INFO)
        # create file handler which logs even debug messages
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        trace_formatter = logging.Formatter("%(asctime)s [%(levelname)s] " + f"{self.logger_name}" + ": %(message)s")
        fh.setFormatter(trace_formatter)
        self.logger.addHandler(fh)

    def init_windows(self):
        status_win_height = 3
        status_win_width = curses.COLS
        status_win_x = 0
        status_win_y = 0
        filter_win_height = 3
        filter_win_width = curses.COLS
        filter_win_x = 0
        filter_win_y = status_win_height
        tag_win_width = 30
        if self.help_info:
            tag_win_height =  curses.LINES - status_win_height - filter_win_height - 1
        else:
            tag_win_height =  curses.LINES - status_win_height
        tag_win_x = curses.COLS - tag_win_width
        tag_win_y = status_win_height + filter_win_height
        main_win_width = curses.COLS  - tag_win_width
        if self.help_info:
            main_win_height = curses.LINES - status_win_height - filter_win_height - 1
        else:
            main_win_height = curses.LINES - status_win_height - filter_win_height
        main_win_x = 0
        main_win_y = status_win_height + filter_win_height
        self.status_win = StatusWin(self.stdscr, status_win_width, status_win_height, status_win_x, status_win_y, "Status")
        self.win_list.append(self.status_win)
        self.filter_win = FilterWin(self.stdscr, filter_win_width, filter_win_height, filter_win_x, filter_win_y, "Filter")
        self.win_list.append(self.filter_win)
        self.main_win = MainWin(self.stdscr, main_win_width, main_win_height, \
                  main_win_x, main_win_y, "Traces", event_file=self.event_file, tmp_dir=self.tmp_dir)
        self.win_list.append(self.main_win)
        self.tag_win = TagWin(self.stdscr, tag_win_width, tag_win_height, tag_win_x, tag_win_y, "Statistics")
        self.win_list.append(self.tag_win)
        ext_win_width = int(main_win_width/2)
        ext_win_height = int(main_win_height/2)
        ext_win_x = main_win_x + int((main_win_width - ext_win_width)/2)
        ext_win_y = main_win_y + int((main_win_height - ext_win_height)/2)
        self.ext_win = ExtendWin(self.stdscr, ext_win_width, ext_win_height, ext_win_x, ext_win_y, "Event Details")
    
    def display_windows(self):
        #self.stdscr.clear()
        for win in self.win_list:
            win.display()

    def display_help(self):
        help_color = curses.color_pair(6)
        keys_help = {
            "SPACE":"Stop/Resume scrolling",
            "UP": "Scroll up",
            "DOWN": "Scroll down",
            "LEFT": "Page up",
            "RIGHT": "Page down",
            "ENTER": "Show/Hide detail",
            "F1": "Filter",
        }
        win_width = "{:<%d}" % (curses.COLS - 1)
        help_row = win_width.format("")
        try:
            self.stdscr.addstr(curses.LINES - 1, 0, help_row, help_color)
        except:
            self.logger.error(traceback.format_exc())
        help_str = ""
        self.stdscr.addstr(curses.LINES - 1, 0, help_str)
        for k in keys_help:
            help_str = keys_help[k]
            self.stdscr.addstr(f"{k}")
            self.stdscr.addstr(f'{help_str}  ', help_color)


    def gui_init(self):
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_RED)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_YELLOW)
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_BLUE)
        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_GREEN)
        self.init_windows()
        self.display_windows()
        if self.help_info:
            self.display_help()

    def focus_next(self):
        if self.focus_pos == None:
            self.focus_pos = 0
        else:
            self.focus_pos += 1
        win_nr = len(self.win_list)
        if self.focus_pos >= win_nr:
            self.focus_pos = 0
        for pos in range(win_nr):
            if pos == self.focus_pos:
                self.win_list[pos].focus()
            elif self.win_list[pos].is_focused():
                self.win_list[pos].unfocus()
        self.display_windows()
        if self.win_list[self.focus_pos].is_text_mode():
            self.win_list[self.focus_pos].start_edit()

    def focus(self, w):
        if w.is_focused():
            return
        for win in self.win_list:
            if win.is_focused():
                win.unfocus()
                win.display()
        w.focus()
        w.display()

    def unfocus(self, w):
        if not w.is_focused():
            return
        w.unfocus()
        w.display()

    def process_watched_event(self, event):
        #event['timestamp'] = time.time()
        if self.filter_editing or not self.event_scroll:
            refresh = False
        else:
            refresh = True
        with self.mutex:
            try:
                self.main_win.event_update(event, refresh)
            except:
                self.logger.error(traceback.format_exc())

    def process_watched_event_headless(self, event):
        boot_ts = "%.6f" % (time.time() - time.monotonic())
        dt = datetime.fromtimestamp(event['timestamp'])
        dt_str = dt.strftime('%H:%M:%S.%f')
        print(f"{dt_str} >> {event['name']} [{event['level']}]: ({event['comm']} pid={event['pid']} uid={event['uid']}) " + \
             f">> {event['detail']}")

    def process_event_from_file(self, event):
        refresh = False
        with self.mutex:
            try:
                self.main_win.event_update(event, refresh)
            except:
                self.logger.error(traceback.format_exc())

    def watch(self):
        try:
            if not self.headless:
                self.trace_mgr.collect(self.process_watched_event)
            else:
                self.trace_mgr.collect(self.process_watched_event_headless)
        except:
            pass
        finally:
            self.running = False

    def start_watch_thread(self):
        self.watch_thread = threading.Thread(target = self.watch, args = (), daemon=True)
        self.watch_thread.start()

    def stop_watch_thread(self):
        if self.watch_thread:
            self.trace_mgr.stop()
            self.watch_thread.join()
            self.watch_thread = None

    def get_message(self):
        message = None
        if self.load_from != None:
            return f"Loaded from: {self.load_from} "
        loading,loaded = self.trace_mgr.loading_status()
        if loading > 0 and loading != loaded:
            percent = int((loaded/loading) * 100)
            return f"Loading events collector, {percent}%"   
        if not self.event_scroll:
            return "Scrolling is stopped, press <SPACE> to continue ..."
        prefix = ['|', '/', '-', '\\']
        phash = int(time.time())%4
        return "Watching ... " + prefix[phash]

    def stats(self):
        self.stats_running =  True
        while self.stats_running:
            if not self.filter_editing:
                with self.mutex:
                    tag_stats = self.trace_mgr.get_stats()
                    self.tag_win.stats_update(tag_stats)
                    main_stats = self.main_win.get_stats()
                    main_stats['message'] = self.get_message()
                    self.status_win.update_stats(main_stats)
            time.sleep(1)

    def start_stats_thread(self):
        self.stats_thread = threading.Thread(target = self.stats, args = (), daemon=True)
        self.stats_thread.start()

    def stop_stats_thread(self):
        if self.stats_thread:
            self.stats_running = False
            self.stats_thread.join()
            self.stats_thread = None

    def key_handler(self, input_ch):
        if input_ch == ord('f') or input_ch == curses.KEY_F1:
            self.focus(self.filter_win)
            self.filter_editing = True
            try:
                filter_text = self.filter_win.edit()
            except:
                self.running = False
                self.unfocus(self.filter_win)
                return
            self.unfocus(self.filter_win)
            self.main_win.apply_filter(filter_text)
            self.filter_editing = False
        elif input_ch == ord(' '):
            self.event_scroll = not self.event_scroll
            if self.event_scroll:
                self.main_win.event_update(None, True)
        elif input_ch == curses.KEY_UP:
            self.event_scroll = False
            self.main_win.select_row(True)
        elif input_ch == curses.KEY_DOWN:
            self.event_scroll = False
            self.main_win.select_row(False)
        elif input_ch == curses.KEY_LEFT or input_ch == curses.KEY_PPAGE:
            self.event_scroll = False
            self.main_win.page_up()
        elif input_ch == curses.KEY_RIGHT or input_ch == curses.KEY_NPAGE:
            self.event_scroll = False
            self.main_win.page_down()
        elif input_ch == curses.KEY_ENTER or input_ch == 10 or input_ch == 13:
            if not self.ext_display:
                event = self.main_win.get_selected_event()
                if event:
                    self.ext_win.show_event(event)
                    self.ext_display = True
            else:
                self.main_win.pad_display()
                self.ext_display = False

    def load_events(self, event_file):
        self.trace_mgr.file_read(event_file, self.process_event_from_file)
        self.main_win.event_update(None, True)

    def run(self):
        self.running = True
        self.gui_init()
        self.display_windows()
        if self.load_from == None:
            self.start_watch_thread()
        else:
            self.logger.info("load traces from %s" % self.load_from)
            try:
                self.load_events(self.load_from)
            except:
                self.logger.error(traceback.format_exc())
        self.start_stats_thread()
        while self.running:
            try:
                input_ch = self.stdscr.getch()
            except:
                self.running = False
                break
            if input_ch == ord('q'):
                break
            else:
                with self.mutex:
                    try:
                        self.key_handler(input_ch)
                    except:
                        self.logger.error(traceback.format_exc())

    def run_headless(self):
        self.running = True
        self.headless = True
        self.start_watch_thread()
        while self.running:
            time.sleep(0.2)

    def stats_to_log(self, stats):
        total = 0
        items = []
        for key,val in stats.items():
            if val == 0:
                continue
            total += val
            items.append("# {:20s} {:6d}".format(key,val))
        return "%d traces collected\n%s" % (total, '\n'.join(items))

    def stop(self):
        if self.stopped:
            return
        self.stopped = True
        self.stop_watch_thread()
        self.stop_stats_thread()
        self.running = False
        if self.load_from == None:
            stats = self.trace_mgr.get_stats()
            stats_log = self.stats_to_log(stats)
            self.logger.info(stats_log)
        if not self.headless and self.main_win:
            self.main_win.close()
