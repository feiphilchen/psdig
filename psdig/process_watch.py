#!/usr/bin/env python3
import os
import sys
import time
import curses
import logging
import re
import traceback
from datetime import datetime
import time
from curses import wrapper
from curses.textpad import Textbox,rectangle
import threading
from .trace_manager import TraceManager
from .window import FilterWin,StatusWin,MainWin,TagWin,ExtendWin
from .trace_buffer import TraceBuffer
from .conf import LOGGER_NAME

class PsWatch(object):
    def __init__(self, stdscr, 
               pid_filter=[], 
               uid_filter=[], 
               event_file=None,
               load_from=None,
               log_file=None):
        self.set_logger(log_file)
        self.win_list = []
        self.stdscr = stdscr
        self.focus_pos = None
        self.watch_thread = None
        self.stats_thread = None
        self.event_scroll = True
        self.filter_editing = False
        self.stats_running = False
        self.event_file = event_file
        self.load_from = load_from
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_RED)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_YELLOW)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_GREEN)
        self.trace_mgr = TraceManager(pid_filter=pid_filter, uid_filter=uid_filter)
        self.running = False
        self.ext_display = False
        self.mutex = threading.Lock()
        self.init_windows()

    def set_logger(self, logfile):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)
        if not logfile:
            logfile = "/dev/null"
        self.logger.setLevel(logging.DEBUG)
        # create file handler which logs even debug messages
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        trace_formatter = logging.Formatter("%(asctime)s [%(levelname)s] " + f"{self.logger_name}" + ": %(message)s")
        fh.setFormatter(trace_formatter)
        self.logger.addHandler(fh)

    def init_windows(self):
        status_win_height = 4
        status_win_width = curses.COLS
        status_win_x = 0
        status_win_y = 0
        filter_win_height = 3
        filter_win_width = curses.COLS
        filter_win_x = 0
        filter_win_y = status_win_height
        tag_win_width = 30
        tag_win_height =  curses.LINES - status_win_height - filter_win_height
        tag_win_x = curses.COLS - tag_win_width
        tag_win_y = status_win_height + filter_win_height
        main_win_width = curses.COLS  - tag_win_width
        main_win_height = curses.LINES - status_win_height - filter_win_height
        main_win_x = 0
        main_win_y = status_win_height + filter_win_height
        self.status_win = StatusWin(self.stdscr, status_win_width, status_win_height, status_win_x, status_win_y, "Status")
        self.win_list.append(self.status_win)
        self.filter_win = FilterWin(self.stdscr, filter_win_width, filter_win_height, filter_win_x, filter_win_y, "Filter")
        self.win_list.append(self.filter_win)
        self.main_win = MainWin(self.stdscr, main_win_width, main_win_height, \
                  main_win_x, main_win_y, "Traces", event_file=self.event_file)
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
        #sys.stdout = sys.__stdout__
        #sys.stdout.write("start to edit ..")
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
        event['timestamp'] = time.time()
        if self.filter_editing or not self.event_scroll:
            refresh = False
        else:
            refresh = True
        with self.mutex:
            try:
                self.main_win.event_update(event, refresh)
            except:
                self.logger.error(traceback.format_exc())

    def process_event_from_file(self, event):
        refresh = False
        with self.mutex:
            try:
                self.main_win.event_update(event, refresh)
            except:
                self.logger.error(traceback.format_exc())

    def watch(self):
        try:
            self.trace_mgr.collect(self.process_watched_event)
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
        loading,loaded = self.trace_mgr.loading_status()
        if loading > 0 and loading != loaded:
            percent = int((loaded/loading) * 100)
            return f"Loading events collector, {percent}%"   
        if self.load_from == None and not self.event_scroll:
            return "Scrolling is stopped, press <SPACE> to continue..."
        return "Watching ..."

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
        if input_ch == ord('f'):
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
        self.display_windows()
        if self.load_from == None:
            self.start_watch_thread()
        else:
            self.load_events(self.load_from)
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

    def stop(self):
        self.stop_watch_thread()
        self.stop_stats_thread()
        self.running = False
        if self.main_win:
            del self.main_win
            self.main_win = None

