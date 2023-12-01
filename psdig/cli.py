import os
import sys
import time
import click
import curses
import logging
import re
import traceback
from curses import wrapper
from psdig import PsWatch,syscall_trace,event_trace,uprobe_trace
from .trace_conf import TraceConfFile
import tempfile
import signal

pswatch=None

def watch_interrupt(sig, frame):
    pswatch.stop()

def watch_start(stdscr, pid, uid, output, log, trace_conf):
    stdscr.clear()
    stdscr.refresh()
    global pswatch
    with tempfile.TemporaryDirectory() as tmpdirname:
        pswatch = PsWatch(stdscr, pid_filter=pid, uid_filter=uid, \
           event_file=output, log_file=log, conf=trace_conf, \
           tmp_dir=tmpdirname)
        signal.signal(signal.SIGINT, watch_interrupt)
        try:
            pswatch.run()
        except:
            pass
        finally:
            pswatch.stop()

def watch_headless(pid, uid, output, log, trace_conf):
    global pswatch
    with tempfile.TemporaryDirectory() as tmpdirname:
        pswatch = PsWatch(None, pid_filter=pid, uid_filter=uid, \
           event_file=output, log_file=log, conf=trace_conf, \
           tmp_dir=tmpdirname)
        signal.signal(signal.SIGINT, watch_interrupt)
        try:
            pswatch.run_headless()
        except:
            pass
        finally:
            pswatch.stop()

def event_load(stdscr, input_file, log):
    stdscr.clear()
    stdscr.refresh()
    pswatch = PsWatch(stdscr, load_from=input_file, log_file=log)
    try:
        pswatch.run()
    except:
        pass
    finally:
        pswatch.stop()

def validate_conf(ctx, param, value):
    conf = TraceConfFile(value)
    error = conf.load()
    if error is not None:
        raise click.BadParameter(error)
    return conf

@click.command()
@click.option('--pid', '-p', type=int, multiple=True, help='Pid filter')
@click.option('--uid', '-u', type=int, multiple=True, help='Uid filter')
@click.option('--output', '-o', type=click.Path(), help='Save traces to the file')
@click.option('--log', '-l', type=click.Path(), help='Log all messages to logfile')
@click.option('--headless', is_flag=True, help='Run without curse windows')
@click.option('--conf', '-c', type=click.File('r'), callback=validate_conf, help='Configuation file')
def watch(pid, uid, output, log, headless, conf):
    """Watch file system, network and process activity"""
    if not headless:
        wrapper(watch_start, pid, uid, output, log, conf)
    else:
        watch_headless(pid, uid, output, log, conf)

@click.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Load events from the file')
@click.option('--log', '-l', type=click.Path(), help='Log all messages to logfile')
def load(input, log):
    """Load traces from file"""
    wrapper(event_load,  input, log)
    pass

@click.group()
def trace():
    """Trace syscall/event/uprobe"""
    pass

@click.group()
def cli():
    """Tool for monitoring system/process activity"""
    pass

cli.add_command(watch, 'watch')
cli.add_command(load,'load')
cli.add_command(trace,'trace')
trace.add_command(syscall_trace, 'syscall')
trace.add_command(event_trace, 'event')
trace.add_command(uprobe_trace, 'uprobe')

