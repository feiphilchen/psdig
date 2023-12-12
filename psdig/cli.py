import os
import sys
import time
import click
import curses
import logging
import re
import traceback
from curses import wrapper
from .process_watch import PsWatch
from .trace import syscall_trace,event_trace,uprobe_trace
from .trace_conf import TraceConfFile
import tempfile
import signal

pswatch=None

def watch_interrupt(sig, frame):
    pswatch.stop()

def watch_start(stdscr, pid, uid, comm, output, log, trace_conf):
    stdscr.clear()
    stdscr.refresh()
    global pswatch
    with tempfile.TemporaryDirectory() as tmpdirname:
        pswatch = PsWatch(stdscr, pid_filter=pid, uid_filter=uid, \
           comm_filter=comm, event_file=output, log_file=log, conf=trace_conf, \
           tmp_dir=tmpdirname)
        signal.signal(signal.SIGINT, watch_interrupt)
        signal.signal(signal.SIGTERM, watch_interrupt)
        try:
            pswatch.run()
        except:
            pass
        finally:
            pswatch.stop()

def watch_headless(pid, uid, comm, output, log, trace_conf):
    global pswatch
    with tempfile.TemporaryDirectory() as tmpdirname:
        pswatch = PsWatch(None, pid_filter=pid, uid_filter=uid, \
           comm_filter=comm, event_file=output, log_file=log, conf=trace_conf, \
           tmp_dir=tmpdirname)
        signal.signal(signal.SIGINT, watch_interrupt)
        signal.signal(signal.SIGTERM, watch_interrupt)
        try:
            pswatch.run_headless()
        except:
            pass
        finally:
            pswatch.stop()

def trace_load(stdscr, input_file, log):
    stdscr.clear()
    stdscr.refresh()
    with tempfile.TemporaryDirectory() as tmpdirname:
        pswatch = PsWatch(stdscr, load_from=input_file, log_file=log, tmp_dir=tmpdirname)
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
@click.option('--comm', '-c', type=str, multiple=True, help='Command filter')
@click.option('--output', '-o', type=click.Path(), help='Save traces to file')
@click.option('--log', '-l', type=click.Path(), help='Log messages to file')
@click.option('--template', '-t', type=click.File('r'), callback=validate_conf, help='Template file')
@click.option('--headless', is_flag=True, help='Run without curse windows')
def watch(pid, uid, comm, output, log, template, headless):
    """Watch file system, network and process activity"""
    if not headless:
        wrapper(watch_start, pid, uid, comm, output, log, template)
    else:
        watch_headless(pid, uid, comm, output, log, template)

@click.command()
@click.option('--log', '-l', type=click.Path(), help='Log all messages to file')
@click.argument('file', type=click.Path(exists=True))
def load(log, file):
    """Load traces from file"""
    wrapper(trace_load,  file, log)
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

