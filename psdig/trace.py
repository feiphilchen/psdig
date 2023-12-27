# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com
import os
import sys
import re
import click
import signal
from .syscall import Syscall
from .event import Event
from .tracepoint import TracePoint
from .uprobe import Uprobe
from .lambda_helper import *
from .dwarf import Dwarf
import tempfile

tracepoint=None
uprobe=None
def sig_handler(sig, frame):
    if tracepoint != None:
        tracepoint.stop()
    if uprobe != None:
        uprobe.stop()
    sys.exit(0)

default_syscall_fmt="lambda:time_str(metadata['timestamp']) + ' %s(%s): '%(metadata.get('comm'), metadata.get('pid')) + syscall_format(syscall, args, ret, metadata)"
def syscall_print_fmt(syscall, metadata, args, ret, ctx):
    fmt,filter_f = ctx
    if filter_f:
        filter_ret = filter_f(syscall, metadata, args, ret)
        if not filter_ret:
            return
    print(fmt.format(syscall=syscall, metadata=metadata, args=args, ret=ret))


def syscall_print_lambda(syscall, metadata, args, ret, ctx):
    lambda_f,filter_f = ctx
    if filter_f:
        filter_ret = filter_f(syscall, metadata, args, ret)
        if not filter_ret:
            return
    print(lambda_f(syscall, metadata, args, ret))

def complete_syscall(ctx, param, incomplete):
    syscalls = Syscall.get_all()
    return [s for s in syscalls if s.startswith(incomplete)]

def validate_syscall(ctx, param, value):
    list_syscall = ctx.params.get('list')
    if list_syscall == True:
        Syscall.table_print(None if len(value) == 0 else value)
        sys.exit(0)
    if len(value) == 0:
        raise click.BadParameter("no syscall to trace")
    syscalls = Syscall.get_all(value)
    if len(syscalls) == 0:
        raise click.BadParameter("no syscall to trace")
    if len(syscalls) > 16:
        raise click.BadParameter("too many syscalls to trace")
    return list(set(syscalls))

@click.command()
@click.option('--output', '-o', type=str, default=default_syscall_fmt, help="Format string")
@click.option('--filter', '-f', type=str, help="Filter string")
@click.option('--pid', '-p', type=int, multiple=True, help='Pid filter')
@click.option('--uid', '-u', type=int, multiple=True, help='Uid filter')
@click.option('--comm', '-c', type=str, multiple=True, help='Command filter')
@click.option('--list', '-l', is_flag=True, help='List all syscalls and exit')
@click.argument('syscall', nargs=-1, shell_complete=complete_syscall, callback=validate_syscall)
def syscall_trace(output, filter, pid, uid, comm, list, syscall):
    """Trace syscall"""
    global tracepoint
    with tempfile.TemporaryDirectory() as tmpdirname:
        tracepoint = TracePoint(pid_filter=pid, uid_filter=uid, comm_filter=comm)
        syscall_obj = Syscall(tracepoint)
        if filter:
            filter_f = lambda syscall,metadata,args,ret:eval(filter)
        else:
            filter_f = None
        if output.strip().startswith('lambda:'):
            lambda_str = output.split(':', 1)[1]
            lambda_f = lambda syscall,metadata,args,ret:eval(lambda_str)
            ctx = lambda_f,filter_f
            callback = syscall_print_lambda
        else:
            ctx = output,filter_f
            callback = syscall_print_fmt
        for s in syscall:
            syscall_obj.add(s, callback, ctx)
        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)
        tracepoint.start(obj_dir=tmpdirname)

default_event_fmt="lambda:time_str(metadata['timestamp']) + ' %s(%s): '%(metadata.get('comm'), metadata.get('pid')) + f' {name}: ' + ','.join([f'{k}={v}' for k,v in args.items()])"
def event_print_fmt(name, metadata, args, ctx):
    fmt,filter_f = ctx
    if filter_f:
        filter_ret = filter_f(name, metadata, args)
        if not filter_ret:
            return
    print(fmt.format(name=name, metadata=metadata, args=args))

def event_print_lambda(name, metadata, args, ctx):
    lambda_f,filter_f = ctx
    if filter_f:
        filter_ret = filter_f(name, metadata, args)
        if not filter_ret:
            return
    print(lambda_f(name, metadata, args))

def complete_event(ctx, param, incomplete):
    events = Event.get_all()
    return [e for e in events if e.startswith(incomplete)]

def validate_event(ctx, param, value):
    list_event = ctx.params.get('list')
    if list_event == True:
        Event.table_print(None if len(value) == 0 else value)
        sys.exit(0)
    if len(value) == 0:
        raise click.BadParameter("no event to trace")
    events = Event.get_all(value)
    if len(events) == 0:
        raise click.BadParameter("no event to trace")
    if len(events) > 16:
        raise click.BadParameter("too many events to trace")
    return list(set(events))

@click.command()
@click.option('--output', '-o', type=str, default=default_event_fmt,help="Format string")
@click.option('--filter', '-f', type=str, help="Filter string")
@click.option('--pid', '-p', type=int, multiple=True, help='Pid filter')
@click.option('--uid', '-u', type=int, multiple=True, help='Uid filter')
@click.option('--comm', '-c', type=str, multiple=True, help='Command filter')
@click.option('--list', '-l', is_flag=True, help='List all events and exit')
@click.argument('event', nargs=-1, shell_complete=complete_event, callback=validate_event)
def event_trace(output, filter, pid, uid, comm, list, event):
    """Trace event"""
    global tracepoint
    with tempfile.TemporaryDirectory() as tmpdirname:
        tracepoint = TracePoint(pid_filter=pid, uid_filter=uid, comm_filter=comm)
        event_obj = Event(tracepoint)
        if filter:
            filter_f = lambda name,metadata,args:eval(filter)
        else:
            filter_f = None
        if output.strip().startswith('lambda:'):
            lambda_str = output.split(':', 1)[1]
            lambda_f = lambda name,metadata,args:eval(lambda_str)
            ctx = lambda_f,filter_f
            callback = event_print_lambda
        else:
            ctx = output,filter_f
            callback = event_print_fmt
        for evt in event:
             event_obj.add(evt, callback, ctx)
        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)
        tracepoint.start(obj_dir=tmpdirname)

def uprobe_print_fmt(function, metadata, args, ret, ctx):
    fmt,filter_f = ctx
    if filter_f:
        filter_ret = filter_f(function, metadata, args, ret)
        if not filter_ret:
            return
    print(fmt.format(metadata=metadata, function=function, args=args, ret=ret))

def uprobe_print_lambda(function, metadata, args, ret, ctx):
    lambda_f,filter_f = ctx
    if filter_f:
        filter_ret = filter_f(function, metadata, args, ret)
        if not filter_ret:
            return
    print(lambda_f(function, metadata, args, ret))


def complete_uprobe_function(ctx, param, incomplete):
    elf = ctx.params.get('elf')
    sym = ctx.params.get('sym')
    try:
        if sym:
            dwarf = Dwarf(sym)
        else:
            dwarf = Dwarf(elf)
        functions = dwarf.all_functions()
    except:
        return []
    return [f for f in functions if f.startswith(incomplete)]

def validate_uprobe_function(ctx, param, value):
    if len(value) == 0:
        raise click.BadParameter("no function to trace")
    elf = ctx.params.get('elf')
    sym = ctx.params.get('sym')
    try:
        if sym:
            dwarf = Dwarf(sym)
        else:
            dwarf = Dwarf(elf)
    except:
        raise click.BadParameter(f'error resolving symbols from {elf}')
    return list(set(value))

default_uprobe_fmt="lambda:time_str(metadata['timestamp']) + ' %s(%s): '%(metadata.get('comm'), metadata.get('pid')) + uprobe_format(function, args, ret, metadata)"
@click.command()
@click.option('--output', '-o', type=str, default=default_uprobe_fmt, help="Output format")
@click.option('--filter', '-f', type=str, help="Filter string")
@click.option('--pid', '-p', type=int, multiple=True, help='Pid filter')
@click.option('--uid', '-u', type=int, multiple=True, help='Uid filter')
@click.option('--comm', '-c', type=str, multiple=True, help='Command filter')
@click.option('--sym', '-s', type=click.Path(exists=True), help='Symbol file')
@click.argument('elf', type=click.Path(exists=True))
@click.argument('function', nargs=-1, shell_complete=complete_uprobe_function, callback=validate_uprobe_function)
def uprobe_trace(output, filter, pid, uid, comm, sym, elf, function):
    """Trace uprobe"""
    global uprobe
    with tempfile.TemporaryDirectory() as tmpdirname:
        uprobe = Uprobe(pid_filter=pid, uid_filter=uid, comm_filter=comm)
        if filter:
            filter_f = lambda function,metadata,args,ret:eval(filter)
        else:
            filter_f = None
        if output.strip().startswith('lambda:'):
            lambda_str = output.split(':', 1)[1]
            lambda_f = lambda function,metadata,args,ret:eval(lambda_str)
            ctx = lambda_f,filter_f
            callback = uprobe_print_lambda
        else:
            ctx = output,filter_f
            callback = uprobe_print_fmt
        for func in function:
            uprobe.add(elf, func, callback, True, ctx, sym)
            uprobe.add(elf, func, callback, False, ctx, sym)
        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)
        try:
            uprobe.start(obj_dir=tmpdirname)
        except Exception as e:
            sys.exit(f"Error: {e}")


