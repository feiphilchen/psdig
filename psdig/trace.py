#!/usr/bin/python3
# vim: set filetype=python
import os
import sys
import re
import click
from .syscall import Syscall
from .event import Event
from .tracepoint import TracePoint
from .uprobe import Uprobe
from .lambda_helper import *
import tempfile

default_syscall_fmt="lambda:f'{name}(' + ','.join([f'{k}={v}' for k,v in args.items()]) + f')={ret}'"
def syscall_print_fmt(name, metadata, args, ret, ctx):
    fmt,filter_f = ctx
    if filter_f:
        filter_ret = filter_f(name, metadata, args, ret)
        if not filter_ret:
            return
    print(fmt.format(name=name, metadata=metadata, args=args, ret=ret))

def syscall_print_lambda(name, metadata, args, ret, ctx):
    lambda_f,filter_f = ctx
    if filter_f:
        filter_ret = filter_f(name, metadata, args, ret)
        if not filter_ret:
            return
    print(lambda_f(name, metadata, args, ret))

@click.command()
@click.option('--output', '-o', type=str, default=default_syscall_fmt, help="Format string")
@click.option('--filter', '-F', type=str, help="Filter string")
@click.option('--pid', '-p', type=int, multiple=True, help='Pid filter')
@click.option('--uid', '-u', type=int, multiple=True, help='Uid filter')
@click.argument('syscall')
def syscall_trace(output, filter, pid, uid, syscall):
    """Trace syscall"""
    with tempfile.TemporaryDirectory() as tmpdirname:
        tracepoint = TracePoint(pid_filter=pid, uid_filter=uid)
        syscall_obj = Syscall(tracepoint)
        if filter:
            filter_f = lambda name,metadata,args,ret:eval(filter)
        else:
            filter_f = None
        if output.strip().startswith('lambda:'):
            lambda_str = output.split(':', 1)[1]
            lambda_f = lambda name,metadata,args,ret:eval(lambda_str)
            ctx = lambda_f,filter_f
            syscall_obj.add(syscall, syscall_print_lambda, ctx)
        else:
            ctx = output,filter_f
            syscall_obj.add(syscall, syscall_print_fmt, ctx)
        tracepoint.start(obj_dir=tmpdirname)

default_event_fmt="lambda:f'{name}: ' + ','.join([f'{k}={v}' for k,v in args.items()])"
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

@click.command()
@click.option('--output', '-o', type=str, default=default_event_fmt,help="Format string")
@click.option('--filter', '-F', type=str, help="Filter string")
@click.option('--pid', '-p', type=int, multiple=True, help='Pid filter')
@click.option('--uid', '-u', type=int, multiple=True, help='Uid filter')
@click.argument('event')
def event_trace(output, filter, pid, uid, event):
    """Trace event"""
    with tempfile.TemporaryDirectory() as tmpdirname:
        tracepoint = TracePoint(pid_filter=pid, uid_filter=uid)
        event_obj = Event(tracepoint)
        if filter:
            filter_f = lambda name,metadata,args:eval(filter)
        else:
            filter_f = None
        if output.strip().startswith('lambda:'):
            lambda_str = output.split(':', 1)[1]
            lambda_f = lambda name,metadata,args:eval(lambda_str)
            ctx = lambda_f,filter_f
            event_obj.add(event, event_print_lambda, ctx)
        else:
            ctx = output,filter_f
            event_obj.add(event, event_print_fmt, ctx)
        tracepoint.start(obj_dir=tmpdirname)


def uprobe_print_fmt(name, metadata, function, args, ctx):
    fmt,filter_f = ctx
    if filter_f:
        filter_ret = filter_f(name, metadata, function, args)
        if not filter_ret:
            return
    print(fmt.format(name=name, metadata=metadata, function=function, args=args))

def uprobe_print_lambda(name, metadata, function, args, ctx):
    lambda_f,filter_f = ctx
    if filter_f:
        filter_ret = filter_f(name, metadata, function, args)
        if not filter_ret:
            return
    print(lambda_f(name, metadata, function, args))

default_uprobe_fmt="lambda:f'{function}: ' + ','.join([f'{k}={v}' for k,v in args.items()])"
@click.command()
@click.option('--output', '-o', type=str, default=default_uprobe_fmt, help="Output format")
@click.option('--filter', '-f', type=str, help="Filter string")
@click.option('--pid', '-p', type=int, multiple=True, help='Pid filter')
@click.option('--uid', '-u', type=int, multiple=True, help='Uid filter')
@click.argument('probe')
def uprobe_trace(output, filter, pid, uid, probe):
    """Trace uprobe"""
    with tempfile.TemporaryDirectory() as tmpdirname:
        uprobe = Uprobe(pid_filter=pid, uid_filter=uid)
        if filter:
            filter_f = lambda name,metadata,function,args:eval(filter)
        else:
            filter_f = None
        if output.strip().startswith('lambda:'):
            lambda_str = output.split(':', 1)[1]
            lambda_f = lambda name,metadata,function,args:eval(lambda_str)
            ctx = lambda_f,filter_f
            uprobe.add(probe, uprobe_print_lambda, ctx)
        else:
            ctx = output,filter_f
            uprobe.add(probe, uprobe_print_fmt, ctx)
        uprobe.start(obj_dir=tmpdirname)

