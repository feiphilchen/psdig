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
import tempfile

def syscall_print_fmt(name, metadata, args, ret, ctx):
    fmt = ctx
    print(fmt.format(name=name, metadata=metadata, args=args, ret=ret))

def syscall_print_lambda(name, metadata, args, ret, ctx):
    lambda_f = ctx
    print(lambda_f(name, metadata, args, ret))

@click.command()
@click.option('--fmt', '-f', type=(str, str), multiple=True, help="<syscall> <fmt>")
@click.option('--lambda', '-l', 'lambda_', type=(str, str), multiple=True, help="<syscall> <lambda>")
@click.option('--pid', '-p', type=int, multiple=True, help='Pid filter')
@click.option('--uid', '-u', type=int, multiple=True, help='Uid filter')
def syscall_trace(fmt, lambda_, pid, uid):
    """Trace syscall"""
    with tempfile.TemporaryDirectory() as tmpdirname:
        tracepoint = TracePoint(pid_filter=pid, uid_filter=uid)
        syscall_obj = Syscall(tracepoint)
        for f in fmt:
            name,format_str = f
            syscall_obj.add(name, syscall_print_fmt, format_str)
        for l in lambda_:
            name,lambda_str = l
            lambda_f = lambda name,metadata,args,ret:eval(lambda_str)
            syscall_obj.add(name, syscall_print_lambda, lambda_f)
        tracepoint.start(obj_dir=tmpdirname)

def event_print_fmt(name, metadata, args, ctx):
    fmt = ctx
    print(fmt.format(name=name, metadata=metadata, args=args))

def event_print_lambda(name, metadata, args, ctx):
    lambda_f = ctx
    print(lambda_f(name, metadata, args))

@click.command()
@click.option('--fmt', '-f', type=(str, str), multiple=True, help="<event> <fmt>")
@click.option('--lambda', '-l', 'lambda_', type=(str, str), multiple=True, help="<event> <lambda>")
@click.option('--pid', '-p', type=int, multiple=True, help='Pid filter')
@click.option('--uid', '-u', type=int, multiple=True, help='Uid filter')
def event_trace(fmt, lambda_, pid, uid):
    """Trace event"""
    with tempfile.TemporaryDirectory() as tmpdirname:
        tracepoint = TracePoint(pid_filter=pid, uid_filter=uid)
        event_obj = Event(tracepoint)
        for f in fmt:
            name,format_str = f
            event_obj.add(name, event_print_fmt, format_str)
        for l in lambda_:
            name,lambda_str = l
            lambda_f = lambda name,metadata,args:eval(lambda_str)
            event_obj.add(name, event_print_lambda, lambda_f)
        tracepoint.start(obj_dir=tmpdirname)


def uprobe_print_fmt(name, metadata, function, args, ctx):
    fmt = ctx
    print(fmt.format(name=name, metadata=metadata, function=function, args=args))

def uprobe_print_lambda(name, metadata, function, args, ctx):
    lambda_f = ctx
    print(lambda_f(name, metadata, function, args))

@click.command()
@click.option('--fmt', '-f', type=(str, str), multiple=True, help="<uprobe> <fmt>")
@click.option('--lambda', '-l', 'lambda_', type=(str, str), multiple=True, help="<uprobe> <lambda>")
@click.option('--pid', '-p', type=int, multiple=True, help='Pid filter')
@click.option('--uid', '-u', type=int, multiple=True, help='Uid filter')
def uprobe_trace(fmt, lambda_, pid, uid):
    """Trace uprobe"""
    with tempfile.TemporaryDirectory() as tmpdirname:
        uprobe = Uprobe(pid_filter=pid, uid_filter=uid)
        for f in fmt:
            p,format_str = f
            uprobe.add(p, uprobe_print_fmt, format_str)
        for l in lambda_:
            p,lambda_str = l
            lambda_f = lambda name,metadata,function,args:eval(lambda_str)
            uprobe.add(p, uprobe_print_lambda, lambda_f)
        uprobe.start(obj_dir=tmpdirname)


