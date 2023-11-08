#!/usr/bin/python3
# vim: set filetype=python
import os
import sys
import re
import click
from .syscall import Syscall
from .tracepoint import TracePoint
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
    """Trace syscall with required format or lambda function"""
    with tempfile.TemporaryDirectory() as tmpdirname:
        tracepoint = TracePoint(obj_dir=tmpdirname, pid_filter=pid, uid_filter=uid)
        syscall_obj = Syscall(tracepoint)
        for f in fmt:
            name,format_str = f
            syscall_obj.add(name, syscall_print_fmt, format_str)
        for l in lambda_:
            name,lambda_str = l
            lambda_f = lambda name,metadata,args,ret:eval(lambda_str)
            syscall_obj.add(name, syscall_print_lambda, lambda_f)
        tracepoint.start()

