#!/usr/bin/python3
# vim: set filetype=python
import os
import sys
import re
import click
from .syscall import Syscall
from .tracepoint import TracePoint

def syscall_print(name, metadata, args, ret, ctx):
    fmt = ctx
    print(fmt.format(name=name, metadata=metadata, args=args, ret=ret))

@click.command()
@click.option('--fmt', '-f', type=(str, str), multiple=True, help="<syscall> <fmt>")
def syscall_trace(fmt):
    """Trace syscall with required format or lambda function"""
    tracepoint = TracePoint()
    syscall_obj = Syscall(tracepoint)
    for f in fmt:
        name,format_str = f
        syscall_obj.add(name, syscall_print, format_str)
    tracepoint.start()

