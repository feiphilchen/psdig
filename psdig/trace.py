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
@click.option('--syscall', '-s', type=(str, str), multiple=True, help="<syscall> <fmt>")
def syscall_trace(syscall):
    """Trace syscall with required format"""
    tracepoint = TracePoint()
    syscall_obj = Syscall(tracepoint)
    for s in syscall:
        name,fmt = s
        syscall_obj.add(name, syscall_print, fmt)
    tracepoint.start()

@click.group()
def cli():
    """Trace different events"""
    pass
    
cli.add_command(syscall_trace, 'syscall')
if __name__ == '__main__':
    cli()
