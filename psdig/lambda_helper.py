# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com
import socket
from datetime import datetime
from .data_type import *

def inet_ntoa(addr):
    if isinstance(addr, Bytes):
        return socket.inet_ntoa(addr.value)
    else:
        return socket.inet_ntoa(addr)

def time_str(timestamp):
    dt = datetime.fromtimestamp(timestamp)
    dt_str = dt.strftime('%H:%M:%S.%f')
    return dt_str

def syscall_format(syscall, args=None, ret=None, metadata=None, argmaxlen=64):
    if args == None:
        arg_str = "()"
    else:
        arg_str_list = []
        for k,v in args.items():
            if isinstance(v, str):
                val = v.encode("unicode_escape").decode("utf-8")
                val = (val[:argmaxlen] + '..') if len(val) > argmaxlen else val
                val = f"{k}=\"{val}\""
                arg_str_list.append(val)
            elif isinstance(v, list):
                val = str(v)
                val = val.encode("unicode_escape").decode("utf-8")
                val = (val[:argmaxlen] + '..') if len(val) > argmaxlen else val
                if val[-1] != ']':
                    val += ']'
                val = f"{k}={val}"
                arg_str_list.append(val)
            else:
                val = str(v)
                val = f"{k}={val}"
                arg_str_list.append(val)
        arg_str = "(" + ", ".join(arg_str_list) + ")"
    if ret != None:
        return f"{syscall}{arg_str} => {ret}"
    else:
        return f"{syscall}{arg_str}"

def l_pad_string(s, width):
    lines = s.splitlines()
    return "\n".join(
        f"%s{line}" % str(" " * width)
        for line in lines
    )

def uprobe_format(function, args=None, ret=None, metadata=None, argmaxlen=64):
    name = function['name']
    enter = metadata['enter']
    if args == None:
        arg_str = "()"
    else:
        arg_str_list = []
        for k,v in args.items():
            if isinstance(v, str):
                val = v.encode("unicode_escape").decode("utf-8")
                val = (val[:argmaxlen] + '..') if len(val) > argmaxlen else val
                val = f"{k}=\"{val}\""
                arg_str_list.append(val)
            elif isinstance(v, list):
                val = str(v)
                val = val.encode("unicode_escape").decode("utf-8")
                val = (val[:argmaxlen] + '..') if len(val) > argmaxlen else val
                if val[-1] != ']':
                    val += ']'
                val = f"{k}={val}"
                arg_str_list.append(val)
            else:
                val = str(v)
                val = f"{k}={val}"
                arg_str_list.append(val)
        arg_str = "(" + ", ".join(arg_str_list) + ")"
    if 'ustack' in metadata:
        ustack_str = "\n  backtrace:\n%s" % l_pad_string(str(metadata['ustack']), 4)
    else:
        ustack_str = ""
    if not enter:
        ret = 'void' if ret == None else ret
        return f"{name}{arg_str} => {ret}{ustack_str}"
    else:
        return f"{name}{arg_str}{ustack_str}"

def context_str(args):
    filename = args.get('@file')
    remote = args.get('@peer_sock')
    if filename != None:
        prefix = f" <file={filename}>"
    elif remote != None:
        prefix = f" <peer_sock={remote}>"
    else:
        prefix = ""
    return prefix
