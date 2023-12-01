import socket
from datetime import datetime

def inet_ntoa(addr_str):
    addr = bytes.fromhex(addr_str)
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
                val = f"{k}={v}"
                arg_str_list.append(val)
        arg_str = "(" + ", ".join(arg_str_list) + ")"
    if ret != None:
        return f"{syscall}{arg_str} => {ret}"
    else:
        return f"{syscall}{arg_str}"

def uprobe_format(function, args=None, ret=None, metadata=None, argmaxlen=64, brief=False):
    name = function['name']
    elf = function['elf']
    addr = function['addr']
    comm = metadata['comm']
    pid = metadata['pid']
    ts = time_str(metadata['timestamp'])
    if args == None:
        arg_str = "()"
    else:
        arg_str_list = []
        for k,v in args.items():
            is_str = metadata['uprobe'].function_arg_is_str(elf, addr, k)
            if isinstance(v, str) and is_str:
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
                val = f"{k}={v}"
                arg_str_list.append(val)
        arg_str = "(" + ", ".join(arg_str_list) + ")"
    prefix = ""
    if not brief:
        prefix = f"{ts} {comm}({pid}): "
    if ret != None:
        return f"{prefix}{name}{arg_str} => {ret}"
    else:
        return f"{prefix}{name}{arg_str}"

