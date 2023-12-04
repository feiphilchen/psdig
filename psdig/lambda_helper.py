import socket
from datetime import datetime

def inet_ntoa(addr):
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
    if not enter:
        ret = 'void' if ret == None else ret
        return f"{name}{arg_str} => {ret}"
    else:
        return f"{name}{arg_str}"

