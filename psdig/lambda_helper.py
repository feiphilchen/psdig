import socket

def inet_ntoa(addr_str):
    addr = bytes.fromhex(addr_str)
    return socket.inet_ntoa(addr)

def function_format(name, args=None, ret=None, argmaxlen=64):
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
        return f"{name}{arg_str} => {ret}"
    else:
        return f"{name}{arg_str}"

def uprobe_format(function, args=None, ret=None, metadata=None, argmaxlen=64):
    name = function['name']
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
        return f"{name}{arg_str} => {ret}"
    else:
        return f"{name}{arg_str}"

