import os
import sys

class SockAddr(object):
    def __init__(self, sa):
        if sa['family'] == 2 or sa['family'] == 10:
            self.init_sockaddr_in(sa)
        elif sa['family'] == 1:
            self.init_sockaddr_un(sa)
        elif sa['family'] == 16:
            self.init_sockaddr_nl(sa)

    def init_sockaddr_in(self, sa):
        self.family = sa['family']
        self.addr = sa['addr']
        self.port = sa['port']

    def init_sockaddr_un(self, sa):
        self.family = sa['family']
        self.path = sa['path']

    def init_sockaddr_nl(self, sa):
        self.family = sa['family']
        self.nl_pid = sa['nl_pid']
        self.nl_groups = sa['nl_groups']

    def __str__(self):
        if self.family == 2:
            return "{family=2,addr=%s,port=%u}" % (self.addr, self.port)
        elif self.family == 10:
            return "{family=10,addr=%s,port=%u}" % (self.addr, self.port)
        elif self.family == 1:
            return "{family=1,path=%s}" % self.path
        elif self.family == 16:
            return "{family=16,nl_pid=%u,nl_groups=%u}" % (self.nl_pid, self.nl_groups)

    def __eq__(self, other):
        if self.family == 2:
            addr = "{family=2,addr=%s,port=%u}" % (self.addr, self.port)
            return addr == other
        elif self.family == 10:
            addr = "{family=10,addr=%s,port=%u}" % (self.addr, self.port)
            return addr == other
        elif self.family == 1:
            addr = "{family=1,path=%s}" % self.path
            return addr == other
        elif self.family == 16:
            addr = "{family=16,nl_pid=%u,nl_groups=%u}" % (self.nl_pid, self.nl_groups)
            return addr == other
        else:
            return False

class Pointer(object):
    def __init__(self, ptr):
        self.ptr = ptr

    def __str__(self):
        value = bytes.fromhex(self.ptr)
        if int.from_bytes(value, sys.byteorder) == 0:
            return "NULL"
        else:
            return f"0x{self.ptr}"
    @property
    def value(self):
        value = bytes.fromhex(self.ptr)
        return int.from_bytes(value, sys.byteorder)

    def __eq__(self, other):
        value = bytes.fromhex(self.ptr)
        return int.from_bytes(value, sys.byteorder) == other

    def __le__(self, other):
        value = bytes.fromhex(self.ptr)
        return int.from_bytes(value, sys.byteorder) <= other

    def __ge__(self, other):
        value = bytes.fromhex(self.ptr)
        return int.from_bytes(value, sys.byteorder) >= other

    def __lt__(self, other):
        value = bytes.fromhex(self.ptr)
        return int.from_bytes(value, sys.byteorder) < other

    def __gt__(self, other):
        value = bytes.fromhex(self.ptr)
        return int.from_bytes(value, sys.byteorder) > other

class Bytes(object):
    def __init__(self, bs):
        self.bs = bs

    def __str__(self):
        return self.bs

    @property
    def value(self):
        return bytes.fromhex(self.bs)

    def __eq__(self, other):
        if isinstance(other, str):
            return self.bs == other
        elif isinstance(other, bytes):
            return bytes.fromhex(self.bs) == other
        else:
            return False
