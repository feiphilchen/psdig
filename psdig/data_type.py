import os
import sys

class SockAddr(object):
    def __init__(self, sa):
        if sa['family'] == 2 or sa['family'] == 10:
            self.init_sockaddr_in(sa)
        elif sa['family'] == 1:
            self.init_sockaddr_un(sa)

    def init_sockaddr_in(self, sa):
        self.family = sa['family']
        self.addr = sa['addr']
        self.port = sa['port']

    def init_sockaddr_un(self, sa):
        self.family = sa['family']
        self.path = sa['path']

    def __str__(self):
        if self.family == 2:
            return f"{self.addr}:{self.port}"
        elif self.family == 10:
            return f"[{self.addr}]:{self.port}"
        elif self.family == 1:
            return f"{self.path}"

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


class Bytes(object):
    def __init__(self, bs):
        self.bs = bs

    def __str__(self):
        return self.bs

    @property
    def value(self):
        return bytes.fromhex(self.bs)


