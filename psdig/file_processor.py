import os
import logging
import time
from .data_type import SockAddr
from .conf import LOGGER_NAME,FD_CACHE

class FdResolve(object):
    def __init__(self):
        self.logger = logging.getLogger(LOGGER_NAME)
        self.fd_hash = {}

    def fd_key(self, pid, fd):
        return f"{pid}:{fd}"

    def cleanup(self, limited):
        sorted_hash = sorted(self.fd_hash, key=lambda x: x[1]['update'])
        for pos in range(0, limited):
            key = sorted_hash[0]
            del self.fd_hash[key]

    def fd_add(self, pid, fd, obj):
        key = self.fd_key(pid, fd)
        time_now = time.time()
        self.fd_hash[key] = {"obj":obj, "update":time_now}
        if len(self.fd_hash) > FD_CACHE:
            self.cleanup(int(FD_CACHE/2))

    def fd_delete(self, pid, fd):
        key = self.fd_key(pid, fd)
        if key in self.fd_hash:
            del self.fd_hash[key]

    def proc_fd(self, pid, fd):
        fd_path = f'/proc/{pid}/fd/{fd}'
        try:
            path = os.readlink(fd_path)
        except:
            return None
        else:
            return path

    def fd_lookup(self, pid, fd):
        key = self.fd_key(pid, fd)
        if key in self.fd_hash:
            self.fd_hash[key]['update'] = time.time()
            return self.fd_hash[key]['obj']
        proc_path = f'/proc/{pid}/fd/{fd}'
        fd_path = os.readlink(proc_path)
        if os.path.exists(fd_path):
            self.fd_add(pid, fd, fd_path)
            return fd_path

    def syscall(self, metadata, syscall, args, ret):
        pid = metadata['pid']
        if syscall in ['sys_open', 'sys_openat']:
            if 'filename' in args and ret >= 0:
                self.fd_add(pid, ret, args['filename'])
        elif syscall in ['sys_close', 'sys_read', 'sys_write', 'sys_sendmsg', 'sys_sendmmsg', 'sys_recvmsg', 'sys_recvmmsg']:
            if 'fd' in args:
                try:
                    result = self.fd_lookup(pid, args['fd'])
                except:
                    return
                if result == None:
                    return
                if isinstance(result, str):
                    args['@file'] = result
                elif isinstance(result, SockAddr):
                    args['@peer_sock'] = result
                if syscall == 'sys_close':
                    self.fd_delete(pid, args['fd'])
        elif syscall in ['sys_connect']:
            if 'uservaddr' in args and ret >= 0 and isinstance(args['uservaddr'], SockAddr):
                self.fd_add(pid, args['fd'], args['uservaddr'])
        elif syscall in ['sys_accept', 'sys_accept4']:
            if 'upeer_sockaddr' in args and ret >= 0 and isinstance(args['upeer_sockaddr'], SockAddr):
                self.fd_add(pid, ret, args['upeer_sockaddr'])

