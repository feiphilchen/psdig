import os
import logging
import time
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

    def file_add(self, pid, fd, filename):
        key = self.fd_key(pid, fd)
        time_now = time.time()
        self.fd_hash[key] = {"filename":filename, "update":time_now}
        if len(self.fd_hash) > FD_CACHE:
            self.cleanup(int(FD_CACHE/2))

    def file_delete(self, pid, fd):
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

    def file_lookup(self, pid, fd):
        key = self.fd_key(pid, fd)
        if key not in self.fd_hash:
            return None
        self.fd_hash[key]['update'] = time.time()
        return self.fd_hash[key]['filename']

    def syscall(self, metadata, syscall, args, ret):
        pid = metadata['pid']
        if syscall in ['sys_open', 'sys_openat']:
            if 'filename' in args and ret >= 0:
                self.file_add(pid, ret, args['filename'])
        elif syscall in ['sys_close']:
            if 'fd' in args:
                filename = self.file_lookup(pid, args['fd'])
                if filename != None:
                    args['filename'] = filename
                    self.file_delete(pid, args['fd'])

