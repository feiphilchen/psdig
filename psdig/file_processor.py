import os
import logging
from .conf import LOGGER_NAME

class FileResolve(object):
    def __init__(self):
        self.logger = logging.getLogger(LOGGER_NAME)
        self.fd_hash = {}

    def file_add(self, pid, fd, filename):
        if pid not in self.fd_hash:
            self.fd_hash[pid] = {}
        self.fd_hash[pid][fd] = filename

    def file_lookup(self, pid, fd):
        if pid not in self.fd_hash:
            return None
        if fd not in self.fd_hash[pid]:
            return None
        return self.fd_hash[pid][fd]

    def syscall(self, metadata, name, args, ret):
        pid = metadata['pid']
        if name in ['open', 'openat']:
            if 'filename' in args and ret >= 0:
                self.file_add(pid, ret, args['filename'])
        elif name in ['close']:
            if 'fd' in args:
                filename = self.file_lookup(pid, args['fd'])
                if filename != None:
                    args['filename'] = filename
