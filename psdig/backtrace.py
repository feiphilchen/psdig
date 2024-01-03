# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com
import os
import sys
import psutil
from .dwarf import Dwarf

class Stack(object):
    def __init__(self, stack, frames):
        self.stack = stack
        self.frames = frames

    def __str__(self):
        return "\n".join(reversed(self.frames))

    def __format__(self, spec):
        return self.__str__()

class Backtrace(object):
    def __init__(self):
        self.dwarfs = {}

    def get_dwarf(self, path):
        if path in self.dwarfs:
            return self.dwarfs[path]
        dwarf = Dwarf(path)
        self.dwarfs[path] = dwarf
        return dwarf
        
    def resolve_ustack(self, pid, stack):
        resolved = []
        start_hash = {}
        try:
            p = psutil.Process(pid)
            maps = p.memory_maps(grouped=False)
            for addr in stack:
                frame_added = False
                for m in maps:
                    start_addr = int(m.addr.split('-')[0], 16)
                    end_addr = int(m.addr.split('-')[1], 16)
                    if m.path not in start_hash:
                        start_hash[m.path] = start_addr
                    if 'x' not in m.perms:
                        continue
                    if addr >= start_addr and addr < end_addr:
                        dwarf = self.get_dwarf(m.path)
                        offset = addr - start_hash[m.path]
                        file,lineno = dwarf.addr2line(offset)
                        if file != None:
                            frame = f"[0x%x] {file}:{lineno} (%s+0x%x)" % (addr, m.path, offset)
                        else:
                            frame = "[0x%x] ?:? (%s+0x%x)" % (addr, m.path, offset)
                        resolved.append(frame)
                        frame_added = True
                        break
                if not frame_added:
                    frame = "[0x%x] ?:?" % addr
                    resolved.append(frame)
        except:
            resolved = ["[0x%x] ?:?" % addr for addr in stack]
            return Stack(stack, resolved)
        return Stack(stack, resolved)

