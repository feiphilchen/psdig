# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com
import shutil
from .trace_manager import TraceManager
from .conf import BPF_OBJ_DIR
from .trace_conf import TraceConfFile

def compile_event_objs():
    shutil.rmtree(BPF_OBJ_DIR, ignore_errors=True)
    default_conf = TraceConfFile()
    default_conf.load()
    mgr = TraceManager(conf=default_conf)
    mgr.compile()

