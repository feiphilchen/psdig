import shutil
from .process_watch import PsWatch
from .trace import syscall_trace,event_trace,uprobe_trace
from .trace_manager import TraceManager
from .conf import BPF_OBJ_DIR
from .trace_conf import TraceConfFile

def compile_event_objs():
    shutil.rmtree(BPF_OBJ_DIR, ignore_errors=True)
    default_conf = TraceConfFile()
    default_conf.load()
    mgr = TraceManager(conf=default_conf)
    mgr.compile()

