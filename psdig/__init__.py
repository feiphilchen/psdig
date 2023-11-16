import shutil
from .process_watch import PsWatch
from .trace import syscall_trace,event_trace,uprobe_trace
from .trace_manager import TraceManager
from .conf import BPF_OBJ_DIR

def compile_event_objs():
    shutil.rmtree(BPF_OBJ_DIR, ignore_errors=True)
    mgr = TraceManager()
    mgr.compile()

