import shutil
from .process_watch import PsWatch
from .trace import syscall_trace
from .event_manager import EventManager
from .conf import BPF_OBJ_DIR

def compile_event_objs():
    shutil.rmtree(BPF_OBJ_DIR, ignore_errors=True)
    mgr = EventManager()
    mgr.compile()

