from .process_watch import PsWatch

import pkgutil

def test_pkg_data():
    data = pkgutil.get_data(__package__, 'trace_event/event.h')
    print(data)
