import os
import re
import pytest
import logging
import time
import subprocess
from trace_collect import TraceCollect
import shlex

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
cases = [
    (
        'uprobe_c/test_uprobe', 
        'psdig watch -t watch/trace_ok.json --headless', 
        [
            '[^\\s]+\\s+>>\\s+uprobe\\s+\\[INFO\\]:\\s+\\(test_uprobe pid=[0-9]+ uid=0\\)\\s+>>\\s+uprobed_add1\\(ptr=0x[0-9a-z]+, iu=3, str="ssss"\\)'
        ],
        None
    ),
    (
        'python3 event/tcp_send_reset.py',
        'psdig watch -t watch/trace_ok.json --headless',
        [
            '[^\\s]+\\s+>>\\s+bind\\s+\\[INFO\\]:\\s+\\(python3 pid=[0-9]+ uid=0\\)\\s+>>\\s+fd=[0-9]+ umyaddr=\\{family=2,addr=127.0.0.1,port=51810\\} addrlen=16 ret=0',
            '[^\\s]+\\s+>>\\s+tcp-rst\\s+\\[WARNING\\]:\\s+\\(python3 pid=[0-9]+ uid=0\\)\\s+>>\\s+saddr=127.0.0.1 sport=51810 daddr=127.0.0.1 dport=[0-9]+'
        ],
        None
    ),
    (
        'uprobe_c/test_uprobe',
        'psdig watch -t watch/trace_ok_default.json --headless',
        [
            '[^\\s]+\\s+>>\\s+uprobe\\s+\\[INFO\\]:\\s+\\(test_uprobe pid=[0-9]+ uid=0\\)\\s+>>\\s+uprobed_add1\\(ptr=0x[0-9a-z]+, iu=3, str="ssss"\\)'
        ],
        None
    ),
    (
        'python3 event/tcp_send_reset.py',
        'psdig watch -t watch/trace_ok_default.json --headless',
        [
            '[^\\s]+\\s+>>\\s+bind\\s+\\[INFO\\]:\\s+\\(python3 pid=[0-9]+ uid=0\\)\\s+>>\\s+fd=[0-9]+ umyaddr=\\{family=2,addr=127.0.0.1,port=51810\\} addrlen=16 ret=0',
            '[^\\s]+\\s+>>\\s+tcp-rst\\s+\\[INFO\\]:\\s+\\(python3 pid=[0-9]+ uid=0\\)\\s+>>\\s+'
        ],
        None
    ),
    (
        'uprobe_c/test_uprobe',
        'psdig watch -t watch/trace_ok_filter.json --headless',
        [
            '[^\\s]+\\s+>>\\s+uprobe\\s+\\[INFO\\]:\\s+\\(test_uprobe pid=[0-9]+ uid=0\\)\\s+>>\\s+uprobed_add1\\(ptr=0x[0-9a-z]+, iu=3, str="ssss"\\)'
        ],
        None
    ),
    (
        'python3 event/tcp_send_reset.py',
        'psdig watch -t watch/trace_ok_filter.json --headless',
        [
            '[^\\s]+\\s+>>\\s+bind\\s+\\[INFO\\]:\\s+\\(python3 pid=[0-9]+ uid=0\\)\\s+>>\\s+fd=[0-9]+ umyaddr=\\{family=2,addr=127.0.0.1,port=51810\\} addrlen=16 ret=0',
            '[^\\s]+\\s+>>\\s+tcp-rst\\s+\\[WARNING\\]:\\s+\\(python3 pid=[0-9]+ uid=0\\)\\s+>>\\s+saddr=127.0.0.1 sport=51810 daddr=127.0.0.1 dport=[0-9]+'
        ],
        None
    ),
    (
        'uprobe_c/test_uprobe',
        'psdig watch -t watch/trace_ok_filter_out.json --headless',
        [
        ],
        None
    ),
    (
        'python3 event/tcp_send_reset.py',
        'psdig watch -t watch/trace_ok_filter_out.json --headless',
        [
        ],
        None
    )
]

@pytest.mark.parametrize("test_cmd,watch_cmd,expect_traces,expect_error", cases)
def test_watch(test_cmd, watch_cmd, expect_traces, expect_error):
    cmd_list = watch_cmd.split()
    trace_cmd = ' '.join(cmd_list)
    logger.info(f'# {trace_cmd}')
    tc = TraceCollect()
    tc.start(cmd_list)
    time.sleep(5)
    logger.info(f'# {test_cmd}')
    subprocess.run(test_cmd, shell=True)
    time.sleep(2)
    logger.info('stop tracing')
    traces,error = tc.stop()
    logger.info('done')
    if error != None:
        logger.info("error:\n" + error)
    logger.info("%u traces:\n %s" % (len(traces), " ".join(traces)))
    if expect_traces != None:
        assert len(expect_traces) == len(expect_traces)
        trace_num = len(expect_traces)
        for pos in range(0, trace_num):
            logger.info('matching: <%s>' % expect_traces[pos])
            hit = re.match(expect_traces[pos], traces[pos].strip())
            assert hit != None
    if expect_error != None:
        hit = re.search(expect_error, error)
        assert hit != None

