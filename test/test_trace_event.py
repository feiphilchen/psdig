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
output_fmt="' %s(%s): '%(metadata.get('comm'), metadata.get('pid')) + f' {event}: ' + ','.join([f'{k}={v}' for k,v in args.items()])"
cases = [
    (
        "python3 event/tcp_send_reset.py", 
        'psdig trace event', 
        ["tcp/tcp_send_reset"],
        None,
        output_fmt,
        [
          '[^(]+\\([0-9]+\\):\\s+tcp/tcp_send_reset:\\s+.*dport=51810(,family=2)?,saddr=7f000001,daddr=7f000001'
        ],
        None
    ),
    (
        "python3 event/tcp_receive_reset.py",
        'psdig trace event',
        ["tcp/tcp_receive_reset"],
        None,
        output_fmt,
        [
          '[^(]+\\([0-9]+\\):\\s+tcp/tcp_receive_reset:\\s+.*dport=51810(,family=2)?,saddr=7f000001,daddr=7f000001'
        ],
        None
    ),
    (
        "python3 event/tcp_receive_reset.py",
        'psdig trace event',
        ["tcp/tcp_receive_reset1"],
        None,
        output_fmt,
        None,
        "no event to trace"
    )
]
@pytest.mark.parametrize("test_cmd,probe_cmd,events,filter_str,output_fmt,expect_traces,expect_error", cases)
def test_event(test_cmd, probe_cmd, events, filter_str, output_fmt, expect_traces, expect_error):
    cmd_list = probe_cmd.split()
    cmd_list += events
    if filter_str != None:
        cmd_list.append('-f')
        cmd_list.append(filter_str)
    if output_fmt != None:
        cmd_list.append('-o')
        cmd_list.append(output_fmt)
    trace_cmd = ' '.join(cmd_list)
    logger.info(f'# {trace_cmd}')
    tc = TraceCollect()
    tc.start(cmd_list)
    time.sleep(3)
    logger.info(f'# {test_cmd}')
    subprocess.run(test_cmd, shell=True)
    time.sleep(3)
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

