from trace_collect import TraceCollect
import os
import pytest
import logging
import time
import subprocess

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
trace_syscall_cmd = "psdig trace syscall"
cases = [
    ("./app/test_syscall openat", "openat", "metadata['comm'] == 'test_syscall' and args['filename'] == '/tmp/test_file.txt'", 1, None)
]

@pytest.mark.parametrize("test_cmd,syscall,filter_str,expect_trace_nr,expect_error", cases)
def test_syscall(test_cmd, syscall, filter_str, expect_trace_nr, expect_error):
    cmd_list = ["psdig", "trace", "syscall", syscall]
    if filter_str != None:
        cmd_list.append('-f')
        cmd_list.append(filter_str)
    trace_cmd = ' '.join(cmd_list)
    logger.info(f'# {trace_cmd}')
    tc = TraceCollect()
    tc.start(cmd_list)
    time.sleep(5)
    logger.info(f'# {test_cmd}')
    subprocess.run(test_cmd, shell=True)
    time.sleep(10)
    traces,error = tc.stop()
    logger.info("%u traces:\n %s" % (len(traces), " ".join(traces)))
    assert expect_trace_nr == len(traces)

