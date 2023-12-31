import os
import re
import pytest
import logging
import time
import subprocess
from trace_collect import TraceCollect

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
trace_syscall_cmd = "psdig trace syscall"
cases = [
    (
        "syscall/test_syscall openat", 
        "sys_openat", 
        "metadata['comm'] == 'test_syscall' and args['filename'] == '/tmp/test_file.txt'" + \
          "and syscall == 'sys_openat' and args['flags'] == 1025 and ret == -2", 
        1, 
        None
    ),
    (
        "syscall/test_syscall exit",
        "sys_exit_group",
        "metadata['comm'] == 'test_syscall' " + \
          "and syscall == 'sys_exit_group' and args['error_code'] == 5",
        1,
        None
    ),
    (
        "syscall/test_syscall fork",
        "sys_clone",
        "metadata['comm'] == 'test_syscall' " + \
          "and syscall == 'sys_clone' and ret > 0",
        1,
        None
    ),
    (
        "syscall/test_syscall exit",
        "sys_execve",
        "syscall == 'sys_execve' and args['filename'] == 'syscall/test_syscall' and ' '.join(args['argv']) == 'syscall/test_syscall exit'",
        1,
        None
    ),
    (
        "syscall/test_syscall tcp-bind",
        "sys_bind",
        "syscall == 'sys_bind' and args['umyaddr']=='{family=2,addr=0.0.0.0,port=55000}'",
        1,
        None
    ),
    (
        "syscall/test_syscall tcp-bind-v6",
        "sys_bind",
        "syscall == 'sys_bind' and args['umyaddr']=='{family=10,addr=::,port=55000}'",
        1,
        None
    ),
    (
        "syscall/test_syscall unix-bind",
        "sys_bind",
        "syscall == 'sys_bind' and args['umyaddr']=='{family=1,path=/tmp/test.sock}'",
        1,
        None
    ),
    (
       "syscall/test_syscall openat", 
       "sys_openatxx", 
       None, 
       0, 
       "no syscall to trace"
    )
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
    time.sleep(2)
    logger.info(f'# {test_cmd}')
    subprocess.run(test_cmd, shell=True)
    time.sleep(2)
    logger.info('stop tracing')
    traces,error = tc.stop()
    logger.info('done')
    if error != None:
        logger.info("error:\n" + error)
    logger.info("%u traces:\n %s" % (len(traces), " ".join(traces)))
    assert expect_trace_nr == len(traces)
    if expect_error != None:
        hit = re.search(expect_error, error)
        assert hit != None

