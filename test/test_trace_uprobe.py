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
uprobe_c="uprobe_c/test_uprobe"
uprobe_cpp="uprobe_cpp/test_uprobe"
output_fmt="lambda:'%s: ' % metadata.get('comm') + uprobe_format(function, args, ret, metadata)"
libc_path=os.popen("ldd %s | grep libc.so | awk '{print $3}'" % uprobe_c).read().strip()
print(f"##{libc_path}##")
cases = [
    (
        uprobe_c, 
        f'psdig trace uprobe {uprobe_c}', 
        ["uprobed_add1", "uprobed_add2",  "uprobed_add3", "uprobed_add4", "uprobed_add5","uprobed_add6"],
        None,
        output_fmt,
        [
            'test_uprobe: uprobed_add1\\(ptr=0x[0-9a-z]+, iu=3, str="ssss"\\)',
            'test_uprobe: uprobed_add1\\(\\) => 0x[0-9a-z]+',
            'test_uprobe: uprobed_add2\\(x=4, et=1\\)',
            'test_uprobe: uprobed_add2\\(\\) => 5',
            'test_uprobe: uprobed_add3\\(x=5, et=0\\)',
            'test_uprobe: uprobed_add3\\(\\) => void',
            'test_uprobe: uprobed_add4\\(ptr=0x[0-9a-z]+, iu=3, str="ssss"\\)',
            'test_uprobe: uprobed_add4\\(\\) => 0x[0-9a-z]+',
            #'test_uprobe: uprobed_add5\\(obj=0x[0-9a-z]+\\)',
            #'test_uprobe: uprobed_add5\\(\\) => void',
            'test_uprobe: uprobed_add6\\(ptr=0x[0-9a-z]+, iu=-1, str="yy"\\)',
            'test_uprobe: uprobed_add6\\(\\) => 0x[0-9a-z]+'

        ],
        None
    ),
    (
        uprobe_c,
        f'psdig trace uprobe {uprobe_c} -s {uprobe_c}',
        ["uprobed_add1", "uprobed_add2",  "uprobed_add3", "uprobed_add4", "uprobed_add5","uprobed_add6"],
        None,
        output_fmt,
        [
            'test_uprobe: uprobed_add1\\(ptr=0x[0-9a-z]+, iu=3, str="ssss"\\)',
            'test_uprobe: uprobed_add1\\(\\) => 0x[0-9a-z]+',
            'test_uprobe: uprobed_add2\\(x=4, et=1\\)',
            'test_uprobe: uprobed_add2\\(\\) => 5',
            'test_uprobe: uprobed_add3\\(x=5, et=0\\)',
            'test_uprobe: uprobed_add3\\(\\) => void',
            'test_uprobe: uprobed_add4\\(ptr=0x[0-9a-z]+, iu=3, str="ssss"\\)',
            'test_uprobe: uprobed_add4\\(\\) => 0x[0-9a-z]+',
            #'test_uprobe: uprobed_add5\\(obj=0x[0-9a-z]+\\)',
            #'test_uprobe: uprobed_add5\\(\\) => void',
            'test_uprobe: uprobed_add6\\(ptr=0x[0-9a-z]+, iu=-1, str="yy"\\)',
            'test_uprobe: uprobed_add6\\(\\) => 0x[0-9a-z]+'
        ],
        None
    ),
    (   
        uprobe_cpp,
        f'psdig trace uprobe {uprobe_cpp}',
        [
           "MyClass2::myMethod(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)",
           "MyClass2::myMethod2(my_enum_e)",
           "MyClass::myMethod(int)",
           "MyNamespace2::MyClass2::MyClass2(long long)",
           "MyNamespace2::MyClass2::myMethod(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)",
           "MyNamespace2::MyClass2::myMethod(unsigned int, char)",
           "MyNamespace2::MyClass2::~MyClass2()",
           "MyNamespace2::MyClass::myMethod1(int)"
        ],
        None,
        output_fmt,
        [
           "test_uprobe: MyNamespace2::MyClass2::MyClass2\\(this=0x[0-9a-z]+, xxxx=10\\)",
           "test_uprobe: MyNamespace2::MyClass2::MyClass2\\(\\) => void",
           "test_uprobe: MyNamespace2::MyClass::myMethod1\\(this=0x[0-9a-z]+, a1=1\\)",
           "test_uprobe: MyNamespace2::MyClass::myMethod1\\(\\) => void",
           "test_uprobe: MyNamespace2::MyClass2::myMethod\\(this=0x[0-9a-z]+, a1=0x[0-9a-z]+\\)",
           "test_uprobe: MyNamespace2::MyClass2::myMethod\\(\\) => -1",
           "test_uprobe: MyNamespace2::MyClass2::myMethod\\(this=0x[0-9a-z]+, x=10, ch=105\\)",
           "test_uprobe: MyNamespace2::MyClass2::myMethod\\(\\) => 0",
           "test_uprobe: MyClass::myMethod\\(this=0x[0-9a-z]+, a1=10\\)",
           "test_uprobe: MyClass::myMethod\\(\\) => void",
           "test_uprobe: MyClass2::myMethod2\\(this=0x[0-9a-z]+, x=1\\)",
           "test_uprobe: MyClass2::myMethod2\\(\\) => 1",
           "test_uprobe: MyNamespace2::MyClass2::~MyClass2\\(this=0x[0-9a-z]+, __in_chrg=\\-*[0-9]+\\)",
           "test_uprobe: MyNamespace2::MyClass2::~MyClass2\\(\\) => void"
        ],
        None
    ),
    (
        uprobe_c,
        f'psdig trace uprobe {uprobe_c}',
        ["xxx"],
        None,
        output_fmt,
        None,
        "fail to resolve function"
    ),
    (
        uprobe_c,
        'psdig trace uprobe uprobe_c/Makefile',
        ["xxx"],
        None,
        output_fmt,
        None,
        "error resolving symbols"
    ),
    (
        uprobe_c,
        f'psdig trace uprobe {uprobe_c} -s uprobe_c/Makefile',
        ["uprobed_add1"],
        None,
        output_fmt,
        None,
        "error resolving symbols"
    ),
    (
        uprobe_c,
        f'psdig trace uprobe {libc_path} -c test_uprobe',
        ["__libc_malloc"],
        None,
        output_fmt,
        [
           "test_uprobe: __libc_malloc\\(bytes=",
           "test_uprobe: __libc_malloc\\(\\) => "
        ],
        None
    )
]

@pytest.mark.parametrize("test_cmd,probe_cmd,functions,filter_str,output_fmt,expect_traces,expect_error", cases)
def test_uprobe(test_cmd, probe_cmd, functions, filter_str, output_fmt, expect_traces, expect_error):
    cmd_list = probe_cmd.split()
    cmd_list += functions
    if filter_str != None:
        cmd_list.append('-f')
        cmd_list.append(filter_str)
    if output_fmt != None:
        cmd_list.append('-o')
        cmd_list.append(output_fmt)
    if hasattr(shlex, 'join'):
        trace_cmd = shlex.join(cmd_list)
    else:
        trace_cmd = ' '.join(cmd_list)
    logger.info(f'# {trace_cmd}')
    tc = TraceCollect()
    tc.start(cmd_list)
    if re.search('libc', probe_cmd):
        time.sleep(20)
    else:
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

