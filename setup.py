import os
import sys
import shlex
import re
import subprocess
import tempfile
import shutil
from setuptools import setup,find_packages
from setuptools.command.install import install
from setuptools.command.build_ext import build_ext

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

def get_os_id():
    d = {}
    with open('/etc/os-release', 'r') as fd:
        os_release = fd.read()
    for line in os_release.splitlines():
        try:
            k,v = line.rstrip().split("=")
        except:
            continue
        # .strip('"') will remove if there or else do nothing
        d[k] = v.strip('"')
    return d['ID'].lower()


def install_libbpf(os_id):
    libbpf_dir_src=os.path.join(os.path.dirname(__file__), 'libbpf', 'src')
    cmd_str = "cd {} && BUILD_STATIC_ONLY=y DESTDIR=/usr/local/share/psdig make install".format(shlex.quote(libbpf_dir_src))
    ret = os.WEXITSTATUS(os.system(cmd_str))
    if ret != 0:
        sys.exit('error building libbpf')

def install_libjsonc(os_id):
    libjsonc_dir_src=os.path.join(os.path.dirname(__file__), 'json-c')
    with tempfile.TemporaryDirectory() as tmpdirname:
        cmd_str = f"cd {tmpdirname} && cmake -DCMAKE_INSTALL_PREFIX=/usr/local/share/psdig/usr {libjsonc_dir_src} && make && make install"
        ret = os.WEXITSTATUS(os.system(cmd_str))
        if ret != 0:
            sys.exit('error building libjson-c')

def check_asm_dir(os_id):
    machine = os.uname().machine
    asm_dir=f'/usr/include/{machine}-linux-gnu/asm'
    if not os.path.exists('/usr/include/asm') and os.path.exists(asm_dir):
        cmd_str = f'ln -sf {asm_dir} /usr/include/asm'
        ret = os.WEXITSTATUS(os.system(cmd_str))

def cache_clean(os_id):
    print("psdig cache clean ...")
    BPF_OBJ_DIR="/usr/local/share/psdig/bpf"
    if os.path.exists(BPF_OBJ_DIR):
        shutil.rmtree(BPF_OBJ_DIR, ignore_errors=True)

def psdig_symlink(os_id):
    psdig_path = os.path.join(sys.prefix, 'bin', 'psdig')
    symlink = '/usr/bin/psdig'
    if not os.path.islink(symlink):
        os.symlink(psdig_path, symlink)


class CustomInstall(install):
    def run(self):
        install.run(self)
        os_id = get_os_id()
        check_asm_dir(os_id)
        install_libbpf(os_id)
        install_libjsonc(os_id)
        cache_clean(os_id)
        psdig_symlink(os_id)

setup(
    name = "psdig",
    version = read('VERSION').strip(),
    author = "Fei Chen",
    author_email = "feiphilchen@gmail.com",
    description = ("psdig is a tool to watch and analyze process behaviors with ebpf trace"),
    license = 'GNU General Public License version 3.0 (GPLv3)',
    keywords = "events,ebpf,trace",
    url = "https://github.com/feiphilchen/psdig",
    packages=['psdig', 'psdig/trace_event', 'psdig/trace_uprobe'],
    long_description=read('README.md'),
    install_requires=[
        "click==8.0.3",
        "psutil==5.9.6",
        "tabulate==0.9.0",
        "pyelftools==0.30"
    ],
    zip_safe=False,
    include_package_data=True,
    package_data={
        "": ["*.c", "*.h", "*.json"],
    },
    cmdclass={
        "install": CustomInstall
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Terminals',
        'Topic :: Utilities'
    ],
    entry_points={
        'console_scripts': [
            'psdig = psdig.cli:cli',
        ],
    }
)

