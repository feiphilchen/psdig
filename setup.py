import os
import sys
import shlex
import re
import subprocess
from setuptools import setup,find_packages
from setuptools.command.install import install
from setuptools.command.build_ext import build_ext
from psdig import compile_event_objs

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

def install_clang(os_id):
    rc = subprocess.call(['which', 'clang'], stdout=subprocess.DEVNULL)
    if rc == 0:
        print("clang is already installed")
        return
    print("installing clang/llvm")
    if os_id == 'ubuntu':
        rc = subprocess.call(['apt-get', 'install', '-y', 'clang'], stdout=subprocess.DEVNULL)

def install_lib(os_id):
    print("installing build library")
    if os_id == 'ubuntu':
        rc = subprocess.call(['apt-get', 'install', '-y', 'libjson-c-dev', 'libelf-dev', 'gcc-multilib'], \
            stdout=subprocess.DEVNULL)

class CustomInstall(install):
    def run(self):
        install.run(self)
        os_id = get_os_id()
        install_libbpf(os_id)
        print("compiling event objects ...")
        compile_event_objs()

setup(
    name = "psdig",
    version = read('VERSION').strip(),
    author = "Fei Chen",
    author_email = "feiphilchen@gmail.com",
    description = ("Watch and filter process events with a curse window"),
    license = 'GNU General Public License version 3.0 (GPLv3)',
    keywords = "events,ebpf,trace",
    url = "https://github.com/feiphilchen/psdig",
    packages=['psdig', 'psdig/trace_event', 'psdig/trace_uprobe'],
    long_description=read('README.md'),
    install_requires=[
        "click",
        "psutil",
        "tabulate",
        "pyelftools==0.30"
    ],
    zip_safe=False,
    include_package_data=True,
    package_data={
        "": ["*.c", "*.h"],
    },
    cmdclass={
        "install": CustomInstall
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    entry_points={
        'console_scripts': [
            'psdig = psdig.cli:cli',
        ],
    }
)
