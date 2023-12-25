#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com
set -e
PSDIG_PREFIX=/usr/local/share/psdig
DEFAULT_PKG='https://github.com/feiphilchen/psdig/releases/download/v1.1.0/psdig-1.1.0.tar.gz'
OS="`cat /etc/os-release | egrep '^ID=' | awk -F '=' '{print $2}' | sed 's/\"//g'`"
VERSION="`cat /etc/os-release | egrep '^VERSION_ID=' | awk -F '=' '{print $2}' | sed 's/\"//g'`"
MACHINE=`uname -m`
KERNEL=`uname -r | awk -F '-' '{print $1}'`
SUPPORTED="ubuntu-18.04-x86_64 ubuntu-20.04-x86_64 ubuntu-22.04-x86_64
ubuntu-18.04-aarch64 ubuntu-20.04-aarch64 ubuntu-22.04-aarch64
debian-10-x86_64 debian-11-x86_64 debian-12-x86_64
debian-10-aarch64 debian-11-aarch64 debian-12-aarch64
"

ubuntu_deps () {
    if [ "$1" == "20.04" -o "$1" == "22.04" ]
    then
        apt-get update && \
        apt-get install -y python3 python3-pip python3-venv libelf-dev clang cmake && \
        python3 -m venv ${PSDIG_PREFIX}/python && \
        ${PSDIG_PREFIX}/python/bin/python3 -m pip install wheel
    elif [ "$1" == "18.04" ]
    then
        apt-get update && \
        apt-get install -y python3 python3-pip python3-venv libelf-dev software-properties-common cmake wget && \
        wget https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh && \
        bash /tmp/llvm.sh 12 &&
        python3 -m venv ${PSDIG_PREFIX}/python && \
        ${PSDIG_PREFIX}/python/bin/python3 -m pip install wheel
    fi
}

debian_deps () {
    if [ "$1" == "12" -o "$1" == "11" ]
    then
        apt-get update && \
        apt-get install -y python3 python3-pip python3-venv libelf-dev clang cmake && \
        python3 -m venv ${PSDIG_PREFIX}/python && \
        ${PSDIG_PREFIX}/python/bin/python3 -m pip install wheel
    elif [ "$1" == "10" ]
    then
        apt-get update && \
        apt-get install -y python3 python3-pip python3-venv libelf-dev software-properties-common cmake wget && \
        wget https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh && \
        bash /tmp/llvm.sh 12 &&
        python3 -m venv ${PSDIG_PREFIX}/python && \
        ${PSDIG_PREFIX}/python/bin/python3 -m pip install wheel
    fi
}

al_deps () {
    if [ "$1" == "2023" ]
    then
        yum install -y python3-pip.noarch clang.${MACHINE} cmake.${MACHINE} elfutils-libelf-devel.${MACHINE} python3-devel && \
        python3 -m venv ${PSDIG_PREFIX}/python && \
        ${PSDIG_PREFIX}/python/bin/python3 -m pip install wheel
    elif [ "$1" == "2" ]
    then
        yum install -y python3-pip.noarch clang.${MACHINE} cmake3.${MACHINE} elfutils-libelf-devel.${MACHINE} python3-devel && \
        python3 -m venv ${PSDIG_PREFIX}/python && \
        ${PSDIG_PREFIX}/python/bin/python3 -m pip install wheel
    fi
}

rhel_deps () {
    major_version=`echo $1 | awk -F '.' '{print $1}'`
    if [ "$major_version" == "8" -o "$major_version" == "9" ]
    then
        yum install -y python3-pip.noarch clang.${MACHINE} cmake.${MACHINE} elfutils-libelf-devel.${MACHINE} python3-devel && \
        python3 -m venv ${PSDIG_PREFIX}/python && \
        ${PSDIG_PREFIX}/python/bin/python3 -m pip install wheel
    fi
}

install_dependency() {
    case $OS in
       ubuntu)
           ubuntu_deps $VERSION
       ;;
       debian)
           debian_deps $VERSION
       ;;
       amzn)
           al_deps $VERSION
       ;;
       rhel)
           rhel_deps $VERSION
       ;;
    esac
}

check_os() {
    os_id="${OS}-${VERSION}-${MACHINE}"
    for os in $SUPPORTED
    do
        if [ "$os" == "$os_id" ]
        then
            return 0
        fi
    done
    print_supported
    return 1
}

print_supported() {
    echo "Supported OS list:"
    for os in $SUPPORTED
    do
        echo "  - ${os}"
    done
}

environ_check() {
    check_os
}

install_psdig() {
    if [ -z "$PSDIG_PKG" ]
    then
        PSDIG_PKG="$DEFAULT_PKG"
    fi
    ${PSDIG_PREFIX}/python/bin/python3 -m pip install "$PSDIG_PKG"
    ${PSDIG_PREFIX}/python/bin/python3 -m psdig.initialize
}

install_all() {
    environ_check
    install_dependency
    install_psdig
}

if [ -z "$1" ]
then
    install_all
    exit 0
fi

case $1 in 
    --deps)
        install_dependency
        shift
        ;;
    --check)
        environ_check
        shift
        ;;
    --pkg)
        install_psdig
        shift
        ;;
esac

