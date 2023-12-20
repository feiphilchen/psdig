# Psdig Install

## Requirements
### Linux Kernel
### Packages

## Install Instructions
### Ubuntu
#### Ubuntu 20.04(Focal)/22.04(Jammy) LTS
```
PSDIG_PREFIX=/usr/local/share/psdig && \
   PSDIG=psdig && \
   sudo apt-get update && \
   sudo apt-get install -y python3 python3-pip python3-venv libelf-dev clang cmake && \
   sudo python3 -m venv ${PSDIG_PREFIX}/python && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install wheel && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install ${PSDIG}
```
#### Ubuntu 18.04(Bionic) LTS
```
PSDIG_PREFIX=/usr/local/share/psdig && \
   PSDIG=psdig && \
   sudo apt-get update && \
   sudo apt-get install -y python3 python3-pip python3-venv software-properties-common cmake && \
   wget https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh && \
   sudo bash /tmp/llvm.sh 12 &&
   sudo python3 -m venv ${PSDIG_PREFIX}/python && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install wheel && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install ${PSDIG}
```
### Debian
#### Debian 11/12
```
PSDIG_PREFIX=/usr/local/share/psdig && \
   PSDIG=psdig && \
   sudo apt-get update && \
   sudo apt-get install -y python3 python3-pip python3-venv libelf-dev clang cmake &&
   sudo python3 -m venv ${PSDIG_PREFIX}/python && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install wheel && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install ${PSDIG}
```
#### Debian 10
```
PSDIG_PREFIX=/usr/local/share/psdig && \
   PSDIG=psdig && \
   sudo apt-get update && \
   sudo apt-get install -y python3 python3-pip python3-venv software-properties-common cmake && \
   wget https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh && \
   sudo bash /tmp/llvm.sh 12 &&
   sudo python3 -m venv ${PSDIG_PREFIX}/python && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install wheel && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install ${PSDIG}
```
### RHEL
#### RHEL 8/9
```
PSDIG_PREFIX=/usr/local/share/psdig && \
   PSDIG=psdig && \
   MACHINE=`uname -m` && \
   sudo yum install -y python3-pip.noarch clang.${MACHINE} cmake.${MACHINE} elfutils-libelf-devel.${MACHINE} python3-devel && \
   sudo python3 -m venv ${PSDIG_PREFIX}/python && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install wheel && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install ${PSDIG}
```
### Amazon Linux
#### AL-2023
```
PSDIG_PREFIX=/usr/local/share/psdig && \
   PSDIG=psdig && \
   MACHINE=`uname -m` && \
   sudo yum install -y python3-pip.noarch clang.${MACHINE} cmake.${MACHINE} elfutils-libelf-devel.${MACHINE} && \
   sudo python3 -m venv ${PSDIG_PREFIX}/python && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install wheel && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install ${PSDIG}
```
#### AL-2
```
PSDIG_PREFIX=/usr/local/share/psdig && \
   PSDIG=psdig && \
   MACHINE=`uname -m` && \
   sudo yum install -y python3-pip.noarch clang.${MACHINE} cmake3.${MACHINE} elfutils-libelf-devel.${MACHINE} && \
   sudo python3 -m venv ${PSDIG_PREFIX}/python && \     
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install wheel && \
   sudo ${PSDIG_PREFIX}/python/bin/pip3 install ${PSDIG}
```
