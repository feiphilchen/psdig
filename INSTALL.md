# Psdig Install

- [System Requirements](#system-requirements)
  - [Linux Kernel](#linux-kernel)
  - [DEBUGFS](#debugfs)
  - [Operating System](#operating-system)
- [Install Instructions](#install-instructions)
  - [One line installer](#one-line-installer)
  - [Install From Source](#install-from-source)

## System Requirements
### Linux Kernel
Kernel 4.7 is required to use psdig since features were added in below releases:
* 4.3 - uprobes
* 4.7 - tracepoints

### DEBUGFS
The debugfs need to be mounted although in most of OS releases it is configured implicitly. Otherwise you need to mount it by
```
mount -t debugfs none /sys/kernel/debug
```

### Operating System
- Ubuntu 18.04/20.04/22.04
- Debian 10/11/12
- RHEL 8/9
- Amazon Linux 2/2023

## Install Instructions
### One-line Installer

```
wget https://raw.githubusercontent.com/feiphilchen/psdig/main/scripts/install.sh -q -O - | bash
```

### Install From Source
```
git clone https://github.com/feiphilchen/psdig.git
cd psdig
make deps
make
make install
```
