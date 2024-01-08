<p align="center"><img src="https://github.com/feiphilchen/psdig/blob/main/images/logo.png"></p>
psdig is a tool to watch and analyze process behaviors with ebpf trace. It aims to automate your trace collection and analysis with python so it does not require your ebpf code and bcc tools. Currently, it supports syscall/tracepoint/uprobe events and provides different ways to collect traces for your needs of troubleshooting, security and performance analysis.

## Features
* Collect and show process activities in a curse window with filtering, statistics and customized format. Trace can be saved into a file or loaded for later analysis.
* Watch your interested events(syscall/tracepoint/uprobe) by defining a custom template with filters and detail formats.
* One-liner syscall/event/uprobe trace with specified format or lambda function. c/cpp functions can be resolved with demangled name,arguments and return value.

![demo](images/demo.gif)

## Install

Check into [INSTALL.md](INSTALL.md) for installation steps.

## Getting started

### Grouped watch
Grouped watch is to trace a number of syscalls/events/uprobes in a batch. Pre-defined trace groups are:
 * file system
 * socket
 * process
 * tcp
 * bio

#### Examples
Traces all activities and display them in a curse window
```
sudo psdig watch
```
Traces only process and socket related system activities
```
sudo psdig watch -g process -g socket
```
Traces all activities and print to console without GUI
```
sudo psdig watch --headless
```

Traces systemd and bash activities, display in curse window and save to file trace.db
```
sudo psdig watch -c systemd -c bash -o trace.db
```

Load from file trace.db and display in curse window
```
sudo psdig load trace.db
```

Watch process/system activities which are defined in template trace_template.json
```
sudo psdig watch -t trace_template.json
```

### Syscall/Event/Uprobe trace one-liners
One-liner can be used to contruct your trace quickly. With filter and formatter options, you can customize output field and limit trace number. 

#### Examples
Traces all file opens 
```
sudo psdig trace syscall sys_openat
```

Traces all file opens happens in systemd, print command, pid, filename to console
```
sudo psdig trace syscall sys_openat -f "metadata['comm'] == 'systemd'" -o "{metadata[comm]}({metadata[pid]}) {args[filename]}"
```

Traces all connections which are initiatied by self, print command, server address and latency with format specifier
```
sudo psdig trace syscall sys_connect -o "'{:20s} {:30s} {:10d}'.format(metadata['comm'], args['uservaddr'], metadata['latency'])"
```

Traces all commands executed in bash, format command line arguments and print with UID
```
sudo psdig trace syscall -c bash sys_execve -o "str(metadata['uid']) + ': '+ ' '.join(args['argv'])"
```

Trace functions call and return(main,uprobed_add1) in program test/uprobe_c/test_uprobe
```
sudo psdig trace uprobe test/uprobe_c/test_uprobe main uprobed_add1
```

Trace all malloc/free function call and return 
```
glibc=`ldd /usr/bin/ls | grep libc.so | awk '{print $3}'` && \
  sudo psdig trace uprobe "$glibc" malloc free
```

## Feedback
Request new feature or file bug on:
[https://github.com/feiphilchen/psdig/issues](https://github.com/feiphilchen/psdig/issues)

Post question or proposal on:
[https://github.com/feiphilchen/psdig/discussions](https://github.com/feiphilchen/psdig/discussions)

## License
Psdig is licensed under [GPLv3+](LICENSE.txt)

Copyright 2023,  Feil Chen(feiphilchen@gmail.com). 

All rights reserved.


