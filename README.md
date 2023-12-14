# psdig
<pre>
.______     _______. _______   __    _______ 
|   _  \   /       ||       \ |  |  /  _____|
|  |_)  | |   (----`|  .--.  ||  | |  |  __  
|   ___/   \   \    |  |  |  ||  | |  | |_ | 
|  |   .----)   |   |  '--'  ||  | |  |__| | 
| _|   |_______/    |_______/ |__|  \______| 
                                             
</pre>
psdig is a tool to watch and analyze process behaviors with ebpf trace. It aims to automate your trace collection and analysis with python so it does not require your ebpf code and bcc tools. Currently, it supports syscall/tracepoint/uprobe events.

## Features
* Collect and show process activities in a curse window with filtering, statistics and customized format. Trace can be saved into a file or loaded for later analysis.
* Watch your interested events(syscall/tracepoint/uprobe) by defining a custom template with filters and detail formats.
* One-liner syscall/event trace with specified format or lambda function.
* Automate c/cpp program function trace with demangled name,arguments and return value.

![demo](images/demo.gif)

## Getting started

### Watch process activities in real time
#### Usage:
```
# psdig watch --help
Usage: psdig watch [OPTIONS]

  Watch file system, network and process activity

Options:
  -p, --pid INTEGER        Pid filter
  -u, --uid INTEGER        Uid filter
  -c, --comm TEXT          Command filter
  -o, --output PATH        Save traces to file
  -l, --log PATH           Log messages to file
  -t, --template FILENAME  Template file
  --headless               Run without curse windows
  --help                   Show this message and exit.

# psdig load --help
Usage: psdig load [OPTIONS] FILE

  Load traces from file

Options:
  -l, --log PATH  Log all messages to file
  --help          Show this message and exit.
```

#### Examples
Traces all process/system activities and display them in a curse window
```
sudo psdig watch
```

Traces all process/system activities and print to console without GUI
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

### Syscall/Event one-liners
#### Usage:
```
# psdig trace syscall --help
Usage: psdig trace syscall [OPTIONS] [SYSCALL]...

  Trace syscall

Options:
  -o, --output TEXT  Format string
  -f, --filter TEXT  Filter string
  -p, --pid INTEGER  Pid filter
  -u, --uid INTEGER  Uid filter
  -c, --comm TEXT    Command filter
  --help             Show this message and exit.
root@ubuntu01:~# psdig trace event --help
Usage: psdig trace event [OPTIONS] [EVENT]...

  Trace event

Options:
  -o, --output TEXT  Format string
  -f, --filter TEXT  Filter string
  -p, --pid INTEGER  Pid filter
  -u, --uid INTEGER  Uid filter
  -c, --comm TEXT    Command filter
  --help             Show this message and exit.
```
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
sudo psdig trace syscall sys_connect -o "lambda:'{:20s} {:30s} {:10d}'.format(metadata['comm'], args['uservaddr'], metadata['latency'])"
```

Traces all commands executed in bash , format command line arguments and print with UID
```
psdig trace syscall -c bash sys_execve -o "lambda:str(metadata['uid']) + ': '+ ' '.join(args['argv'])"
```
