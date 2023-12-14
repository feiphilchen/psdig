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
* Collect and show process activities in a curse window with filtering, statistics and customized format.
* Save traces into file and load them for later analysis.
* Watch with a customized template which describe interested events(syscall/tracepoint/uprobe), filters and detail formats.
* One-liner syscall/event trace with specified format or lambda function.
* Automate c/cpp program function trace with demangled name,arguments and return value.

![demo](images/demo.gif)

## Getting started

### Watch process activities
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


