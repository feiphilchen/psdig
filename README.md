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
* One-liner syscall/event trace with specified format or lambda function in python one-liners.
* Automate c/cpp program function trace with demangled name,arguments and return value.

![demo](images/demo.gif)

## Getting started
