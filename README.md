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
* watch and show process events in a curse window with filtering, statistics and customized formats.
* save traces into file and load them for later analysis.
* trace syscall/events with specified format or lambda function in python one-liners.
* trace c/cpp program functions with demangled name and customized filters.

![demo](images/demo.gif)

