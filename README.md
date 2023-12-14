# psdig
<pre>
.______     _______. _______   __    _______ 
|   _  \   /       ||       \ |  |  /  _____|
|  |_)  | |   (----`|  .--.  ||  | |  |  __  
|   ___/   \   \    |  |  |  ||  | |  | |_ | 
|  |   .----)   |   |  '--'  ||  | |  |__| | 
| _|   |_______/    |_______/ |__|  \______| 
                                             
</pre>
psdig is a tool to watch and analyze process events with ebpf. It aims to empower your trace collection and analysis with python but no ebpf c code, so it does not require bcc tools.

## Features
* generate ebpf code and attach to tracepoint without writing c code 
* watch and show event trace in a curse window with filtering, statistics and etc.
* save events in file and load it to curse UI for later analysis.
* correlate syscall enter/exit traces to single event and tranlate arguments to human reable format
* trace events with specified format or lambda function in python one-liners.

![demo](images/demo.gif)

