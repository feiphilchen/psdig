predefined_syscall_events = [
   {
       "event":"open",
       "syscall":"openat",
       "detail_fmt": "{args[filename]} mode={args[mode]} flags={args[flags]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"open",
       "syscall":"open",
       "detail_fmt": "{args[filename]} mode={args[mode]} flags={args[flags]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"unlink",
       "syscall":"unlink",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"unlink",
       "syscall":"unlinkat",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"unlink",
       "syscall":"unlinkat",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"truncate",
       "syscall":"truncate",
       "detail_fmt": "{args[pathname]} length={args[length]} ret={ret}",
       "result": "ret >= 0"
   },
   {   
       "event":"chown",
       "syscall":"chown",
       "detail_fmt": "{args[filename]} uid={args[user]} gid={args[group]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"chown",
       "syscall":"fchownat",
       "detail_fmt": "{args[filename]} uid={args[user]} gid={args[group]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"chmod",
       "syscall":"chmod",
       "detail_fmt": "{args[filename]} mode={args[mode]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"chmod",
       "syscall":"fchmodat",
       "detail_fmt": "{args[filename]} mode={args[mode]} ret={ret}",
       "result": "ret >= 0"
   },
   {    
       "event":"rmdir",
       "syscall":"rmdir",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"mkdir",
       "syscall":"mkdir",
       "detail_fmt": "{args[pathname]} mode={args[mode]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"mkdir",
       "syscall":"mkdirat",
       "detail_fmt": "{args[pathname]} mode={args[mode]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"symlink",
       "syscall":"symlink",
       "detail_fmt": "oldname={args[oldname]} newname={args[newname]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"symlink",
       "syscall":"symlinkat",
       "detail_fmt": "oldname={args[oldname]} newname={args[newname]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"kill",
       "syscall":"kill",
       "detail_fmt": "pid={args[pid]} signal={args[sig]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"exec",
       "syscall":"execve",
       "detail_lambda": "' '.join(args['argv'])",
       "result": "ret >= 0"
   },
   {
       "event":"setuid",
       "syscall":"setuid",
       "detail_fmt": "uid={args[uid]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"sethostname",
       "syscall":"sethostname",
       "detail_fmt": "hostname={args[name]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"listen",
       "syscall":"listen",
       "detail_fmt": "fd={args[fd]} backlog={args[backlog]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"connect",
       "syscall":"connect",
       "detail_fmt": "address={args[uservaddr]} ret={ret}",
       "result": "ret >= 0"
   },
   {
       "event":"accept",
       "syscall":"accept",
       "detail_fmt": "address={args[upeer_sockaddr]} ret={ret}",
       "result": "ret >= 0"
   }
]
