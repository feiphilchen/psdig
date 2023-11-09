predefined_traces = [
   {
       "event":"open",
       "syscall":"openat",
       "detail_fmt": "{args[filename]} mode={args[mode]} flags={args[flags]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"open",
       "syscall":"open",
       "detail_fmt": "{args[filename]} mode={args[mode]} flags={args[flags]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"unlink",
       "syscall":"unlink",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"unlink",
       "syscall":"unlinkat",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"unlink",
       "syscall":"unlinkat",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"truncate",
       "syscall":"truncate",
       "detail_fmt": "{args[pathname]} length={args[length]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {   
       "event":"chown",
       "syscall":"chown",
       "detail_fmt": "{args[filename]} uid={args[user]} gid={args[group]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"chown",
       "syscall":"fchownat",
       "detail_fmt": "{args[filename]} uid={args[user]} gid={args[group]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"chmod",
       "syscall":"chmod",
       "detail_fmt": "{args[filename]} mode={args[mode]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"chmod",
       "syscall":"fchmodat",
       "detail_fmt": "{args[filename]} mode={args[mode]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {    
       "event":"rmdir",
       "syscall":"rmdir",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"mkdir",
       "syscall":"mkdir",
       "detail_fmt": "{args[pathname]} mode={args[mode]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"mkdir",
       "syscall":"mkdirat",
       "detail_fmt": "{args[pathname]} mode={args[mode]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"symlink",
       "syscall":"symlink",
       "detail_fmt": "oldname={args[oldname]} newname={args[newname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"symlink",
       "syscall":"symlinkat",
       "detail_fmt": "oldname={args[oldname]} newname={args[newname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"kill",
       "syscall":"kill",
       "detail_fmt": "pid={args[pid]} signal={args[sig]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"exec",
       "syscall":"execve",
       "detail_lambda": "' '.join(args['argv'])",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"setuid",
       "syscall":"setuid",
       "detail_fmt": "uid={args[uid]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"sethostname",
       "syscall":"sethostname",
       "detail_fmt": "hostname={args[name]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"listen",
       "syscall":"listen",
       "detail_fmt": "fd={args[fd]} backlog={args[backlog]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"connect",
       "syscall":"connect",
       "detail_fmt": "address={args[uservaddr]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"accept",
       "syscall":"accept",
       "detail_fmt": "address={args[upeer_sockaddr]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"bind",
       "syscall":"bind",
       "detail_fmt": "address={args[umyaddr]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "event":"mount",
       "syscall":"mount",
       "detail_fmt": "dev_name={args[dev_name]} dir_name={args[dir_name]} type={args[type]} ret={ret}",
       "level_lambda": "'INFO' if ret == 0 else 'ERROR'"
   },
   {
       "event":"umount",
       "syscall":"umount",
       "detail_fmt": "name={args[name]} flags={args[flags]} ret={ret}",
       "level_lambda": "'INFO' if ret == 0 else 'ERROR'"
   }
]
