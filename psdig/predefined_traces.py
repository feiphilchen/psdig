predefined_traces = [
   {
       "name":"open",
       "trigger":"syscall:openat",
       "detail": "{args[filename]} mode={args[mode]} flags={args[flags]} ret={ret}",
       "level": {"lambda":"'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"open",
       "trigger":"syscall:open",
       "detail": "{args[filename]} mode={args[mode]} flags={args[flags]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {   
       "name":"close",
       "trigger":"syscall:close",
       "detail": "fd={args[fd]} ret={ret}",
       "level": {"lambda": "'INFO' if ret == 0 else 'ERROR'"}
   },
   {
       "name":"unlink",
       "trigger":"syscall:unlink",
       "detail": "{args[pathname]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"unlink",
       "trigger":"syscall:unlinkat",
       "detail": "{args[pathname]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"unlink",
       "trigger":"syscall:unlinkat",
       "detail": "{args[pathname]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"truncate",
       "trigger":"syscall:truncate",
       "detail": "{args[pathname]} length={args[length]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {   
       "name":"chown",
       "trigger":"syscall:chown",
       "detail": "{args[filename]} uid={args[user]} gid={args[group]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"chown",
       "trigger":"syscall:fchownat",
       "detail": "{args[filename]} uid={args[user]} gid={args[group]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"chmod",
       "trigger":"syscall:chmod",
       "detail": "{args[filename]} mode={args[mode]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"chmod",
       "trigger":"syscall:fchmodat",
       "detail": "{args[filename]} mode={args[mode]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {    
       "name":"rmdir",
       "trigger":"syscall:rmdir",
       "detail": "{args[pathname]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"mkdir",
       "trigger":"syscall:mkdir",
       "detail": "{args[pathname]} mode={args[mode]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"mkdir",
       "trigger":"syscall:mkdirat",
       "detail": "{args[pathname]} mode={args[mode]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"symlink",
       "trigger":"syscall:symlink",
       "detail": "oldname={args[oldname]} newname={args[newname]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"symlink",
       "trigger":"syscall:symlinkat",
       "detail": "oldname={args[oldname]} newname={args[newname]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"kill",
       "trigger":"syscall:kill",
       "detail": "pid={args[pid]} signal={args[sig]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"exec",
       "trigger":"syscall:execve",
       "detail": {"lambda":"' '.join(args['argv'])"},
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"fork",
       "trigger":"syscall:fork",
       "detail": "pid={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"exit",
       "trigger":"syscall:exit",
       "detail": "error_code={args[error_code]}",
       "level": {"lambda": "'INFO' if args['error_code'] == 0 else 'ERROR'"}
   },
   {
       "name":"exit",
       "trigger":"syscall:exit_group",
       "detail": "error_code={args[error_code]}",
       "level": {"lambda": "'INFO' if args['error_code'] == 0 else 'ERROR'"}
   },
   {
       "name":"setuid",
       "trigger":"syscall:setuid",
       "detail": "uid={args[uid]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"sethostname",
       "trigger":"syscall:sethostname",
       "detail": "hostname={args[name]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"listen",
       "trigger":"syscall:listen",
       "detail": "fd={args[fd]} backlog={args[backlog]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"connect",
       "trigger":"syscall:connect",
       "detail": "address={args[uservaddr]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"accept",
       "trigger":"syscall:accept",
       "detail": "address={args[upeer_sockaddr]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"bind",
       "trigger":"syscall:bind",
       "detail": "address={args[umyaddr]} ret={ret}",
       "level": {"lambda": "'INFO' if ret >= 0 else 'ERROR'"}
   },
   {
       "name":"mount",
       "trigger":"syscall:mount",
       "detail": "dev_name={args[dev_name]} dir_name={args[dir_name]} type={args[type]} ret={ret}",
       "level": {"lambda": "'INFO' if ret == 0 else 'ERROR'"}
   },
   {
       "name":"umount",
       "trigger":"syscall:umount",
       "detail": "name={args[name]} flags={args[flags]} ret={ret}",
       "level": {"lambda": "'INFO' if ret == 0 else 'ERROR'"}
   },
   {
       "name":"tcp-recv-rst",
       "trigger":"event:tcp/tcp_receive_reset",
       "detail": {"lambda":"'saddr=%s sport=%d daddr=%s dport=%d' % (inet_ntoa(args['saddr']), args['sport'], inet_ntoa(args['daddr']), args['dport'])"},
       "level": "WARNING"
   },
   {
       "name":"tcp-send-rst",
       "trigger":"event:tcp/tcp_send_reset",
       "detail": {"lambda":"'saddr=%s sport=%d daddr=%s dport=%d' % (inet_ntoa(args['saddr']), args['sport'], inet_ntoa(args['daddr']), args['dport'])"},
       "level": "WARNING"
   }
]
