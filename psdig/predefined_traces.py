predefined_traces = [
   {
       "name":"open",
       "trigger":"syscall:openat",
       "detail_fmt": "{args[filename]} mode={args[mode]} flags={args[flags]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"open",
       "trigger":"syscall:open",
       "detail_fmt": "{args[filename]} mode={args[mode]} flags={args[flags]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"unlink",
       "trigger":"syscall:unlink",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"unlink",
       "trigger":"syscall:unlinkat",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"unlink",
       "trigger":"syscall:unlinkat",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"truncate",
       "trigger":"syscall:truncate",
       "detail_fmt": "{args[pathname]} length={args[length]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {   
       "name":"chown",
       "trigger":"syscall:chown",
       "detail_fmt": "{args[filename]} uid={args[user]} gid={args[group]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"chown",
       "trigger":"syscall:fchownat",
       "detail_fmt": "{args[filename]} uid={args[user]} gid={args[group]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"chmod",
       "trigger":"syscall:chmod",
       "detail_fmt": "{args[filename]} mode={args[mode]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"chmod",
       "trigger":"syscall:fchmodat",
       "detail_fmt": "{args[filename]} mode={args[mode]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {    
       "name":"rmdir",
       "trigger":"syscall:rmdir",
       "detail_fmt": "{args[pathname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"mkdir",
       "trigger":"syscall:mkdir",
       "detail_fmt": "{args[pathname]} mode={args[mode]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"mkdir",
       "trigger":"syscall:mkdirat",
       "detail_fmt": "{args[pathname]} mode={args[mode]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"symlink",
       "trigger":"syscall:symlink",
       "detail_fmt": "oldname={args[oldname]} newname={args[newname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"symlink",
       "trigger":"syscall:symlinkat",
       "detail_fmt": "oldname={args[oldname]} newname={args[newname]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"kill",
       "trigger":"syscall:kill",
       "detail_fmt": "pid={args[pid]} signal={args[sig]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"exec",
       "trigger":"syscall:execve",
       "detail_lambda": "' '.join(args['argv'])",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"setuid",
       "trigger":"syscall:setuid",
       "detail_fmt": "uid={args[uid]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"sethostname",
       "trigger":"syscall:sethostname",
       "detail_fmt": "hostname={args[name]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"listen",
       "trigger":"syscall:listen",
       "detail_fmt": "fd={args[fd]} backlog={args[backlog]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"connect",
       "trigger":"syscall:connect",
       "detail_fmt": "address={args[uservaddr]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"accept",
       "trigger":"syscall:accept",
       "detail_fmt": "address={args[upeer_sockaddr]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"bind",
       "trigger":"syscall:bind",
       "detail_fmt": "address={args[umyaddr]} ret={ret}",
       "level_lambda": "'INFO' if ret >= 0 else 'ERROR'"
   },
   {
       "name":"mount",
       "trigger":"syscall:mount",
       "detail_fmt": "dev_name={args[dev_name]} dir_name={args[dir_name]} type={args[type]} ret={ret}",
       "level_lambda": "'INFO' if ret == 0 else 'ERROR'"
   },
   {
       "name":"umount",
       "trigger":"syscall:umount",
       "detail_fmt": "name={args[name]} flags={args[flags]} ret={ret}",
       "level_lambda": "'INFO' if ret == 0 else 'ERROR'"
   },
   {
       "name":"tcp-recv-rst",
       "trigger":"event:tcp/tcp_receive_reset",
       "detail_lambda": "'saddr=%s sport=%d daddr=%s dport=%d' % (inet_ntoa(args['saddr']), args['sport'], inet_ntoa(args['daddr']), args['dport'])",
       "level": "WARNING"
   },
   {
       "name":"tcp-send-rst",
       "trigger":"event:tcp/tcp_send_reset",
       "detail_lambda": "'saddr=%s sport=%d daddr=%s dport=%d' % (inet_ntoa(args['saddr']), args['sport'], inet_ntoa(args['daddr']), args['dport'])",
       "level": "WARNING"
   }
]
