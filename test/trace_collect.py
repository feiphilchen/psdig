import os
import fcntl
import subprocess
import threading

class TraceCollect(object):
    def __init__(self):
        self.proc = None
        self.collect_thread = None
        self.output = []

    def collect(self, cmd):
        os.environ['PYTHONUNBUFFERED'] = 'y'
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:
            line = self.proc.stdout.readline()
            if not line:
                break
            line = line.decode()
            self.output.append(line)

    def start_trace_thread(self, cmd):
        self.collect_thread = threading.Thread(target = self.collect, args = (cmd,), daemon=True)
        self.collect_thread.start()

    def start(self, cmd):
        self.output = []
        self.start_trace_thread(cmd)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
            fd = self.proc.stderr.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            error = self.proc.stderr.read()
            if error:
                return self.output,error.decode()
            else:
                return self.output,None
        else:
            return [],None



