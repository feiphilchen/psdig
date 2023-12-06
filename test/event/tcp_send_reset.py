import os
import time
import socket
import struct
import subprocess
import socket
import threading

server_port=51810

def process():
    sock = socket.socket()
    sock.bind(("127.0.0.1",server_port))
    sock.listen(3)
    print("Waiting on connection")
    conn = sock.accept()
    print("Client connected")
    while True:
        m = conn[0].recv(4096)
        conn[0].send(m[::-1])
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()

def client(host, port):
    print("Connecting to server")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect((host, port))
    l_onoff = 1
    l_linger = 0
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                 struct.pack('ii', l_onoff, l_linger))
    s.close()
    print("Closed with rst")

thread = threading.Thread(target=process)
thread.daemon = True
thread.start()
time.sleep(2)
client('127.0.0.1', server_port)
