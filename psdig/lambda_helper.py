import socket

def inet_ntoa(addr_str):
    addr = bytes.fromhex(addr_str)
    return socket.inet_ntoa(addr)

