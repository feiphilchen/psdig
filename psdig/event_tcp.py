# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com
import os
import sys
import re
import json
import time
import socket

class EventTcpRecvRst(object):
    def __init__(self, event_mgr):
        self.event_name = "tcp-recv-rst"
        self.em = event_mgr
        self.em.trace_register(self.event_name)
        self.em.event_watch("tcp/tcp_receive_reset", self.tcp_receive_rst)

    def tcp_receive_rst(self, event):
        if 'saddr' in event['parameters'] and 'daddr' in event['parameters']:
            saddr = bytes.fromhex(event['parameters']['saddr'])
            daddr = bytes.fromhex(event['parameters']['daddr'])
            saddr = socket.inet_ntoa(saddr)
            daddr = socket.inet_ntoa(daddr)
            sport = event['parameters']['sport']
            dport = event['parameters']['dport']
            detail = f"saddr={saddr} sport={sport} daddr={daddr} dport={dport}"
            args = {
               "name":self.event_name,
               "comm": event["comm"],
               "pid": event["pid"],
               "uid": event["uid"],
               "detail": detail,
               "level": "INFO"
            }
            self.em.trace_send(args)

class EventTcpSendRst(object):
    def __init__(self, event_mgr):
        self.event_name = "tcp-send-rst"
        self.em = event_mgr
        self.em.trace_register(self.event_name)
        self.em.event_watch("tcp/tcp_send_reset", self.tcp_send_rst)

    def tcp_send_rst(self, event):
        if 'saddr' in event['parameters'] and 'daddr' in event['parameters']:
            saddr = bytes.fromhex(event['parameters']['saddr'])
            daddr = bytes.fromhex(event['parameters']['daddr'])
            saddr = socket.inet_ntoa(saddr)
            daddr = socket.inet_ntoa(daddr)
            sport = event['parameters']['sport']
            dport = event['parameters']['dport']
            detail = f"saddr={saddr} sport={sport} daddr={daddr} dport={dport}"
            args = {
               "name":self.event_name,
               "comm": event["comm"],
               "pid": event["pid"],
               "uid": event["uid"],
               "detail": detail,
               "level": "INFO"
            }
            self.em.trace_send(args)

