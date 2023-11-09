import os
import sqlite3
import logging
import traceback
import random 
import re
import json
from .conf import LOGGER_NAME

class EventDb(object):
    def __init__(self, name=None, persist=False):
        if name:
            self.db_name = name
        else:
            self.db_name = self.get_default_db()
        self.persist = persist
        self.set_logger()
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
          CREATE TABLE IF NOT EXISTS events
          ([row_id] INTEGER PRIMARY KEY,
          [id] INTEGER,
          [timestamp] REAL,
          [command] TEXT,
          [pid] INTEGER,
          [uid] INTEGER,
          [event] TEXT,
          [level] TEXT,
          [detail] TEXT,
          [extend] TEXT)
          ''')
        conn.commit()
        conn.close()

    def get_default_db(self):
        r = random.randint(0, 1000000) 
        return f"/var/tmp/{r}.event.db"

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def count(self):
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) from events')
        result = cur.fetchone()
        cur.close()
        conn.close()
        return result[0]

    def event_to_tuple(self, event):
        extend_str = json.dumps(event['extend'])
        return (event['id'], event['timestamp'], event['comm'], str(event['pid']), str(event['uid']), event['name'], event['level'], event['detail'], extend_str)

    def event_to_dict(self, evt):
        id,timestamp,command,pid,uid,name,level,detail,extend_str = evt
        event = {}
        event['id'] = id
        event['timestamp'] = timestamp
        event['comm'] = command
        event['pid'] = pid
        event['uid'] = uid
        event['name'] = name
        event['level'] = level
        event['detail'] = detail
        event['extend'] = json.loads(extend_str)
        return event

    def read(self, row_start, count):
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        row_id_start = row_start + 1
        row_id_end = row_id_start + count
        result = []
        sql = f"SELECT id,timestamp, command, pid, uid, event, level, detail, extend FROM events WHERE row_id >={row_id_start} and row_id < {row_id_end}"
        for row in cur.execute(sql):
            event = self.event_to_dict(row)
            result.append(event)
        cur.close()
        conn.close()
        return result

    def write(self, events):
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        event_tuples = []
        for evt in events:
            t = self.event_to_tuple(evt)
            event_tuples.append(t)
        sql = "INSERT INTO events(id, timestamp, command, pid, uid, event, level, detail, extend) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"
        cur.executemany(sql, event_tuples)
        conn.commit()
        cur.close()
        conn.close()

    def clear(self):
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        sql = "DELETE FROM events"
        cur.execute(sql)
        conn.commit()
        cur.close()
        conn.close()

    def filter_check(self, event, filter_text):
        filter_out = True
        if filter_text == None:
            return False
        for evt_field in event:
            value = str(evt_field)
            if re.search(filter_text, value):
                filter_out = False
                break
        return filter_out

    def filter(self, filter_text):
        result = []
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        sql = "SELECT id,timestamp,command,pid,uid,event,level,detail,extend FROM events"
        for row in cur.execute(sql):
            filter_out = self.filter_check(row, filter_text)
            if filter_out:
                continue
            event = self.event_to_dict(row)
            result.append(event)
        cur.close()
        conn.close()
        return result

    def __del__(self):
        if not self.persist and os.path.exists(self.db_name):
            os.unlink(self.db_name)
