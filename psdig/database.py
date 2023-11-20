import os
import sqlite3
import logging
import traceback
import random 
import re
import json
from .conf import LOGGER_NAME

class TraceDB(object):
    def __init__(self, name=None):
        if name:
            self.db_name = name
        else:
            self.db_name = self.get_default_db()
        self.set_logger()
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
          CREATE TABLE IF NOT EXISTS traces
          ([row_id] INTEGER PRIMARY KEY,
          [id] INTEGER,
          [timestamp] REAL,
          [command] TEXT,
          [pid] INTEGER,
          [uid] INTEGER,
          [name] TEXT,
          [level] TEXT,
          [detail] TEXT,
          [extend] TEXT)
          ''')
        conn.commit()
        conn.close()

    def get_default_db(self):
        r = random.randint(0, 1000000) 
        return f"/var/tmp/{r}.trace.db"

    def set_logger(self):
        self.logger_name = LOGGER_NAME
        self.logger = logging.getLogger(self.logger_name)

    def count(self):
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) from traces')
        result = cur.fetchone()
        cur.close()
        conn.close()
        return result[0]

    def trace_to_tuple(self, trace):
        extend_str = json.dumps(trace['extend'])
        return (trace['id'], trace['timestamp'], trace['comm'], str(trace['pid']), str(trace['uid']), trace['name'], trace['level'], trace['detail'], extend_str)

    def trace_to_dict(self, trace_tuple):
        id,timestamp,command,pid,uid,name,level,detail,extend_str = trace_tuple
        trace = {}
        trace['id'] = id
        trace['timestamp'] = timestamp
        trace['comm'] = command
        trace['pid'] = pid
        trace['uid'] = uid
        trace['name'] = name
        trace['level'] = level
        trace['detail'] = detail
        trace['extend'] = json.loads(extend_str)
        return trace

    def read(self, row_start, count):
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        row_id_start = row_start + 1
        row_id_end = row_id_start + count
        result = []
        sql = f"SELECT id,timestamp, command, pid, uid, name, level, detail, extend FROM traces WHERE row_id >={row_id_start} and row_id < {row_id_end}"
        for row in cur.execute(sql):
            trace = self.trace_to_dict(row)
            result.append(trace)
        cur.close()
        conn.close()
        return result

    def write(self, traces):
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        trace_tuples = []
        for trace in traces:
            t = self.trace_to_tuple(trace)
            trace_tuples.append(t)
        sql = "INSERT INTO traces(id, timestamp, command, pid, uid, name, level, detail, extend) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"
        cur.executemany(sql, trace_tuples)
        conn.commit()
        cur.close()
        conn.close()

    def clear(self):
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        sql = "DELETE FROM traces"
        cur.execute(sql)
        conn.commit()
        cur.close()
        conn.close()

    def filter_check(self, trace, filter_text):
        filter_out = True
        if filter_text == None:
            return False
        for field in trace:
            value = str(field)
            if re.search(filter_text, value):
                filter_out = False
                break
        return filter_out

    def filter(self, filter_text):
        result = []
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        sql = "SELECT id,timestamp,command,pid,uid,name,level,detail,extend FROM traces"
        for row in cur.execute(sql):
            filter_out = self.filter_check(row, filter_text)
            if filter_out:
                continue
            trace = self.trace_to_dict(row)
            result.append(trace)
        cur.close()
        conn.close()
        return result

    def __del__(self):
        pass

