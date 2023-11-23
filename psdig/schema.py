#!/usr/bin/python3
# vim: set filetype=python
import os
import sys
import re
import json

TRACEFS="/sys/kernel/debug/tracing/events"
class EventSchema(object):
    def __init__(self):
        self.event_fields = {}
        self.type_mapping = {
            "unsigned char": "EVENT_FIELD_TYPE_UINT",
            "unsigned short": "EVENT_FIELD_TYPE_UINT",
            "unsigned int": "EVENT_FIELD_TYPE_UINT",
            "unsigned long": "EVENT_FIELD_TYPE_UINT",
            "unsigned long long": "EVENT_FIELD_TYPE_UINT",
            "__u8": "EVENT_FIELD_TYPE_UINT",
            "__u16": "EVENT_FIELD_TYPE_UINT",
            "__u32": "EVENT_FIELD_TYPE_UINT",
            "__u64": "EVENT_FIELD_TYPE_UINT",
            "__uint8": "EVENT_FIELD_TYPE_UINT",
            "__uint16": "EVENT_FIELD_TYPE_UINT",
            "__uint32": "EVENT_FIELD_TYPE_UINT",
            "__uint64": "EVENT_FIELD_TYPE_UINT",
            "uint8": "EVENT_FIELD_TYPE_UINT",
            "uint16": "EVENT_FIELD_TYPE_UINT",
            "uint32": "EVENT_FIELD_TYPE_UINT",
            "uint64": "EVENT_FIELD_TYPE_UINT",
            "char": "EVENT_FIELD_TYPE_INT",
            "short": "EVENT_FIELD_TYPE_INT",
            "int": "EVENT_FIELD_TYPE_INT",
            "long": "EVENT_FIELD_TYPE_INT",
            "long long": "EVENT_FIELD_TYPE_INT",
            "__int8": "EVENT_FIELD_TYPE_INT",
            "__int16": "EVENT_FIELD_TYPE_INT",
            "__int32": "EVENT_FIELD_TYPE_INT",
            "__int64": "EVENT_FIELD_TYPE_INT",
            "int8": "EVENT_FIELD_TYPE_INT",
            "int16": "EVENT_FIELD_TYPE_INT",
            "int32": "EVENT_FIELD_TYPE_INT",
            "int64": "EVENT_FIELD_TYPE_INT",
            "uid_t": "EVENT_FIELD_TYPE_UINT",
            "gid_t": "EVENT_FIELD_TYPE_UINT",
            "pid_t": "EVENT_FIELD_TYPE_UINT",
            "size_t": "EVENT_FIELD_TYPE_UINT",
            "umode_t": "EVENT_FIELD_TYPE_UINT",
            "char *": "EVENT_FIELD_TYPE_STR",
            "const char *": "EVENT_FIELD_TYPE_STR",
            "const char *const *": "EVENT_FIELD_TYPE_STR_LIST",
            "struct sockaddr *": "EVENT_FIELD_TYPE_SOCKADDR"
        }

    def parse_event_field(self, field_str):
        result = field_str.split(';')
        field_name_type = result[0]
        field_offset = result[1]
        field_size = result[2]
        field_signed = result[3]
        field_name = field_name_type.split()[-1]
        field_type = " ".join(field_name_type.split()[0:-1])
        field_offset = field_offset.split(':')[-1]
        field_size = field_size.split(':')[-1]
        field_signed = field_signed.split(':')[-1]
        array = re.match('([^\[]+)\[[0-9]+\]$', field_name)
        if array:
            field_name = array.group(1)
            field_type = f"{field_type}[]"
        field = {'name':field_name, 
                 'type':field_type,
                 'offset': int(field_offset),
                 'size': int(field_size),
                 'signed': int(field_signed)}
        return field

    def parse_event_format(self, event):
        format_file = "%s/%s/format" % (TRACEFS, event)
        with open(format_file, 'r') as fd:
            format_str = fd.read()
        lines = format_str.splitlines()
        fields = []
        for line in lines:
            matched = re.match('\s+field:(.*)$', line)
            if matched:
                field = self.parse_event_field(matched.group(1))
                fields.append(field)
        self.event_fields[event] = fields

    def get_event_id(self, event_name):
        evt_id = f'EVENT_ID_{event_name}'
        evt_id = evt_id.replace('/', '_')
        evt_id = evt_id.upper()
        return evt_id

    def save_event_id_list(self, fp):
        id_list = []
        for event_name,fields in self.event_fields.items():
            evt_id = f'EVENT_ID_{event_name}'
            evt_id = evt_id.replace('/', '_')
            evt_id = evt_id.upper()
            id_list.append(evt_id)
        id_list.append('EVENT_ID_MAX')
        id_list_str = ",\n    ".join(id_list)
        enum_id_list="enum {\n    " + id_list_str + "\n};"
        fp.write(enum_id_list)

    def get_field_type_mapping(self, field_type):
        if field_type in self.type_mapping:
            return self.type_mapping[field_type]
        else:
            return 'EVENT_FIELD_TYPE_BYTES'

    def get_field_define_str(self, field_def):
        mb_list = []
        for elm in field_def:
            value = field_def[elm]
            if elm == "name":
                mb_str = f".{elm}=\"{value}\""
            elif elm == "size" or elm == "offset":
                mb_str = f".{elm}={value}"
            elif elm == "type":
                mapped_type = self.get_field_type_mapping(value)
                mb_str = f".{elm}={mapped_type}"
            else:
                continue
            mb_list.append(mb_str)
        mb_list_str = ','.join(mb_list)
        return "{%s}" % mb_list_str

    def get_field_define_name(self, event_name, field_name):
        field_id = f'EVT_FIELD_{event_name}_{field_name}'
        field_id = field_id.replace('/', '_')
        field_id = field_id.upper()
        return field_id

    def save_field_define_list(self, fp):
        for event_name,fields in self.event_fields.items():
            for field in fields:
                field_name = field['name']
                field_id = self.get_field_define_name(event_name, field_name)
                field_def_json = self.get_field_define_str(field)
                field_def_str = f"#define {field_id} {field_def_json}\n"
                fp.write(field_def_str)

    def get_event_schema_name(self, event_name):
        schema_name = f'EVT_SCHEMA_{event_name}'
        schema_name = schema_name.replace('/', '_')
        schema_name = schema_name.upper()
        return schema_name

    def save_event_schema_list(self, fp):
        schema_list = []
        for event_name,fields in self.event_fields.items():
            field_list = []
            schema_name = self.get_event_schema_name(event_name)
            schema_list.append(schema_name)
            event_id = self.get_event_id(event_name)
            for field in fields:
                field_name = field['name']
                field_id = self.get_field_define_name(event_name, field_name)
                field_list.append(field_id)
            field_list_str = ',\\\n        '.join(field_list)
            field_nr = len(field_list)
            schema="""#define %s { \\
        .name = "%s", \\
        .id = %s, \\
        .field_nr = %u,\\
        .fields = { \\
            %s \\
        } \\
    }
""" % (schema_name, event_name, event_id, field_nr, field_list_str)
            fp.write(schema)
        schema_list_str = ',\\\n        '.join(schema_list)
        schema_list_def="""#define EVT_SCHEMA_LIST { \\
        %s \\
}\n
    """ % (schema_list_str)
        fp.write(schema_list_def)

    def save_event_func_list(self, fp):
        fp.write("\n#define EVT_TRACE_FUNC_LIST ")
        for event_name,fields in self.event_fields.items():
            section_name = '"tracepoint/%s"' % event_name
            schema_name = self.get_event_schema_name(event_name)
            func_name = f'func_{event_name}'
            func_name = func_name.replace('/', '_')
            func_name = func_name.lower()
            fp.write("\\\n  ")
            fp.write(f"EVENT_TRACE_FUNC({section_name}, {func_name}, {schema_name})")

    def start_schema(self, fp):
        header="""#ifndef __EVENT_SCHEMA_H__
#define __EVENT_SCHEMA_H__
#include "event.h"
"""
        fp.write(header)

    def end_schema(self, fp):
        footer="\n#endif\n"
        fp.write(footer)

    def save_schemas(self, outfile):
        with open(outfile, "w") as fp:
            self.start_schema(fp)
            self.save_event_id_list(fp)
            fp.write("\n")
            self.save_field_define_list(fp)
            fp.write("\n")
            self.save_event_schema_list(fp)
            self.save_event_func_list(fp)
            self.end_schema(fp)

    def build(self, events, outfile):
        self.event_fields = {}
        for event in events:
            self.parse_event_format(event.strip())
        self.save_schemas(outfile)

if __name__ == '__main__':
    schema = EventSchema()
    events = sys.argv[1].split(',')
    schema.build(events, "test.h")
