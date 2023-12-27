/* 
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Author: feiphilchen@gmail.com
 */
#ifndef __EVENT_H__
#define __EVENT_H__

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/netlink.h>

typedef enum {
   EVENT_FIELD_TYPE_INT,
   EVENT_FIELD_TYPE_UINT,
   EVENT_FIELD_TYPE_STR,
   EVENT_FIELD_TYPE_INT_LIST,
   EVENT_FIELD_TYPE_STR_LIST,
   EVENT_FIELD_TYPE_SOCKADDR,
   EVENT_FIELD_TYPE_PTR,
   EVENT_FIELD_TYPE_BYTES
} event_field_type_t;

typedef enum {
   EVENT_FILTER_TYPE_PID = 0,
   EVENT_FILTER_TYPE_UID,
   EVENT_FILTER_TYPE_COMM,
   EVENT_FILTER_TYPE_MAX
} event_filter_type_t;

#define EVENT_MAX_SIZE 4096
#define EVENT_COMM_SIZE 32
struct event_header {
   unsigned int  id;
   unsigned int  len;
   unsigned int  pid;
   unsigned int  tid;
   unsigned int  uid;
   unsigned int  gid;
   __u64         ktime_ns;
#define EVENT_FLAGS_SYSCALL 0x01
   unsigned int  flags;
   __u64         duration;
   int           ret_id;
   char          comm[EVENT_COMM_SIZE];
};

typedef union event {
    struct event_header hdr;
    char                msg[EVENT_MAX_SIZE];
} event_t;

#ifndef __BPF_PROG__
#define F_NAME_INIT(n) .name = n,
#else
#define F_NAME_INIT(n)
#endif

#define FIELD_NAME_SIZE 32
struct event_field {
#ifndef __BPF_PROG__
    char               name[FIELD_NAME_SIZE];
#endif
    unsigned short       offset;
    unsigned short       size;
    unsigned short       skip;
    event_field_type_t type;
};

#ifndef __BPF_PROG__
#define SCHEMA_NAME_INIT(n) .name = n,
#else
#define SCHEMA_NAME_INIT(n)
#endif

#define EVENT_NAME_SIZE 64
#define EVENT_MAX_FIELDS 24
struct event_schema {
   int                id;
#ifndef __BPF_PROG__
   char               name[EVENT_NAME_SIZE];
#endif
   unsigned int       field_nr;
   struct event_field fields[EVENT_MAX_FIELDS];
};

union event_sockaddr {
    struct {
       unsigned short  sa_family;
       char 	   sa_data[16];
   } raw;
   struct sockaddr_un  un;
   struct sockaddr_in  in;
   struct sockaddr_in6 in6;
   struct sockaddr_nl  nl;
};

struct syscall_context {
    __u64         ktime_ns;
    unsigned char data[1024];
};

typedef union event_sockaddr event_sockaddr_t;

#define EVENT_FIELD_MAX_STR_LEN 128
#define EVENT_FIELD_STR_LIST_LEN 32
#define EVENT_FIELD_MAX_BYTES_LEN 512

#define EVENT_TRACE_FUNC(_sec, _func, _schema) \
SEC(_sec) \
int _func(void *ctx) \
{ \
    struct event_schema schema = _schema; \
    read_event(ctx, &schema, 0); \
    return 0; \
}

#define SYSCALL_START_FUNC(_sec, _func, _schema, _noexit) \
SEC(_sec) \
int _func(void *ctx) \
{ \
    struct event_schema start_schema = _schema; \
    if (_noexit) { \
        read_event(ctx, &start_schema, 1); \
    } else {\
        syscall_start(ctx, &start_schema); \
    }\
    return 0; \
}

#define SYSCALL_FINISH_FUNC(_sec, _func, _enter_schema, _exit_schema) \
SEC(_sec) \
int _func(void *ctx) \
{ \
    struct event_schema finish_enter_schema = _enter_schema; \
    struct event_schema finish_exit_schema = _exit_schema; \
    syscall_finish(ctx, &finish_enter_schema, &finish_exit_schema); \
    return 0; \
}
#endif
