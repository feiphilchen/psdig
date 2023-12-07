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
   char          comm[EVENT_COMM_SIZE];
   unsigned char data[0];
};

typedef union event {
    struct event_header hdr;
    char                msg[EVENT_MAX_SIZE];
} event_t;

#define FIELD_NAME_SIZE 64
struct event_field {
    char               name[FIELD_NAME_SIZE];
    unsigned int       offset;
    unsigned int       size;
    event_field_type_t type;
};

#define EVENT_NAME_SIZE 128
#define EVENT_MAX_FIELDS 16
struct event_schema {
   int                id;
   char               name[EVENT_NAME_SIZE];
   unsigned int       field_nr;
   struct event_field fields[EVENT_MAX_FIELDS];
};

union event_sockaddr {
    struct {
       unsigned short  sa_family;
       unsigned short  padding;
       char 	   sa_data[14];
   } raw;
   struct sockaddr_un  un;
   struct sockaddr_in  in;
   struct sockaddr_in6 in6;
   struct sockaddr_nl  nl;
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
    read_event(ctx, &schema); \
    return 0; \
}

#endif
