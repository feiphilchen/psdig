#ifndef __UPROBE_H__
#define __UPROBE_H__

#define TRACE_MAX_SIZE 4096
#define TRACE_COMM_SIZE 32

struct trace_header {
   unsigned int  id;
   unsigned int  len;
   unsigned int  pid;
   unsigned int  tid;
   unsigned int  uid;
   unsigned int  gid;
   __u64         ktime_ns;
   char          comm[TRACE_COMM_SIZE];
   unsigned char data[0];
};

typedef union trace {
    struct trace_header hdr;
    char                msg[TRACE_MAX_SIZE];
} trace_t;

typedef enum {
   TRACE_FILTER_TYPE_PID = 0,
   TRACE_FILTER_TYPE_UID,
   TRACE_FILTER_TYPE_MAX
} TRACE_filter_type_t;

typedef enum {
   TRACE_DATA_TYPE_INT = 0,
   TRACE_DATA_TYPE_UINT,
   TRACE_DATA_TYPE_STR,
   TRACE_DATA_TYPE_FLOAT,
   TRACE_DATA_TYPE_PTR,
   TRACE_DATA_TYPE_ARRAY,
   TRACE_DATA_TYPE_OBJECT,
   TRACE_DATA_TYPE_BYTES
} trace_field_type_t;

typedef struct trace_data {
    trace_field_type_t type;
    unsigned int       len;
    unsigned char      value[0];
} trace_data_t;

#define TRACE_DATA_MAX_STR_LEN 512
#define TRACE_DATA_MAX_BYTES_LEN 512

#endif
