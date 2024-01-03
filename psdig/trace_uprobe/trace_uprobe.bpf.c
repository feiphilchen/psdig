/* 
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Author: feiphilchen@gmail.com
 */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/perf_event.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "uprobe.h"

char _license[] SEC("license") = "GPL";

#define uprobe_bpf_printk(level, fmt,...) do {\
        if ((level) > 0) { \
           char ___fmt[] = fmt; \
            bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);\
        }\
} while(0)

struct bpf_map_def SEC("maps") perf_evt_buffer = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 1024
};

struct bpf_map_def SEC("maps") trace_heap = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(trace_t)*2,
    .max_entries = 1
};

struct bpf_map_def SEC("maps") trace_filter_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = TRACE_FILTER_TYPE_MAX
};

struct bpf_map_def SEC("maps") trace_pid_filter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64
};

struct bpf_map_def SEC("maps") trace_uid_filter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64
};

struct bpf_map_def SEC("maps") trace_comm_filter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = TRACE_COMM_SIZE,
    .value_size = TRACE_COMM_SIZE,
    .max_entries = 64
};

struct bpf_map_def SEC("maps") exclude_pid_filter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64
};

struct bpf_map_def SEC("maps") stackmap = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(__u32),
	.value_size = PERF_MAX_STACK_DEPTH * sizeof(__u64),
	.max_entries = 10000,
};
#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK | BPF_F_REUSE_STACKID)

static int
check_pid_filter(unsigned int pid)
{
    int filter_type = TRACE_FILTER_TYPE_PID;
    int * count, * filter;

    filter = bpf_map_lookup_elem(&exclude_pid_filter, &pid);
    if (filter != NULL) {
        return 1;
    }
    count = bpf_map_lookup_elem(&trace_filter_count, &filter_type);
    if (count == NULL) {
        return 0;
    }
    if (*count == 0) {
        return 0;
    }
    filter = bpf_map_lookup_elem(&trace_pid_filter, &pid);
    if (filter == NULL) {
        return 1;
    }
    return 0;
}

static int
check_uid_filter(unsigned int uid)
{
    int filter_type = TRACE_FILTER_TYPE_UID;
    int * count, * filter;

    count = bpf_map_lookup_elem(&trace_filter_count, &filter_type);
    if (count == NULL) {
        return 0;
    }
    if (*count == 0) {
        return 0;
    }
    filter = bpf_map_lookup_elem(&trace_uid_filter, &uid);
    if (filter == NULL) {
        return 1;
    }
    return 0;
}

static int
check_comm_filter(char * comm)
{
    int filter_type = TRACE_FILTER_TYPE_COMM;
    int * count, * filter;

    count = bpf_map_lookup_elem(&trace_filter_count, &filter_type);
    if (count == NULL) {
        return 0;
    }
    if (*count == 0) {
        return 0;
    }
    filter = bpf_map_lookup_elem(&trace_comm_filter, comm);
    if (filter == NULL) {
        return 1;
    }
    return 0;
}

static inline int
trace_add_str (trace_t * t, char * str)
{
    trace_data_t * data;
    __u32          buf_len;
    int            ret;
    void         * buf;

    if (str == NULL) {
        return -1;
    }
    if (t->hdr.len < TRACE_MAX_SIZE - sizeof(trace_data_t)) {
        data = (trace_data_t *)(t->hdr.len + (void *)t);
        data->type = TRACE_DATA_TYPE_STR;
        t->hdr.len += sizeof(trace_data_t);
        t->hdr.len &= TRACE_MAX_SIZE -1;
        buf_len = TRACE_MAX_SIZE - t->hdr.len;
        buf = t->hdr.len + (void *)t;
        ret = bpf_probe_read_str(buf, buf_len, (void *)str);
        if (ret < 0) {
            return -1;
        }
        data->len = ret;
        t->hdr.len += ret;
        return 0;
    }
    return -1;
}

static inline int
trace_add (trace_t * t, void * addr, __u32 len, trace_field_type_t type)
{   
    trace_data_t * data;
    int            ret;

    if (t->hdr.len + sizeof(trace_data_t) + len <= sizeof(trace_t)) {
        data = (trace_data_t *)(t->hdr.len + (void *)t);
        data->type = type;
        ret = bpf_probe_read(data->value, len, (void *)addr);
        if (ret < 0) {
            return -1;
        }
        data->len = len;
        t->hdr.len += len + sizeof(trace_data_t);
        return 0;
    }
    return -1;
}

static inline int
trace_add_obj (trace_t * t, __u32 field_num)
{
    trace_data_t * data;
    int            ret;

    if (t->hdr.len + sizeof(trace_data_t) <= sizeof(trace_t)) {
        data = (trace_data_t *)(t->hdr.len + (void *)t);
        data->type = TRACE_DATA_TYPE_OBJECT;
        data->len = field_num;
        t->hdr.len += sizeof(trace_data_t);
        return 0;
    }
    return -1;
}

static inline int
read_bytes (trace_t * t, void * addr, __u32 size, char * field)
{
    void * data;
    if (t->hdr.len < sizeof(trace_t) - size) {
        data = t->hdr.len + (void *)t;
        bpf_probe_read(data, size, addr);
        t->hdr.len += size;
    }
    return 0;
}

static inline int
read_ptr (trace_t * t, void * addr, char * field)
{
    if (trace_add_str(t, field) < 0) {
        return -1;
    }
    if (trace_add(t, addr, sizeof(void *), TRACE_DATA_TYPE_PTR) < 0) {
        return -1;
    }
    return 0;
}

static inline int
read_int (trace_t * t, void * addr, __u32 size, char * field)
{
    if (trace_add_str(t, field) < 0) {
        return -1;
    }
    if (trace_add(t, addr, size, TRACE_DATA_TYPE_INT) < 0) {
        return -1;
    }
    return 0;
}

static inline int
read_uint (trace_t * t, void * addr, __u32 size, char * field)
{
    if (trace_add_str(t, field) < 0) {
        return -1;
    }
    if (trace_add(t, addr, size, TRACE_DATA_TYPE_UINT) < 0) {
        return -1;
    }
    return 0;
}

static inline int
read_float (trace_t * t, void * addr, __u32 size, char * field)
{
    if (trace_add_str(t, field) < 0) {
        return -1;
    }
    if (trace_add(t, addr, size, TRACE_DATA_TYPE_FLOAT) < 0) {
        return -1;
    }
    return 0;
}

static inline int
__read_str (trace_t * t, char * str, char * field)
{
    if (trace_add_str(t, field) < 0) {
        return -1;
    }
    if (trace_add_str(t, str) < 0) {
        if (trace_add(t, &str, sizeof(void *), TRACE_DATA_TYPE_PTR) < 0) {
            return -1;
        }
        return 0;
    }
    return 0;
}

static inline int
obj_start (trace_t * t, __u32 field_cnt)
{
    if (trace_add(t, &field_cnt, sizeof(void *), TRACE_DATA_TYPE_PTR) < 0) {
        return -1;
    }
    return 0;
}

static trace_t *
__trace_init (void *ctx, __u32 id)
{
    trace_t    * trace;
    int          zero = 0;
    int          filter_out;
    char         comm[TRACE_COMM_SIZE] = {0};
    
    trace = bpf_map_lookup_elem(&trace_heap, &zero);
    if (trace == NULL) {
        return NULL;
    }
    trace->hdr.id = id;
    trace->hdr.pid = bpf_get_current_pid_tgid() >>32;
    trace->hdr.tid = bpf_get_current_pid_tgid() & 0xffffffff;
    trace->hdr.gid = bpf_get_current_uid_gid() >> 32;
    trace->hdr.uid = bpf_get_current_uid_gid() & 0xffffffff;
    trace->hdr.ktime_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(trace->hdr.comm, sizeof(trace->hdr.comm));
    bpf_get_current_comm(comm, sizeof(comm));
    trace->hdr.len = sizeof(struct trace_header);
    filter_out = check_pid_filter(trace->hdr.pid);
    if (filter_out > 0) {
        return NULL;
    }
    filter_out = check_uid_filter(trace->hdr.uid);
    if (filter_out > 0) {
        return NULL;
    }
    filter_out = check_comm_filter(comm);
    if (filter_out > 0) {
        return NULL;
    }
#ifdef __PSDIG_KSTACK__
    trace->hdr.kstack = bpf_get_stackid(ctx, &stackmap, KERN_STACKID_FLAGS);
#else
    trace->hdr.kstack = -1;   
#endif
#ifdef __PSDIG_USTACK__
    trace->hdr.ustack = bpf_get_stackid(ctx, &stackmap, USER_STACKID_FLAGS);
#else
    trace->hdr.ustack = -1;
#endif
    return trace;
}

#define trace_init(ctx, t, id) do { \
   (t) = __trace_init(ctx, id); \
   if ((t) == NULL) {  \
       return 0; \
   } \
} while(0)

#define read_str(t, str, field) do { \
    __read_str(t, (char *)str, field); \
} while(0)

void
trace_send (void *ctx, trace_t * trace)
{
    trace->hdr.len &= TRACE_MAX_SIZE - 1;
    bpf_perf_event_output(ctx, &perf_evt_buffer, BPF_F_CURRENT_CPU, trace, trace->hdr.len);
}


#define uprobe_enter_start(id) \
   trace_t    * t; \
   trace_init(ctx, t, id);

#define uprobe_enter_finish() \
   trace_send(ctx, t);

#define uprobe_ret_start(id) \
   trace_t    * t; \
   trace_init(ctx, t, id);

#define uprobe_ret_finish() \
   trace_send(ctx, t);

