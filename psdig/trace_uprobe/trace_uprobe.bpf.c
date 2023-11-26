#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "uprobe.h"

char _license[] SEC("license") = "GPL";

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

struct bpf_map_def SEC("maps") exclude_pid_filter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64
};

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


static inline int
trace_add_str (trace_t * t, char * str)
{
    trace_data_t * data;
    __u32          buf_len;
    int            ret;
    void         * buf;

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
__read_str (trace_t * t, char * str, char * field)
{
    if (trace_add_str(t, field) < 0) {
        return -1;
    }
    if (trace_add_str(t, str) < 0) {
        return -1;
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
__trace_init (__u32 id)
{
    trace_t    * trace;
    int          zero = 0;
    int          filter_out;

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
    trace->hdr.len = sizeof(struct trace_header);
    filter_out = check_pid_filter(trace->hdr.pid);
    if (filter_out > 0) {
        return NULL;
    }
    filter_out = check_uid_filter(trace->hdr.uid);
    if (filter_out > 0) {
        return NULL;
    }
    return trace;
}

#define trace_init(t, id) do { \
   (t) = __trace_init(id); \
   if ((t) == NULL) {  \
       return 0; \
   } \
} while(0)

#define read_str(t, str, field) __read_str(t, (char *)str, field)

void
trace_send (void *ctx, trace_t * trace)
{
    trace->hdr.len &= TRACE_MAX_SIZE - 1;
    bpf_perf_event_output(ctx, &perf_evt_buffer, BPF_F_CURRENT_CPU, trace, trace->hdr.len);
}

#define uprobe_enter_start(id) \
   trace_t    * t; \
   trace_init(t, id);

#define uprobe_enter_finish() \
   trace_send(ctx, t);

#define uprobe_ret_start(id) \
   trace_t    * t; \
   trace_init(t, id);
#define uprobe_ret_finish() \
   trace_send(ctx, t);

