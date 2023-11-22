#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "event_schema.h"

char _license[] SEC("license") = "GPL";

#define event_bpf_printk(level, fmt,...) do {\
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

struct bpf_map_def SEC("maps") event_heap = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(event_t),
    .max_entries = 1
};

struct bpf_map_def SEC("maps") event_schemas = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct event_schema),
    .max_entries = 512
};

struct bpf_map_def SEC("maps") event_filter_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = EVENT_FILTER_TYPE_MAX
};

struct bpf_map_def SEC("maps") event_pid_filter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64
};

struct bpf_map_def SEC("maps") event_uid_filter = {
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

static inline int
read_event_field_bytes (void                 * ctx, 
                        struct event_field   * field,
                        event_t              * evt)
{
    void * data;

    if (evt->hdr.len < sizeof(event_t) - field->size) {
        data = evt->hdr.len + (void *)evt;
        bpf_probe_read(data, field->size, ctx + field->offset);
        evt->hdr.len += field->size;
    }
    return 0;
}

static inline int
read_event_field_string (void                 * ctx,
                         struct event_field   * field,
                         event_t              * evt)
{
    void * data;
    char * str;
    long   ret;
    bpf_probe_read(&str, sizeof(str), ctx + field->offset);
    if (evt->hdr.len < sizeof(event_t) - EVENT_FIELD_MAX_STR_LEN) {
        data = evt->hdr.len + (void *)evt;
        //event_bpf_printk(1, "read_event_field_string_ %lx\n",(__u64)str);
        ret = bpf_probe_read_str(data, EVENT_FIELD_MAX_STR_LEN, str);
        if (ret >= 0) {
            evt->hdr.len += ret;
        } else {
            //event_bpf_printk(1, "read string error %d\n", ret);
            return -1;
        }
    }
    return -1;
}

static inline int
read_event_field_string_list (void                 * ctx,
                              struct event_field   * field,
                              event_t              * evt)
{
    void  * data;
    char ** pstr;
    char * str;
    long   ret;
    unsigned int pos;

    bpf_probe_read(&pstr, sizeof(pstr), ctx + field->offset);
    event_bpf_printk(1, "read_event_field_string_list %lx\n",(__u64)pstr);
    #pragma unroll
    for (pos = 0; pos < EVENT_FIELD_STR_LIST_LEN; pos++) {
        str = NULL;
        bpf_probe_read(&str, sizeof(str), pstr + pos);
        if (str == NULL) {
            event_bpf_printk(1, "error read str ptr\n");
            break;
        }
        if (evt->hdr.len < sizeof(event_t) - EVENT_FIELD_MAX_STR_LEN) {
            data = evt->hdr.len + (void *)evt;
            ret = bpf_probe_read_str(data, EVENT_FIELD_MAX_STR_LEN, str);
            if (ret > 0) {
                evt->hdr.len += ret;
            } else {
                event_bpf_printk(1, "error bpf_probe_read_user_str:%d\n", ret);
                return -1;
            }
        }
    }
    if (evt->hdr.len < sizeof(event_t) - 1) {
        data = evt->hdr.len + (void *)evt;
        *(char *)data = '\0';
        evt->hdr.len += 1;
        //event_bpf_printk(1, "null\n");
        return 0;
    }
    return -1;
}

static inline int
read_event_field_sockaddr (void                 * ctx,
                           struct event_field   * field,
                           event_t              * evt)
{
    void                  * data;
    struct event_sockaddr * sa;

    if (evt->hdr.len < sizeof(event_t) - sizeof(struct event_sockaddr)) {
        data = evt->hdr.len + (void *)evt;
        bpf_probe_read(&sa, sizeof(struct event_sockaddr *), ctx + field->offset);
        bpf_probe_read(data, sizeof(struct event_sockaddr), (void *)sa);
        evt->hdr.len += sizeof(struct event_sockaddr);
    }
    return 0;
}

static int
check_pid_filter(unsigned int pid)
{
    int filter_type = EVENT_FILTER_TYPE_PID;
    int * count, * filter;

    filter = bpf_map_lookup_elem(&exclude_pid_filter, &pid);
    if (filter != NULL) {
        return 1;
    }
    count = bpf_map_lookup_elem(&event_filter_count, &filter_type);
    if (count == NULL) {
        return 0;
    }
    if (*count == 0) {
        return 0;
    }
    filter = bpf_map_lookup_elem(&event_pid_filter, &pid);
    if (filter == NULL) {
        return 1;
    }
    return 0;
}

static int
check_uid_filter(unsigned int uid)
{
    int filter_type = EVENT_FILTER_TYPE_UID;
    int * count, * filter;

    count = bpf_map_lookup_elem(&event_filter_count, &filter_type);
    if (count == NULL) {
        return 0;
    }
    if (*count == 0) {
        return 0;
    }
    filter = bpf_map_lookup_elem(&event_uid_filter, &uid);
    if (filter == NULL) {
        return 1;
    }
    return 0;
}

static inline int
read_event (void                * ctx,
            struct event_schema * schema)
{
    struct event_field  * ef;
    int                    zero = 0;
    unsigned int           len = 0, pos = 0;
    void                 * data;
    event_t              * evt;
    int                   filter_out;

    evt = bpf_map_lookup_elem(&event_heap, &zero);
    if (evt == NULL) {
        return 0;
    }
    evt->hdr.pid = bpf_get_current_pid_tgid() >>32;
    evt->hdr.gid = bpf_get_current_uid_gid() >> 32;
    evt->hdr.uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt->hdr.ktime_ns = bpf_ktime_get_ns();
    filter_out = check_pid_filter(evt->hdr.pid);
    if (filter_out > 0) {
        return 0;
    }
    filter_out = check_uid_filter(evt->hdr.uid);
    if (filter_out > 0) {
        return 0;
    }
    bpf_get_current_comm(evt->hdr.comm, sizeof(evt->hdr.comm));
    evt->hdr.len = sizeof(struct event_header);
    evt->hdr.id = schema->id;
    #pragma unroll
    for (pos = 0;  pos < schema->field_nr; pos++) {
        ef = &schema->fields[pos];
        if (ef->type == EVENT_FIELD_TYPE_INT ||
            ef->type == EVENT_FIELD_TYPE_BYTES) {
            read_event_field_bytes(ctx, ef, evt);
        } else if (ef->type == EVENT_FIELD_TYPE_STR) {
            read_event_field_string(ctx, ef, evt);
        } else if (ef->type == EVENT_FIELD_TYPE_STR_LIST) {
            read_event_field_string_list(ctx, ef, evt);
        } else if (ef->type == EVENT_FIELD_TYPE_SOCKADDR) { 
            read_event_field_sockaddr(ctx, ef, evt);
        }
    }
    evt->hdr.len &= EVENT_MAX_SIZE - 1;
    bpf_perf_event_output(ctx, &perf_evt_buffer, BPF_F_CURRENT_CPU, evt, evt->hdr.len);
    return 0;
}

#if 0
SEC("tracepoint/syscalls/sys_enter_execve")
int execve_trace(void *ctx)
{
    struct event_schema schema = EVT_SCHEMA_SYSCALLS_SYS_ENTER_EXECVE;
    read_event(ctx, &schema);
    return 0;
}
#endif
