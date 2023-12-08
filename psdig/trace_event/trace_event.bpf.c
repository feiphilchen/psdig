#define __BPF_PROG__
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

struct bpf_map_def SEC("maps") event_comm_filter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = EVENT_COMM_SIZE,
    .value_size = EVENT_COMM_SIZE,
    .max_entries = 64
};

struct bpf_map_def SEC("maps") exclude_pid_filter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64
};

struct bpf_map_def SEC("maps") syscall_ctx = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(struct syscall_context),
    .max_entries = 2048
};

struct bpf_map_def SEC("maps") tmp_syscall_ctx = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct syscall_context),
    .max_entries = 1
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
        ret = bpf_probe_read_str(data, EVENT_FIELD_MAX_STR_LEN, str);
        if (ret >= 0) {
            evt->hdr.len += ret;
        } else {
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
    #pragma unroll
    for (pos = 0; pos < EVENT_FIELD_STR_LIST_LEN; pos++) {
        str = NULL;
        bpf_probe_read(&str, sizeof(str), pstr + pos);
        if (str == NULL) {
            break;
        }
        if (evt->hdr.len < sizeof(event_t) - EVENT_FIELD_MAX_STR_LEN) {
            data = evt->hdr.len + (void *)evt;
            ret = bpf_probe_read_str(data, EVENT_FIELD_MAX_STR_LEN, str);
            if (ret > 0) {
                evt->hdr.len += ret;
            } else {
                return -1;
            }
        }
    }
    if (evt->hdr.len < sizeof(event_t) - 1) {
        data = evt->hdr.len + (void *)evt;
        *(char *)data = '\0';
        evt->hdr.len += 1;
        return 0;
    }
    return -1;
}

static inline int
read_event_field_sockaddr (void                 * ctx,
                           struct event_field   * field,
                           event_t              * evt)
{
    event_sockaddr_t      * data;
    event_sockaddr_t      * sa;
    __u16                   family;

    if (evt->hdr.len < sizeof(event_t) - sizeof(event_sockaddr_t)) {
        data = evt->hdr.len + (void *)evt;
        bpf_probe_read(&sa, sizeof(event_sockaddr_t *), ctx + field->offset);
        bpf_probe_read(&family, sizeof(family), sa);
        if (family == 0) {
            data->raw.sa_family = 0;
            bpf_probe_read(data->raw.sa_data, sizeof(event_sockaddr_t *), ctx + field->offset);
        } else {
            bpf_probe_read(data, sizeof(event_sockaddr_t), (void *)sa);
        }
        evt->hdr.len += sizeof(event_sockaddr_t);
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

static int
check_comm_filter(char * comm)
{
    int filter_type = EVENT_FILTER_TYPE_COMM;
    int * count, * filter;

    count = bpf_map_lookup_elem(&event_filter_count, &filter_type);
    if (count == NULL) {
        return 0;
    }
    if (*count == 0) {
        return 0;
    }
    filter = bpf_map_lookup_elem(&event_comm_filter, comm);
    if (filter == NULL) {
        return 1;
    }
    return 0;
}


static inline int
read_event (void                * ctx,
            struct event_schema * schema,
            unsigned int          syscall)
{
    struct event_field  * ef;
    int                    zero = 0;
    unsigned int           len = 0, pos = 0;
    void                 * data;
    event_t              * evt;
    int                   filter_out;
    char                  comm[EVENT_COMM_SIZE] = {0};
    evt = bpf_map_lookup_elem(&event_heap, &zero);
    if (evt == NULL) {
        return 0;
    }
    evt->hdr.pid = bpf_get_current_pid_tgid() >>32;
    evt->hdr.tid = bpf_get_current_pid_tgid() & 0xffffffff;
    evt->hdr.gid = bpf_get_current_uid_gid() >> 32;
    evt->hdr.uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt->hdr.ktime_ns = bpf_ktime_get_ns();
    evt->hdr.flags = 0;
    evt->hdr.duration = 0;
    if (syscall) {
        evt->hdr.flags = EVENT_FLAGS_SYSCALL;
        evt->hdr.ret_id = -1;
    }
    bpf_get_current_comm(comm, sizeof(comm));
    filter_out = check_pid_filter(evt->hdr.pid);
    if (filter_out > 0) {
        return 0;
    }
    filter_out = check_uid_filter(evt->hdr.uid);
    if (filter_out > 0) {
        return 0;
    }
   
    filter_out = check_comm_filter(comm);
    if (filter_out > 0) {
        return 0;
    }
    bpf_get_current_comm(evt->hdr.comm, sizeof(evt->hdr.comm));
    evt->hdr.len = sizeof(struct event_header);
    evt->hdr.id = schema->id;
    #pragma unroll
    for (pos = 0;  pos < schema->field_nr; pos++) {
        ef = &schema->fields[pos];
        if (ef->skip) {
           continue;
        }
        if (ef->type == EVENT_FIELD_TYPE_INT ||
            ef->type == EVENT_FIELD_TYPE_UINT ||
            ef->type == EVENT_FIELD_TYPE_BYTES ||
            ef->type == EVENT_FIELD_TYPE_PTR) {
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

static inline int
syscall_start (void                * ctx,
              struct event_schema * schema)
{
    int                        zero = 0;
    struct syscall_context   * tmp_sc;
    unsigned int               pid, tid, uid;
    int                        filter_out;
    char                       comm[EVENT_COMM_SIZE] = {0};
    __u64                      ktime_ns;
    unsigned int               len = 0, pos = 0;
    struct event_field       * ef;
    int                        ret;

    ktime_ns = bpf_ktime_get_ns();
    pid = bpf_get_current_pid_tgid() >>32;
    tid = bpf_get_current_pid_tgid() & 0xffffffff;
    uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(comm, sizeof(comm));
    filter_out = check_pid_filter(pid);
    if (filter_out > 0) {
        return 0;
    }
    filter_out = check_uid_filter(uid);
    if (filter_out > 0) {
        return 0;
    }
   
    filter_out = check_comm_filter(comm);
    if (filter_out > 0) {
        return 0;
    }
    tmp_sc = bpf_map_lookup_elem(&tmp_syscall_ctx, &zero);
    if (tmp_sc == NULL) {
        return 0;
    }
    tmp_sc->ktime_ns = ktime_ns;
    #pragma unroll
    for (pos = 0;  pos < schema->field_nr; pos++) {
        ef = &schema->fields[pos];
        len += ef->size;
    }
    ret = bpf_probe_read(tmp_sc->data, len, ctx);
    bpf_map_update_elem(&syscall_ctx, &tid, tmp_sc, BPF_ANY);
    return 0;
}

static inline int
syscall_finish (void                * ctx,
               struct event_schema * start_schema,
               struct event_schema * exit_schema)
{
    struct event_field  * ef;
    int                    zero = 0;
    unsigned int           len = 0, pos = 0;
    void                 * data;
    event_t              * evt;
    int                   filter_out;
    struct syscall_context   * sc;
    char                  comm[EVENT_COMM_SIZE] = {0};
    __u64                 ktime_ns;

    ktime_ns = bpf_ktime_get_ns();
    evt = bpf_map_lookup_elem(&event_heap, &zero);
    if (evt == NULL) {
        return 0;
    }
    evt->hdr.pid = bpf_get_current_pid_tgid() >>32;
    evt->hdr.tid = bpf_get_current_pid_tgid() & 0xffffffff;
    evt->hdr.gid = bpf_get_current_uid_gid() >> 32;
    evt->hdr.uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt->hdr.ktime_ns = bpf_ktime_get_ns();
    evt->hdr.flags = EVENT_FLAGS_SYSCALL;
    evt->hdr.ret_id = -1;
    bpf_get_current_comm(comm, sizeof(comm));
    filter_out = check_pid_filter(evt->hdr.pid);
    if (filter_out > 0) {
        return 0;
    }
    filter_out = check_uid_filter(evt->hdr.uid);
    if (filter_out > 0) {
        return 0;
    }
    filter_out = check_comm_filter(comm);
    if (filter_out > 0) {
        return 0;
    }
    bpf_get_current_comm(evt->hdr.comm, sizeof(evt->hdr.comm));
    evt->hdr.len = sizeof(struct event_header);
    evt->hdr.id = start_schema->id;
    sc = bpf_map_lookup_elem(&syscall_ctx, &evt->hdr.tid);
    if (sc == NULL) {
        return 0;
    }
    evt->hdr.ktime_ns = sc->ktime_ns;
    evt->hdr.duration = ktime_ns - sc->ktime_ns;
    #pragma unroll
    for (pos = 0;  pos < start_schema->field_nr; pos++) {
        ef = &start_schema->fields[pos];
        if (ef->skip) {
           continue;
        }
        if (ef->type == EVENT_FIELD_TYPE_INT ||
            ef->type == EVENT_FIELD_TYPE_UINT ||
            ef->type == EVENT_FIELD_TYPE_BYTES ||
            ef->type == EVENT_FIELD_TYPE_PTR) {
            read_event_field_bytes(sc->data, ef, evt);
        } else if (ef->type == EVENT_FIELD_TYPE_STR) {
            read_event_field_string(sc->data, ef, evt);
        } else if (ef->type == EVENT_FIELD_TYPE_STR_LIST) {
            read_event_field_string_list(sc->data, ef, evt);
        } else if (ef->type == EVENT_FIELD_TYPE_SOCKADDR) { 
            read_event_field_sockaddr(sc->data, ef, evt);
        }
    }
    if (exit_schema != NULL) {
    #pragma unroll
        for (pos = 0;  pos < exit_schema->field_nr; pos++) {
            ef = &exit_schema->fields[pos];
            if (ef->skip) {
                continue;
            }
            if (ef->type == EVENT_FIELD_TYPE_INT ||
                ef->type == EVENT_FIELD_TYPE_UINT ||
                ef->type == EVENT_FIELD_TYPE_BYTES ||
                ef->type == EVENT_FIELD_TYPE_PTR) {
                read_event_field_bytes(ctx, ef, evt);
            }
        }
        evt->hdr.ret_id = exit_schema->id;
    }
    evt->hdr.len &= EVENT_MAX_SIZE - 1;
    bpf_perf_event_output(ctx, &perf_evt_buffer, BPF_F_CURRENT_CPU, evt, evt->hdr.len);
    return 0;
}

