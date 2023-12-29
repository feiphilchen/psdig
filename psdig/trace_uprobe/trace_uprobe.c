/* 
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Author: feiphilchen@gmail.com
 */
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/types.h>
#include <json-c/json.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "uprobe.h"

#define MAX_UPROBE_TRACE 64
#define MAX_PID_FILTER 32
#define MAX_UID_FILTER 32
#define MAX_COMM_FILTER 32
struct uprobe {
    char * obj;
    char * path;
    __u64  addr;
};

struct uprobe uprobe_trace[MAX_UPROBE_TRACE];
unsigned int pid_filter[MAX_PID_FILTER];
unsigned int uid_filter[MAX_UID_FILTER];
unsigned int pid_exclude[MAX_PID_FILTER];
void *  comm_filter[MAX_COMM_FILTER];
unsigned int pid_filter_count = 0;
unsigned int pid_exclude_count = 0;
unsigned int uid_filter_count = 0;
unsigned int comm_filter_count = 0;
unsigned int uprobe_trace_count = 0;
pthread_mutex_t print_mutex;

/* set rlimit (required for every app) */
static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur       = RLIM_INFINITY,
        .rlim_max       = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}


static int libbpf_print(enum libbpf_print_level level, const char *format,
                     va_list args)
{
        if (level == LIBBPF_DEBUG || level == LIBBPF_INFO)
                return 0;

        return vfprintf(stderr, format, args);
}

int
init_pid_filter (struct bpf_object * bo)
{
    unsigned int pos;
    int         updated, filter_count_fd, filter_fd;
    unsigned int filter_type = TRACE_FILTER_TYPE_PID;
    pid_t       pid;

    filter_fd = bpf_object__find_map_fd_by_name(bo, "exclude_pid_filter");
    if (filter_fd < 0) {
         fprintf(stderr, "ERROR: bpf_object__find_map_fd_by_name failed\n");
         return -EINVAL;
    }
    for (pos = 0; pos < pid_exclude_count; pos++) {
        updated = bpf_map_update_elem(filter_fd, &pid_exclude[pos], &pid_exclude[pos], BPF_ANY);
        if (updated < 0) {
             fprintf(stderr, "failed to update pid to exclude: id=%u, %s\n",
                 pid_exclude[pos], strerror(errno));
             return -EINVAL;
        }
    }
    pid = getpid();
    updated = bpf_map_update_elem(filter_fd, &pid, &pid, BPF_ANY);
    if (updated < 0) {
         fprintf(stderr, "failed to update self pid to exclude: id=%u, %s\n",
              pid, strerror(errno));
    }
    filter_count_fd = bpf_object__find_map_fd_by_name(bo, "trace_filter_count");
    if (filter_count_fd < 0) {
         fprintf(stderr, "ERROR: bpf_object__find_map_fd_by_name failed\n");
         return -EINVAL;
    }
    updated = bpf_map_update_elem(filter_count_fd, &filter_type, &pid_filter_count, BPF_ANY);
    if (pid_filter_count == 0) {
        return 0;
    }
    filter_fd = bpf_object__find_map_fd_by_name(bo, "trace_pid_filter");
    for (pos = 0; pos < pid_filter_count; pos++) {
        updated = bpf_map_update_elem(filter_fd, &pid_filter[pos], &pid_filter[pos], BPF_ANY);
        if (updated < 0) {
             fprintf(stderr, "failed to update pid filter: id=%u, %s\n",
                 pid_filter[pos], strerror(errno));
             return -EINVAL;
        }
    }
    return 0;
}

int
init_uid_filter (struct bpf_object * bo)
{
    unsigned int pos;
    int         updated, filter_count_fd, filter_fd;
    unsigned int filter_type = TRACE_FILTER_TYPE_UID;

    filter_count_fd = bpf_object__find_map_fd_by_name(bo, "trace_filter_count");
    if (filter_count_fd < 0) {
         fprintf(stderr, "ERROR: bpf_object__find_map_fd_by_name failed\n");
         return -EINVAL;
    }
    updated = bpf_map_update_elem(filter_count_fd, &filter_type, &uid_filter_count, BPF_ANY);
    if (uid_filter_count == 0) {
        return 0;
    }
    filter_fd = bpf_object__find_map_fd_by_name(bo, "trace_uid_filter");
    for (pos = 0; pos < uid_filter_count; pos++) {
        updated = bpf_map_update_elem(filter_fd, &uid_filter[pos], &uid_filter[pos], BPF_ANY);
        if (updated < 0) {
             fprintf(stderr, "failed to update uid filter: id=%u, %s\n",
                 uid_filter[pos], strerror(errno));
             return -EINVAL;
        }
    }
    return 0;
}

int
init_comm_filter (struct bpf_object * bo)
{
    unsigned int pos;
    int         updated, filter_count_fd, filter_fd;
    unsigned int filter_type = TRACE_FILTER_TYPE_COMM;

    filter_count_fd = bpf_object__find_map_fd_by_name(bo, "trace_filter_count");
    if (filter_count_fd < 0) {
         fprintf(stderr, "ERROR: bpf_object__find_map_fd_by_name failed\n");
         return -EINVAL;
    }
    updated = bpf_map_update_elem(filter_count_fd, &filter_type, &comm_filter_count, BPF_ANY);
    if (comm_filter_count == 0) {
        return 0;
    }
    filter_fd = bpf_object__find_map_fd_by_name(bo, "trace_comm_filter");
    for (pos = 0; pos < comm_filter_count; pos++) {
        updated = bpf_map_update_elem(filter_fd, comm_filter[pos], comm_filter[pos], BPF_ANY);
        if (updated < 0) {
             fprintf(stderr, "failed to update comm filter: id=%s, %s\n",
                 (char *)comm_filter[pos], strerror(errno));
             return -EINVAL;
        }
    }
    return 0;
}

static  int 
trace_read_str (trace_data_t * data, 
                char          * buf, 
                unsigned int    buf_len)
{
    strncpy(buf, data->value, buf_len);
    return data->len + sizeof(trace_data_t);
}

static  int
trace_read_uint (trace_data_t * data,
                struct json_object   * jobj,
                char           * field_name)
{
    unsigned int ulen;
    uint8_t   u8;
    uint16_t  u16;
    uint32_t  u32;
    uint64_t  u64;

    ulen = data->len;
    if (ulen == 1) {
        memcpy(&u8, data->value, ulen);
        json_object_object_add(jobj, field_name, json_object_new_uint64((uint64_t)u8));
    } else if (ulen == 2) {
        memcpy(&u16, data->value, ulen);
        json_object_object_add(jobj, field_name, json_object_new_uint64((uint64_t)u16));
    } else if (ulen == 4) {
        memcpy(&u32, data->value, ulen);
        json_object_object_add(jobj, field_name, json_object_new_uint64((uint64_t)u32));
    } else if (ulen == 8) {
        memcpy(&u64, data->value, ulen);
        json_object_object_add(jobj, field_name, json_object_new_uint64((uint64_t)u64));
    } else {
        return -EINVAL;
    }
    return data->len + sizeof(trace_data_t);
}

static  int
trace_read_int (trace_data_t * data,
               struct json_object   * jobj,
               char           * field_name)
{
    unsigned int ulen;
    int8_t   i8;
    int16_t  i16;
    int32_t  i32;
    int64_t  i64;

    ulen = data->len;
    if (ulen == 1) {
        memcpy(&i8, data->value, ulen);
        json_object_object_add(jobj, field_name, json_object_new_int64((int64_t)i8));
    } else if (ulen == 2) {
        memcpy(&i16, data->value, ulen);
        json_object_object_add(jobj, field_name, json_object_new_int64((int64_t)i16));
    } else if (ulen == 4) {
        memcpy(&i32, data->value, ulen);
        json_object_object_add(jobj, field_name, json_object_new_int64((int64_t)i32));
    } else if (ulen == 8) {
        memcpy(&i64, data->value, ulen);
        json_object_object_add(jobj, field_name, json_object_new_int64((int64_t)i64));
    } else {
        return -EINVAL;
    }
    return data->len + sizeof(trace_data_t);
}

static  int
trace_read_float (trace_data_t         * data,
                  struct json_object   * jobj,
                  char                 * field_name)
{
    unsigned int ulen;
    float        flt;
    double       dbl;

    ulen = data->len;
    if (ulen == sizeof(float)) {
        memcpy(&flt, data->value, ulen);
        json_object_object_add(jobj, field_name, json_object_new_double(flt));
    } else if (ulen == sizeof(double)) {
        memcpy(&dbl, data->value, ulen);
        json_object_object_add(jobj, field_name, json_object_new_double(dbl));
    } else {
        return -EINVAL;
    }
    return data->len + sizeof(trace_data_t);
}

static  int
trace_read_ptr (trace_data_t * data,
                void        ** ptr)
{
    unsigned int ulen;
    ulen = data->len;
    if (ulen == sizeof(void *)) {
        memcpy(ptr, data->value, ulen);
    } else {
        return -EINVAL;
    }
    return data->len + sizeof(trace_data_t);
}


static  int
trace_read_obj (trace_data_t        * data,
                struct json_object   * jobj,
                struct json_object   * jschema)

{
    void               * ptr;
    char                field_name[TRACE_DATA_MAX_STR_LEN];
    char                str_data[TRACE_DATA_MAX_STR_LEN];
    void               * ptr_data;
    char                ptr_data_str[32];
    int                 ret, field_id = 0, field_cnt;
    struct json_object   *mb_obj;
    struct json_object   * child_schema;

    ptr = data->value;
    field_cnt = data->len;
    while (field_id < field_cnt) {
        data = (trace_data_t *)ptr;
        if (data->type != TRACE_DATA_TYPE_STR) {
            return -EINVAL;
        }
        ret = trace_read_str(data, field_name, sizeof(field_name));
        if (ret < 0) {
            return -EINVAL;
        }
        ptr += ret;
        data = (trace_data_t *)ptr;
        switch (data->type) {
            case TRACE_DATA_TYPE_INT:
                ret = trace_read_int(data, jobj, field_name);
                if (ret < 0) {
                    return -EINVAL;
                }
                break;
            case TRACE_DATA_TYPE_UINT:
                ret = trace_read_uint(data, jobj, field_name);
                if (ret < 0) {
                    return -EINVAL;
                }
                break;
            case TRACE_DATA_TYPE_FLOAT:
                ret = trace_read_float(data, jobj, field_name);
                if (ret < 0) {
                    return -EINVAL;
                }
                break;
            case TRACE_DATA_TYPE_PTR:
                ret = trace_read_ptr(data, &ptr_data);
                if (ret < 0) {
                    return -EINVAL;
                }
                snprintf(ptr_data_str, sizeof(ptr_data_str), "%lx", (uintptr_t)ptr_data);
                json_object_object_add(jobj, field_name, json_object_new_string(ptr_data_str));
                json_object_object_add(jschema, field_name, json_object_new_string("ptr"));
                break;
            case TRACE_DATA_TYPE_STR:
                ret = trace_read_str(data, str_data, sizeof(str_data));
                if (ret < 0) {
                    return -EINVAL;
                }
                json_object_object_add(jobj, field_name, json_object_new_string(str_data));
                break;
            case TRACE_DATA_TYPE_OBJECT:
                mb_obj = json_object_new_object();
                child_schema = json_object_new_object();
                json_object_object_add(jobj, field_name, mb_obj);
                json_object_object_add(jschema, field_name, child_schema);
                ret = trace_read_obj(data, mb_obj, child_schema);
                if (ret < 0) {
                    return -EINVAL;
                }
            default:
                return -EINVAL;
        }
        ptr += ret;
        field_id++;
    }
    return (int)(ptr - (void *)data);
}


static  int
trace_read_stack (int                    stackmap,
                  long                   stackid,
                  struct json_object   * jobj,
                  const char           * name)
{
    __u64 ip[PERF_MAX_STACK_DEPTH] = {};
    int   i;
    struct json_object   *jarray;


    if (bpf_map_lookup_elem(stackmap, &stackid, ip) != 0) {
        return -EINVAL;
    }
    jarray = json_object_new_array();
    if (jarray == NULL) {
        bpf_map_delete_elem(stackmap, &stackid);
        return -ENOMEM;
    }
    json_object_object_add(jobj, name, jarray);
    for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
        if (ip[i] != 0) {
            json_object_array_add(jarray, json_object_new_uint64(ip[i]));
        }
    }
    bpf_map_delete_elem(stackmap, &stackid);
    return 0;
}

void print_bpf_output(void *ctx,
                      int cpu,
                      void *data,
                      __u32 size)
{
    struct trace_header * th;
    trace_data_t        * td;
    struct json_object   *jobj, * jparams, *jschema;
    const char          * json_str;
    int                   ret;
    perf_buffer_ctx_t   * pb_ctx = (perf_buffer_ctx_t *)ctx;

    th = (struct trace_header *)data;
    td = (trace_data_t *)(th + 1);
    jobj = json_object_new_object();
    jparams = json_object_new_object();
    jschema = json_object_new_object();
    json_object_object_add(jobj, "id", json_object_new_int64(th->id));
    json_object_object_add(jobj, "comm", json_object_new_string(th->comm));
    json_object_object_add(jobj, "pid", json_object_new_int64(th->pid));
    json_object_object_add(jobj, "tid", json_object_new_int64(th->tid));
    json_object_object_add(jobj, "uid", json_object_new_int64(th->uid));
    json_object_object_add(jobj, "gid", json_object_new_int64(th->gid));
    json_object_object_add(jobj, "cpuid", json_object_new_int64(cpu));
    json_object_object_add(jobj, "ktime_ns", json_object_new_int64(th->ktime_ns));
    json_object_object_add(jobj, "parameters", jparams);
    json_object_object_add(jobj, "schema", jschema);
    if (th->ustack >= 0) {
        trace_read_stack(pb_ctx->stackmap_fd, th->ustack, jobj, "ustack");
    }
    if (th->kstack >= 0) {
        trace_read_stack(pb_ctx->stackmap_fd, th->kstack, jobj, "kstack");
    }
    ret = trace_read_obj(td, jparams, jschema);
    if (ret < 0) {
        json_object_put(jobj);
        return ;
    }
    json_str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY);
    pthread_mutex_lock(&print_mutex);
    printf("%s\n", json_str);
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
    json_object_put(jobj);
    return;
}


struct perf_buffer *
init_perf_buffer (struct bpf_object * bo, perf_buffer_ctx_t * pb_ctx)
{
    int                      pb_map_fd;
    struct perf_buffer     * pb;
    struct perf_buffer_opts  pb_opts = {};

    pb_map_fd = bpf_object__find_map_fd_by_name(bo, "perf_evt_buffer");
    if (pb_map_fd < 0) {
         fprintf(stderr, "ERROR: bpf_object__find_map_fd_by_name failed\n");
         return NULL;
    }
    pb_opts.sz = sizeof(size_t);
    pb = perf_buffer__new(pb_map_fd, 8, print_bpf_output, NULL, pb_ctx, &pb_opts);
    if (pb == NULL) {
         fprintf(stderr, "ERROR: perf_buffer__new failed\n");
        return NULL;
    }
    return pb;
}

static void *
uprobe_trace_thread (void * obj)
{
    struct uprobe * probe;
    struct bpf_program * bp, *prog;
    struct perf_buffer * pb;
    struct bpf_link  * link;
    struct bpf_object * bo;
    int                 stackmap_fd;
    perf_buffer_ctx_t  pb_ctx;
    int    j = 0, ret;

    memset(&pb_ctx, 0, sizeof(pb_ctx));
    probe = (struct uprobe *)obj;
    bo = bpf_object__open(probe->obj);
    if (bo == NULL) {
        perror("error opening object\n");
        return NULL;
    }
    ret = bpf_object__load(bo);
    if (ret < 0) {
        perror("error loading object\n");
        return NULL;
    }
    prog = bpf_object__find_program_by_name(bo, "uprobe_enter");
    if (prog != NULL) {
        link = bpf_program__attach_uprobe(prog, false, -1, probe->path, probe->addr);
        if (link == NULL) {
             perror("error attaching program uprobe_add\n");
             return NULL;
        }
    }
    prog = bpf_object__find_program_by_name(bo, "uprobe_exit");
    if (prog != NULL) {
        link = bpf_program__attach_uprobe(prog, true, -1, probe->path, probe->addr);
        if (link == NULL) {
             perror("error attaching program uprobe_add\n");
             return NULL;
        }
    }
    stackmap_fd = bpf_object__find_map_fd_by_name(bo, "stackmap");
    if (stackmap_fd < 0) {
         fprintf(stderr, "ERROR: bpf_object__find_map_fd_by_name failed\n");
         return NULL;
    }
    pb_ctx.stackmap_fd = stackmap_fd;
    if (init_pid_filter(bo) < 0) {
        fprintf(stderr, "ERROR: fail to initialize pid filter\n");
        return NULL;
    }
    if (init_uid_filter(bo) < 0) {
        fprintf(stderr, "ERROR: fail to initialize uid filter\n");
        return NULL;
    }
    if (init_comm_filter(bo) < 0) {
        fprintf(stderr, "ERROR: fail to initialize comm filter\n");
        return NULL;
    }
    pb = init_perf_buffer(bo, &pb_ctx);
    if (pb == NULL) {
        fprintf(stderr, "ERROR: fail to initialize perf buffer\n");
        return NULL;
    }
    while ((ret = perf_buffer__poll(pb, 1000)) >= 0) {
        ;
    }
    return NULL;
}

/* display usage */
static void
usage(const char *prgname)
{
    printf("%s [options]\n"
           "  -o: <obj>,<addr>,<path> Uprobe object\n"
           "  -p: <pid>               Pid filter\n"
           "  -x: <pid>               Pid excluded\n"
           "  -u: <uid>               Uid filter\n"
           "  -c: <command>           Command filter\n"
           "  -h:                     Show help message and exit\n",
               prgname);
    return;
}

static const char short_options[] =
        "h"  /* help */
        "u:" /* uid filter*/
        "p:" /* pid filter */
        "x:" /* pid excluded */
        "c:" /* command filter */
        "o:" /* trace object file*/
        ;

static int
parse_uprobe_str (char * uprobe_str)
{
    char * comma, *str;

    str = uprobe_str;
    if (uprobe_trace_count >= MAX_UPROBE_TRACE) {
        return -ENOENT;
    }
    comma = strchr(str, ',');
    if (comma != NULL) {
        *comma = '\0';
        uprobe_trace[uprobe_trace_count].obj = strdup(str);
        str = comma + 1;
    } else {
        return -EINVAL;
    }
    comma = strchr(str, ',');
    if (comma != NULL) {
        *comma = '\0';
        uprobe_trace[uprobe_trace_count].addr = atoll(str);
        //printf("offset %llu\n", uprobe_trace[uprobe_trace_count].addr);
        str = comma + 1;
    } else { 
        return -EINVAL;
    }
    uprobe_trace[uprobe_trace_count].path = strdup(str);
    uprobe_trace_count++;
    return 0;
}

void *
alloc_comm_filter (char * comm)
{
    void * buf;
    buf = malloc(TRACE_COMM_SIZE);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf, 0, TRACE_COMM_SIZE);
    strncpy(buf, comm, TRACE_COMM_SIZE);
    return buf;
}

static int
parse_args (int argc, char **argv)
{
    int     opt, ret;
    char ** argvopt;
    int     option_index;
    char *  prgname = argv[0];
    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, short_options,
                                  NULL, &option_index)) != EOF) {
        switch (opt) {
            case 'h':
                usage(prgname);
                exit(0);
            case 'u':
                if (uid_filter_count < MAX_UID_FILTER) {
                    uid_filter[uid_filter_count] = atoi(optarg);
                    uid_filter_count++;
                }
                break;
            case 'p':
                if (pid_filter_count < MAX_PID_FILTER) {
                    pid_filter[pid_filter_count] = atoi(optarg);
                    pid_filter_count++;
                }
                break;
            case 'x':
                if (pid_exclude_count < MAX_PID_FILTER) {
                    pid_exclude[pid_exclude_count] = atoi(optarg);
                    pid_exclude_count++;
                }
                break;
            case 'c':
                if (comm_filter_count < MAX_COMM_FILTER) {
                    comm_filter[comm_filter_count] = alloc_comm_filter(optarg);
                    comm_filter_count++;
                }
                break;
            case 'o':
                if (parse_uprobe_str(optarg) < 0) {
                    usage(prgname);
                    return -1;
                }
                break;
            default:
                usage(prgname);
                return -1;
        }
    }
    optind = 1; /* reset getopt lib */
    return 0;
}


int
main (int argc, char * argv[])
{
    unsigned int pos, thread_cnt = 0;
    pthread_t thread_id[MAX_UPROBE_TRACE];
    void *    thread_ret;

    if (parse_args(argc, argv) < 0) {
        exit(1);
    }
    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();
    libbpf_set_print(libbpf_print);
    pthread_mutex_init(&print_mutex, NULL);
    for (pos = 0; pos < uprobe_trace_count; pos++) {
        if (pthread_create(&thread_id[thread_cnt++],
                            NULL,
                            uprobe_trace_thread,
                            &uprobe_trace[pos]) != 0) {
            perror("pthread_create() error");
            exit(1);
        }
    }
    for (pos = 0; pos < thread_cnt; pos++) {
        pthread_join(thread_id[pos], &thread_ret);
    }
    return 0;
}

