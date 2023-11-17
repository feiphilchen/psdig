#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <json-c/json.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "event_schema.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

#define MAX_TRACE_OBJ 64
#define MAX_PID_FILTER 32
#define MAX_UID_FILTER 32
char * trace_objs[MAX_TRACE_OBJ];
unsigned int pid_filter[MAX_PID_FILTER];
unsigned int uid_filter[MAX_UID_FILTER];
unsigned int pid_filter_count = 0;
unsigned int uid_filter_count = 0;
unsigned int trace_obj_count = 0;
struct event_schema event_schemas [] = EVT_SCHEMA_LIST;

pthread_mutex_t print_mutex;
/* read trace logs from debug fs */
void read_trace_pipe(void)
{
    int trace_fd;

    trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0)
        return;

    while (1) {
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz> 0) {
            buf[sz] = 0;
            puts(buf);
        }
    }
}

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

void debug(const char *fmt, ...)
{
  FILE* pFile = fopen("/tmp/debug.txt", "a");
  if(pFile != NULL)
  {
   va_list args;
   va_start(args, fmt);
   vfprintf(pFile, fmt, args);
   va_end(args);
   fclose(pFile);
  }
}

void bytes_to_str(uint8_t * bytes, uint32_t bytes_len, char * buf)
{
    unsigned int          pos;
    char                * ptr = buf;
    int                   ret;

    for (pos = 0; pos < bytes_len; pos++) {
        ret = sprintf(ptr, "%02x", bytes[pos]);
        ptr += ret;
    }
    *ptr = '\0';
    return ;
}

void print_bpf_output(void *ctx, 
                      int cpu,
                      void *data, 
                      __u32 size)
{
    struct event_header * evt;
    struct event_schema * schema;
    struct event_field  * field;
    unsigned int          pos;
    uint64_t              result;
    void                * ptr;
    char                  str[EVENT_FIELD_MAX_STR_LEN];
    char                  bytes_str[EVENT_FIELD_MAX_BYTES_LEN*2 + 1];
    int                   ret, str_num;
    struct json_object   *jobj, *jarray, *jparams;
    const char          * json_str;
    struct event_sockaddr sa;
    char                  addr_buf[INET6_ADDRSTRLEN];
    bool                  print = true;

    evt = data;
    schema = &event_schemas[evt->id];
    //printf("event(%u/%u):%s\n", evt->id, evt->len, schema->name);
    ptr = evt->data;
    jobj = json_object_new_object();
    jparams = json_object_new_object();
    json_object_object_add(jobj, "event", json_object_new_string(schema->name));
    json_object_object_add(jobj, "comm", json_object_new_string(evt->comm));
    json_object_object_add(jobj, "pid", json_object_new_int64(evt->pid));
    json_object_object_add(jobj, "uid", json_object_new_int64(evt->uid));
    json_object_object_add(jobj, "gid", json_object_new_int64(evt->gid));
    json_object_object_add(jobj, "cpuid", json_object_new_int64(cpu));
    json_object_object_add(jobj, "ktime_ns", json_object_new_int64(evt->ktime_ns));
    json_object_object_add(jobj, "parameters", jparams);
    for (pos = 0; pos < schema->field_nr; pos++) {
        field = &schema->fields[pos];
        if (field->type == EVENT_FIELD_TYPE_INT) {
            result = 0;
            memcpy(&result, ptr, field->size);
            ptr += field->size;
            json_object_object_add(jparams, field->name, json_object_new_int64((int64_t)result));
        } if (field->type == EVENT_FIELD_TYPE_BYTES) {
            if (field->size <= EVENT_FIELD_MAX_BYTES_LEN) {
                bytes_to_str(ptr, field->size, bytes_str);
                json_object_object_add(jparams, field->name, json_object_new_string(bytes_str));
            }
            ptr += field->size;
        } else if (field->type == EVENT_FIELD_TYPE_STR) {
            ret = snprintf(str, sizeof(str), "%s", (char *)ptr);
            ptr += ret + 1;
            json_object_object_add(jparams, field->name, json_object_new_string(str));
        } else if (field->type == EVENT_FIELD_TYPE_STR_LIST) {
            str_num = 0;
            jarray = json_object_new_array();
            while (1) {
                ret = snprintf(str, sizeof(str), "%s", (char *)ptr);
                if (str[0] == '\0') {
                    ptr += 1;
                    break;
                }
                ptr += ret + 1;
                json_object_array_add(jarray, json_object_new_string(str));
                str_num++;
            }
            json_object_object_add(jparams, field->name, jarray);
        } else if (field->type == EVENT_FIELD_TYPE_SOCKADDR) {
            memcpy(&sa, ptr, sizeof(struct event_sockaddr));
            //debug("family:0x%x\n", sa.sa_family);
            if (sa.sa_family != AF_INET && sa.sa_family != AF_INET6) {
                print = false;
                break;
            }
            inet_ntop(sa.sa_family, sa.sa_data, addr_buf, sizeof(addr_buf));
            json_object_object_add(jparams, field->name, json_object_new_string(addr_buf));
            ptr += sizeof(struct event_sockaddr);
        }
    }
    json_str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY);
    pthread_mutex_lock(&print_mutex);
    if (print) {
       printf("%s\n", json_str);
       fflush(stdout);
    }
    pthread_mutex_unlock(&print_mutex);
    json_object_put(jobj);
    return;
}

int
init_event_schemas (struct bpf_object * bo)
{
    struct event_schema * schema;
    unsigned int schema_num, pos;
    int         updated, schema_map_fd;

    schema_map_fd = bpf_object__find_map_fd_by_name(bo, "event_schemas");
    if (schema_map_fd < 0) {
         fprintf(stderr, "ERROR: bpf_object__find_map_fd_by_name failed\n");
         return -EINVAL;
    }
    schema_num = sizeof(event_schemas)/sizeof(struct event_schema);
    for (pos = 0; pos < schema_num; pos++) {
        schema = &event_schemas[pos];
        updated = bpf_map_update_elem(schema_map_fd, &schema->id, schema, BPF_ANY);
        if (updated < 0) {
             fprintf(stderr, "failed to update schema: id=%u, %s\n",schema->id, strerror(errno));
             return -EINVAL;
        }
    }
    return 0;
}

int
init_pid_filter (struct bpf_object * bo)
{
    unsigned int pos;
    int         updated, filter_count_fd, filter_fd;
    unsigned int filter_type = EVENT_FILTER_TYPE_PID;

    filter_count_fd = bpf_object__find_map_fd_by_name(bo, "event_filter_count");
    if (filter_count_fd < 0) {
         fprintf(stderr, "ERROR: bpf_object__find_map_fd_by_name failed\n");
         return -EINVAL;
    }
    updated = bpf_map_update_elem(filter_count_fd, &filter_type, &pid_filter_count, BPF_ANY);
    if (pid_filter_count == 0) {
        return 0;
    }
    filter_fd = bpf_object__find_map_fd_by_name(bo, "event_pid_filter");
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
    unsigned int filter_type = EVENT_FILTER_TYPE_UID;

    filter_count_fd = bpf_object__find_map_fd_by_name(bo, "event_filter_count");
    if (filter_count_fd < 0) {
         fprintf(stderr, "ERROR: bpf_object__find_map_fd_by_name failed\n");
         return -EINVAL;
    }
    updated = bpf_map_update_elem(filter_count_fd, &filter_type, &uid_filter_count, BPF_ANY);
    if (uid_filter_count == 0) {
        return 0;
    }
    filter_fd = bpf_object__find_map_fd_by_name(bo, "event_uid_filter");
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

struct perf_buffer *
init_perf_buffer (struct bpf_object * bo)
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
    pb = perf_buffer__new(pb_map_fd, 8, print_bpf_output, NULL, NULL, &pb_opts);
    if (pb == NULL) {
         fprintf(stderr, "ERROR: perf_buffer__new failed\n");
        return NULL;
    }
    return pb;
}

static void *
event_trace_thread (void * obj)
{
    struct bpf_program * bp, *prog;
    struct perf_buffer * pb;
    struct bpf_link  * links[2];
    struct bpf_object * bo;
    int    j = 0, ret;

    bo = bpf_object__open((char *)obj);
    if (bo == NULL) {
        perror("error opening object\n");
        return NULL;
    }
    ret = bpf_object__load(bo);
    if (ret < 0) {
        perror("error loading object\n");
        return NULL;
    }
    bpf_object__for_each_program(prog, bo) {
            links[j] = bpf_program__attach(prog);
            if (libbpf_get_error(links[j])) {
                    fprintf(stderr, "ERROR: bpf_program__attach failed\n");
                    links[j] = NULL;
                    return NULL;
            }
            j++;
    }
    if (init_pid_filter(bo) < 0) {
        fprintf(stderr, "ERROR: fail to initialize pid filter\n");
        return NULL;
    }
    if (init_uid_filter(bo) < 0) {
        fprintf(stderr, "ERROR: fail to initialize uid filter\n");
        return NULL;
    }
    pb = init_perf_buffer(bo);
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
           "  -o: <trace-obj> Trace object file\n"
           "  -p: <pid>       Pid filter\n"
           "  -u: <uid>       Uid filter\n"
           "  -h:             Show help message and exit\n",
               prgname);
    return;
}

static const char short_options[] =
        "h"  /* help */
        "u:" /* uid filter*/
        "p:" /* pid filter */
        "o:" /* trace object file*/
        ;

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
            case 'o':
                trace_objs[trace_obj_count] = strdup(optarg);
                trace_obj_count++;
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
    pthread_t thread_id[MAX_TRACE_OBJ];
    void *    thread_ret;

    if (parse_args(argc, argv) < 0) {
        exit(1);
    }
    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();
    pthread_mutex_init(&print_mutex, NULL);
    for (pos = 0; pos < trace_obj_count; pos++) {
        if (pthread_create(&thread_id[thread_cnt++], 
                            NULL,
                            event_trace_thread,
                            trace_objs[pos]) != 0) {
            perror("pthread_create() error");
            exit(1);
        }
    }
    for (pos = 0; pos < thread_cnt; pos++) {
        pthread_join(thread_id[pos], &thread_ret);
    }
    return 0;
}


