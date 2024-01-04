#include "stdio.h"
#include "string.h"
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

struct test_struct2 {
    unsigned int xx;
};

struct test_struct {
    int    x;
    int    y;
    struct test_struct2 z;
    char   name[32];
};

union test_union {
    int    x;
    int    y;
};


typedef enum {
   ENUM_VAL_0,
   ENUM_VAL_1
} enum_type;

int g_session = 0;
struct test_struct * __attribute__ ((noinline)) uprobed_add1(struct test_struct * ptr, int iu, char * str) {
    printf("%s(ptr=%p, iu=%d, str=%s)=>%p\n", __FUNCTION__, ptr, iu, str,ptr);
    return ptr;
}

long long __attribute__ ((noinline)) uprobed_add2(unsigned long x, enum_type et) {
    printf("%s(x=%lu, et=%u)=>%lld\n", __FUNCTION__, x, et, (long long)(x+et));
    return (long long)(x+et);
}

void  __attribute__ ((noinline)) uprobed_add3(unsigned long x, enum_type et) {
    printf("%s(x=%lu, et=%u)=>void\n", __FUNCTION__, x, et);
    g_session = (int)(x+et);
}

struct test_struct * __attribute__ ((noinline)) uprobed_add4(void * ptr, int iu, char * str) {
    printf("%s(ptr=%p, iu=%d, str=%s)=>%p\n", __FUNCTION__, ptr, iu, str, ptr);
    return ptr;
}

void  __attribute__ ((noinline)) uprobed_add5(struct test_struct obj) {
    printf("%s(obj=%p)=>void\n", __FUNCTION__, &obj);
    g_session = (int)obj.x;
}

union test_union * __attribute__ ((noinline)) uprobed_add6(union test_union * ptr, int iu, char * str) {
    printf("%s(ptr=%p, iu=%d, str=%s)=>%p\n", __FUNCTION__, ptr, iu, str, ptr);
    return ptr;
}

int 
main(int argc, char * argv[])
{
    struct test_struct obj;
    struct test_struct * result;
    union  test_union  u;
    int                ret;
    char *             str="ssss";
    int64_t          t = -1;
    unsigned long long t12;
    unsigned int      sleep_sec = 0;

    if (argc > 1) {
        if (strcmp(argv[1], "-s") == 0) {
            sleep_sec = 3;
        }
    }
    strcpy(obj.name, str);
    u.x = 0;
    obj.x = 1;
    obj.y = 10;
    obj.z.xx = 123;
    uprobed_add1(&obj, 3, str);
    uprobed_add2(4, ENUM_VAL_1);
    uprobed_add3(5, ENUM_VAL_0);
    uprobed_add4(&obj, 3, str);
#if 0
    uprobed_add5(obj);
#endif
    uprobed_add6(&u, -1, "yy");
    if (sleep_sec > 0) {
        sleep(sleep_sec);
    }
    return 0;
}

