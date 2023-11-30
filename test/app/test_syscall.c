#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

void 
syscall_openat (void)
{
    int fd;
    errno = 0;
    fd = openat(AT_FDCWD, "/tmp/test_file.txt", O_WRONLY | O_APPEND);
    printf("openat(AT_FDCWD, \"/tmp/test_file.txt\", O_WRONLY | O_APPEND)=>%d, errno=>%d\n", fd, errno);
}

int 
main(int argc, char * argv[]) 
{
    if (argc != 2) {
        return -1;
    }
    if (strcmp(argv[1], "openat") == 0) {
        syscall_openat();
    }
    return 0;
}
