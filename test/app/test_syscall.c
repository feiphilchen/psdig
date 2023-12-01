#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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
    printf("openat(%u, \"/tmp/test_file.txt\", %u)=>%d, errno=>%d\n",  AT_FDCWD, O_WRONLY | O_APPEND, fd, errno);
}

void
syscall_close (void)
{
    int fd, ret;
    fd = open("/tmp/test_file2.txt", O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd > 0) {
        ret = close(fd);
        printf("close(%u)=>%d\n", fd, ret);
    }
}

void
syscall_exit (void)
{
    exit(5);
}

void
syscall_fork (void)
{
    pid_t pid;

    pid = fork();
    printf("forked pid=%u\n", pid);
}

int 
main(int argc, char * argv[]) 
{
    if (argc != 2) {
        return -1;
    }
    if (strcmp(argv[1], "openat") == 0) {
        syscall_openat();
    } else if (strcmp(argv[1], "close") == 0) {
        syscall_close();
    } else if (strcmp(argv[1], "exit") == 0) {
        syscall_exit();
    } else if (strcmp(argv[1], "fork") == 0) {
        syscall_fork();
    }
    return 0;
}
