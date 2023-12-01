#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

void syscall_tcp_bind (void)
{
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(55000);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
}

void syscall_tcp_bind_v6 (void)
{
    int listenfd = 0, connfd = 0;
    struct sockaddr_in6 serv_addr;

    listenfd = socket(AF_INET6, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(55000);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
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
    } else if (strcmp(argv[1], "tcp-bind") == 0) {
        syscall_tcp_bind();
    } else if (strcmp(argv[1], "tcp-bind-v6") == 0) {
        syscall_tcp_bind_v6();
    }
    return 0;
}
