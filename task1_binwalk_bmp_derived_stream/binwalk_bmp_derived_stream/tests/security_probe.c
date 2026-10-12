/* Trusted diagnostic for the actual jail boundary, compiled by test_verify.py. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || getuid() != 65534 || getgid() != 65534) return 1;
    if (open(argv[1], O_RDONLY) != -1) return 2;
    if (open("/tests/fixtures/cases_manifest.json", O_RDONLY) != -1) return 3;
    if (open("/proc/1/root/tests/verify.py", O_RDONLY) != -1) return 4;
    if (open("/../../tests/verify.py", O_RDONLY) != -1) return 5;
    if (open("/escape", O_CREAT | O_WRONLY, 0600) != -1) return 6;
    if (setuid(0) != -1) return 7;
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 8;
    errno = 0;
    if (socket(AF_INET, SOCK_STREAM, 0) != -1 || errno != EPERM) return 9;
    for (int fd = 3; fd < 64; fd++) {
        if (fcntl(fd, F_GETFD) != -1) return 10;
    }
    if (fork() != -1) return 11;
    puts("isolated");
    return 0;
}
