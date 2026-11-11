#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int netwatch_main(int argc, char **argv);
static int fail_capture;

int __wrap_find_default_interface(char ifname[IFNAMSIZ]) {
    snprintf(ifname, IFNAMSIZ, "lo");
    return 1;
}

/* Stand in for the raw socket, so this test needs no root or network access. */
int __wrap_open_raw_socket(const char *ifname) {
    (void)ifname;
    return open("/dev/null", O_RDONLY);
}

int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t length) {
    (void)fd; (void)level; (void)option; (void)value; (void)length;
    return 0;
}

ssize_t __wrap_recieve_packet(int fd, unsigned char *buffer, size_t size) {
    (void)fd; (void)buffer; (void)size;
    sigset_t blocked, previous;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    assert(sigprocmask(SIG_BLOCK, &blocked, &previous) == 0);
    fputs("test: capture ready\n", stderr);
    if (fail_capture) {
        assert(sigprocmask(SIG_SETMASK, &previous, NULL) == 0);
        errno = EIO;
        return -1;
    }
    sigsuspend(&previous);
    assert(sigprocmask(SIG_SETMASK, &previous, NULL) == 0);
    errno = EINTR;
    return -1;
}

static void check_run(int should_fail) {
    int output[2];
    assert(pipe(output) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(output[0]);
        assert(dup2(output[1], STDERR_FILENO) >= 0);
        close(output[1]);
        fail_capture = should_fail;
        char *args[] = { "netwatch", NULL };
        exit(netwatch_main(1, args));
    }
    close(output[1]);
    FILE *log = fdopen(output[0], "r");
    assert(log);
    char line[256];
    assert(fgets(line, sizeof line, log));
    assert(strstr(line, "test: capture ready"));
    if (!should_fail) assert(kill(child, SIGTERM) == 0);
    int saw_expected = 0;
    while (fgets(line, sizeof line, log)) {
        if (strstr(line, should_fail ? "capture failed" : "clean shutdown"))
            saw_expected = 1;
    }
    fclose(log);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == (should_fail ? 1 : 0));
    assert(saw_expected);
}

static void check_spoof_packet_option(void) {
    int output[2];
    assert(pipe(output) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(output[0]);
        assert(dup2(output[1], STDERR_FILENO) >= 0);
        close(output[1]);
        char *args[] = { "netwatch", "--packet-json", "--spoof", "invalid", "192.0.2.1", NULL };
        exit(netwatch_main(5, args));
    }
    close(output[1]);
    FILE *log = fdopen(output[0], "r");
    assert(log);
    char line[256];
    assert(fgets(line, sizeof line, log));
    assert(strstr(line, "bad target IP"));
    fclose(log);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 1);
}

int main(void) {
    alarm(10);
    char directory[] = "/tmp/netwatch-shutdown-XXXXXX";
    assert(mkdtemp(directory));
    assert(chdir(directory) == 0);
    check_run(0);
    check_run(1);
    check_spoof_packet_option();
    unlink("netwatch.log");
    unlink("netwatch_tls.jsonl");
    assert(chdir("/") == 0);
    assert(rmdir(directory) == 0);
    puts("shutdown tests passed");
    return 0;
}
