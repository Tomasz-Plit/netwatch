#include "../include/port_lock.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

#define TABLE "netwatch_port_lock"

static int run_nft(const char *script) {
    int input[2];
    if (pipe(input) < 0) return 0;
    pid_t child = fork();
    if (child < 0) { close(input[0]); close(input[1]); return 0; }
    if (child == 0) {
        close(input[1]);
        if (dup2(input[0], STDIN_FILENO) < 0) _exit(127);
        close(input[0]);
        const char *path = access("/usr/sbin/nft", X_OK) == 0 ? "/usr/sbin/nft" : "/usr/bin/nft";
        execl(path, "nft", "-f", "-", (char *)NULL);
        perror("nft");
        _exit(127);
    }
    close(input[0]);
    size_t left = strlen(script);
    while (left) {
        ssize_t n = write(input[1], script, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        script += n;
        left -= (size_t)n;
    }
    close(input[1]);
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 0;
    return left == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int port_lock_start(unsigned port, int *control_fd, pid_t *watcher) {
    int lock = open("/run/lock/netwatch-port-lock.lock", O_CREAT | O_RDWR, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) < 0) {
        perror("port lock");
        if (lock >= 0) close(lock);
        return 0;
    }
    int control[2], ready[2];
    if (pipe(control) < 0) { close(lock); return 0; }
    if (pipe(ready) < 0) { close(control[0]); close(control[1]); close(lock); return 0; }
    pid_t child = fork();
    if (child < 0) {
        close(control[0]); close(control[1]); close(ready[0]); close(ready[1]); close(lock);
        return 0;
    }
    if (child == 0) {
        close(control[1]); close(ready[0]);
        signal(SIGINT, SIG_IGN);
        signal(SIGTERM, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
        char rules[2500];
        int length = snprintf(rules, sizeof rules,
            "create table inet " TABLE "\n"
            "add chain inet " TABLE " input { type filter hook input priority -10; policy accept; }\n"
            "add chain inet " TABLE " output { type filter hook output priority -10; policy accept; }\n"
            "add rule inet " TABLE " input iifname lo accept\n"
            "add rule inet " TABLE " output oifname lo accept\n"
            "add rule inet " TABLE " input ct state established,related accept\n"
            "add rule inet " TABLE " output ct state established,related accept\n"
            "add rule inet " TABLE " input icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect, packet-too-big } accept\n"
            "add rule inet " TABLE " output icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect, packet-too-big } accept\n"
            "add rule inet " TABLE " output tcp sport %u accept\n"
            "add rule inet " TABLE " output udp dport 53 accept\n"
            "add rule inet " TABLE " output tcp dport 53 accept\n"
            "add rule inet " TABLE " input reject\n"
            "add rule inet " TABLE " output reject\n", port);
        int installed = length > 0 && (size_t)length < sizeof rules && run_nft(rules);
        char result = installed ? '1' : '0';
        (void)write(ready[1], &result, 1);
        close(ready[1]);
        if (!installed) _exit(1);
        char discard[16];
        while (read(control[0], discard, sizeof discard) > 0) {}
        close(control[0]);
        int removed = run_nft("delete table inet " TABLE "\n");
        close(lock);
        _exit(removed ? 0 : 1);
    }
    close(lock);
    close(control[0]); close(ready[1]);
    char result = '0';
    ssize_t n = read(ready[0], &result, 1);
    close(ready[0]);
    if (n != 1 || result != '1') {
        close(control[1]);
        waitpid(child, NULL, 0);
        fprintf(stderr, "could not install temporary port rules\n");
        return 0;
    }
    *control_fd = control[1];
    *watcher = child;
    return 1;
}

int port_lock_stop(int control_fd, pid_t watcher) {
    close(control_fd);
    int status;
    while (waitpid(watcher, &status, 0) < 0) if (errno != EINTR) return 0;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "could not remove temporary port rules\n");
        return 0;
    }
    return 1;
}
