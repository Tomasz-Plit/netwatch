#include "../include/port_lock.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static int table_exists(void) {
    return system("nft list table inet netwatch_port_lock >/dev/null 2>&1") == 0;
}

static int connect_to(const char *ip, unsigned port, unsigned local_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct timeval timeout = { .tv_sec = 2 };
    assert(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) == 0);
    if (local_port) {
        struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons(local_port) };
        assert(bind(fd, (struct sockaddr *)&local, sizeof local) == 0);
    }
    struct sockaddr_in peer = { .sin_family = AF_INET, .sin_port = htons(port) };
    assert(inet_pton(AF_INET, ip, &peer.sin_addr) == 1);
    int result = connect(fd, (struct sockaddr *)&peer, sizeof peer);
    close(fd);
    return result;
}

int main(void) {
    char current[64];
    const char *host = getenv("NETWATCH_HOST_NETNS");
    ssize_t n = readlink("/proc/self/ns/net", current, sizeof current - 1);
    if (!host || n <= 0) { fputs("namespace check unavailable\n", stderr); return 77; }
    current[n] = '\0';
    if (strcmp(current, host) == 0) { fputs("refusing to test on host network\n", stderr); return 77; }

    int control;
    pid_t watcher;
    const char *peer = getenv("NETWATCH_PEER_IP");
    if (peer) {
        assert(connect_to(peer, 8443, 0) == 0);
        assert(connect_to(peer, 8444, 0) == 0);
        assert(connect_to(peer, 53, 0) == 0);
    }
    assert(port_lock_start(45000, &control, &watcher));
    assert(table_exists());
    if (peer) {
        assert(connect_to(peer, 8443, 45000) == 0);
        assert(connect_to(peer, 8444, 0) < 0);
        assert(connect_to(peer, 53, 0) == 0);
    }
    assert(port_lock_stop(control, watcher));
    assert(!table_exists());

    pid_t capture = fork();
    assert(capture >= 0);
    if (capture == 0) {
        assert(port_lock_start(45000, &control, &watcher));
        kill(getpid(), SIGKILL);
    }
    assert(waitpid(capture, NULL, 0) == capture);
    for (int i = 0; i < 50 && table_exists(); i++) usleep(100000);
    assert(!table_exists());
    return 0;
}
