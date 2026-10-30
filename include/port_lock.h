#ifndef PORT_LOCK_H
#define PORT_LOCK_H

#include <sys/types.h>

int port_lock_start(unsigned port, int *control_fd, pid_t *watcher);
int port_lock_stop(int control_fd, pid_t watcher);

#endif
