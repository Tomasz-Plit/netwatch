#ifndef PACKET_LOGGING_H
#define PACKET_LOGGING_H

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

int open_raw_socket(const char *ifname);
ssize_t recieve_packet(int sockfd, unsigned char *buf, size_t size);
void log_packet(FILE *f, const unsigned char *buf, ssize_t rec, unsigned port_filter);

#endif
