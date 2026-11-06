#ifndef TLS_JSON_H
#define TLS_JSON_H
#include "tls_parsing.h"
#include <stdio.h>
#include <time.h>
void tls_json_write_ip(FILE *f, const struct tls_event *ev, int family, const unsigned char *src, const unsigned char *dst, uint16_t sport, uint16_t dport, const struct timespec *ts, double synack_ms, double hello_server_ms);
void tls_json_write(FILE *f, const struct tls_event *ev,
                    const unsigned char *src, const unsigned char *dst,
                    uint16_t sport, uint16_t dport, const struct timespec *ts,
                    double synack_ms, double hello_server_ms);
#endif
