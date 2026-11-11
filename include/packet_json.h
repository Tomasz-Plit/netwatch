#ifndef PACKET_JSON_H
#define PACKET_JSON_H
#include <stddef.h>
#include <stdio.h>
void packet_json_write(FILE *out, const unsigned char *frame, size_t length);
#endif
