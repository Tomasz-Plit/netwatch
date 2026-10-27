#ifndef STATISTIC_H
#define STATISTIC_H

#include <stdio.h>

void host_seen(const char *name, const unsigned char *ip);
void stats_print(FILE *out);

#endif
