#ifndef HELPER_H
#define HELPER_H

#include <net/if.h>
#include <stdint.h>

uint16_t rd16(const unsigned char *p);
uint32_t rd32(const unsigned char *p);
int find_default_interface(char ifname[IFNAMSIZ]);
#endif
