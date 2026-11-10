#include "../include/helpers.h"
#include <net/if.h>
#include <stdio.h>

uint16_t rd16(const unsigned char *p){ return (p[0] << 8) | p[1]; }
uint32_t rd32(const unsigned char *p){
    return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3]);
}
int find_default_interface(char ifname[IFNAMSIZ]){
    FILE *routes = fopen("/proc/net/route", "r");
    if(!routes){
        perror("/proc/net/route");
        return 0;
    }

    char line[256];
    fgets(line, sizeof line, routes);

    while(fgets(line, sizeof line, routes)){
        char name[IFNAMSIZ];
        unsigned long destination;
        unsigned int flags;

        if (sscanf(line, "%15s %lx %*s %x", name, &destination, &flags) == 3 &&
            destination == 0 && (flags & 1)) {
            snprintf(ifname, IFNAMSIZ, "%s", name);
            fclose(routes);
            return 1;
        }
    }
    fclose(routes);
    return 0;
}