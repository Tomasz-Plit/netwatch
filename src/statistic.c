#include "../include/statistic.h"
#include <string.h>
#include <time.h>

#define MAX_HOSTS 4096

struct host_stat{
    char name[256];
    char ip[16];
    unsigned long count;
    time_t last_seen;
};
static struct host_stat hosts[MAX_HOSTS];
static size_t nhosts;
void host_seen(const char *name, const unsigned char *ip){
    char ip_str[16];
    snprintf(ip_str, sizeof ip_str, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    for(size_t i = 0; i < nhosts; i++){
        if(strcmp(hosts[i].name, name) == 0 && strcmp(hosts[i].ip, ip_str) == 0){
            hosts[i].count++;
            hosts[i].last_seen = time(NULL);
            return;
        }
    }
    if(nhosts == MAX_HOSTS) return;
    snprintf(hosts[nhosts].name, sizeof hosts[nhosts].name, "%s", name);
    snprintf(hosts[nhosts].ip, sizeof hosts[nhosts].ip, "%s", ip_str);
    hosts[nhosts].count = 1;
    hosts[nhosts].last_seen = time(NULL);
    nhosts++;
}

void stats_print(FILE *out){
    fprintf(out, "\n === website visits: %zu ===\n", nhosts);
    fprintf(out, "%-6s %-40s %-15s %s\n", "COUNT", "WEBSITE", "VISITOR IP", "LAST SEEN");
    for (size_t i = 0; i < nhosts; i++) {
        char when[16];
        struct tm tmv;
        localtime_r(&hosts[i].last_seen, &tmv);
        strftime(when, sizeof when, "%H:%M:%S", &tmv);

        fprintf(out, "%-6lu %-40s %-15s %s\n", hosts[i].count, hosts[i].name, hosts[i].ip, when);
    fflush(out);
    }
}
