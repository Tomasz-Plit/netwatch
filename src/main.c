#include <math.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/socket.h>
#include <bits/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/types.h>

static uint16_t rd16(const unsigned char *p){ return (p[0] << 8) | p[1]; }
static uint32_t rd32(const unsigned char *p){
    return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3]);
}


int open_raw_socket(const char *ifname){
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {perror("socket"); return -1;}
    struct sockaddr_ll address;
    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = if_nametoindex(ifname);
    if (address.sll_ifindex == 0) { perror("if_nametoindex"); return -1; }  
    if (bind(sockfd, (struct sockaddr *)&address, sizeof address) == -1) {
        perror("bind");
        return -1;
    }
    return sockfd;
}

ssize_t recieve_packet(int sockfd, unsigned char *buf, size_t size){
    ssize_t rec = recvfrom(
        sockfd, buf, size, 0, NULL, NULL 
    );
    if(rec == -1) {perror("recvfrom");}
    return rec;
}

void log_packet(FILE *f, const unsigned char *buf, ssize_t rec){
    if(rec < 14) return;
    fprintf(f, "Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
    fprintf(f, "Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
    
    if(rd16(buf + 12) != 0x0800) {fprintf(f, "not an IPv4 \n\n"); return;}
    if(rec < 14 + 20) return;
    
    const unsigned char *ip = buf + 14;
    int ihl = (ip[0] & 0x0f) * 4;
    uint16_t total = rd16(ip + 2);
    uint8_t proto = ip[9];
    uint16_t id = rd16(ip + 4);
    uint16_t check_sum = rd16(ip + 10);    
    uint16_t flags = rd16(ip + 6);
    int df = (flags >> 14) & 1;
    int mf = (flags >> 13) & 1;
    uint16_t frag_of = flags & 0x1FFF;

    fprintf(f, "IP Header: IPv4\n\t");
    fprintf(f, "Header length: %d\n \tTotal length: %u\n \tTTL: %u\n \tProtocol: %u\n",
        ihl, total, ip[8], proto);
    fprintf(f, "\tid: %u\n \tcheck_sum: %u\n", id, check_sum);
    fprintf(f, "\tSrc IP: %u.%u.%u.%u \n", ip[12], ip[13], ip[14], ip[15]);
    fprintf(f, "\tDst IP: %u.%u.%u.%u \n", ip[16], ip[17], ip[18], ip[19]);
    fprintf(f, "\tFlags: DF:%d MF %d\n", df, mf);
    fprintf(f, "\tFragment offset %u (%u bytes)\n\n", frag_of, frag_of * 8);
    //------------ End of ip -----------
    const unsigned char *l4 = ip + ihl;
    size_t l4_len = total - ihl;
    size_t hdr = 0;
    
    if(proto == 6){
        hdr = (l4[12] >> 4) * 4;
        if(total < ihl + 20 || ihl + 14 + 20 > rec) return;
        if(hdr < 20 || ihl + hdr > total || 14 + ihl + hdr > rec) return;

        uint16_t sport = rd16(l4);
        uint16_t dport = rd16(l4 + 2);
        uint32_t seq = rd32(l4+4);
        uint32_t ack = rd32(l4 + 8);
        uint8_t fl = l4[13];
        uint16_t window = rd16(l4 + 14);
        uint16_t tcp_ck = rd16(l4 + 16);
        uint16_t urgent = rd16(l4+18);
        fprintf(f, "TCP Header:\n\t Src port: %u\n\t Dst port: %u\n", sport, dport);
        fprintf(f, "\t Sequence number: %u\n\t Acknowledgement number: %u\n\t Header length: %zu bytes\n",
        seq, ack, hdr);
        fprintf(f, "\t Flags: 0x%02x [%s%s%s%s%s%s%s]\n", fl,
            (fl & 0x80) ? "CWR " : "",
            (fl & 0x40) ? "ECE " : "",
            (fl & 0x20) ? "URG " : "",
            (fl & 0x10) ? "ACK " : "",
            (fl & 0x08) ? "PSH " : "",
            (fl & 0x04) ? "RST " : "",
            (fl & 0x02) ? "SYN " : "",
            (fl & 0x01) ? "FIN " : "");
        fprintf(f, "\t Window ize: %u\n\t Checksum: 0x%04x\n\t Urgent pointer: %u\n",
            window, tcp_ck, urgent);
        
        if(hdr > 20){
            fprintf(f, "\tOptions (%zu bytes): ", hdr - 20);
            for(size_t i = 20; i < hdr; i++){
                fprintf(f, "%02x", l4[i]);
            }
            fprintf(f, "\n");
        }
    }
    else if(proto == 17){
        if(total < ihl + 8 || 14 + ihl + 8 > (size_t)rec) return;

        uint16_t sport = rd16(l4);
        uint16_t dport = rd16(l4+ 2);
        uint16_t udp_len = rd16(l4 + 4);
        uint16_t udp_ck = rd16(l4 + 6);

        fprintf(f, "UDP Header: \n\t Src port: %u\n\t Dst port: %u\n\t Length: %u\n\t Checksum: 0x%04x\n",
        sport, dport, udp_len, udp_ck);
    }



    fprintf(f, "\n ---------------------------------------------\n");
    return;
}


int main(void){
    int sockfd = open_raw_socket("wlp0s20f3:");
    if(sockfd == -1) return 1;

    FILE *logfile = fopen("netwatch.log", "w");
    if(!logfile){perror("fopen"); return 1;}
    setvbuf(logfile, NULL, _IOLBF, 0);

    unsigned char buffer[65535];

    while(1){
        ssize_t rec = recieve_packet(sockfd, buffer, sizeof(buffer));   
        log_packet(logfile, buffer, rec);
    }
    return 0;
}