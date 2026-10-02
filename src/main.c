#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <bits/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
int main(void){
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct sockaddr_ll address;
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = if_nametoindex("wlp0s20f3:");
    int output = bind(
        sockfd,
        (struct sockaddr *) &address,
        sizeof(address)
    );
    if (sockfd == -1){
        perror("socket");
    }
    if (output == -1){
        perror("bind");
    }
    printf("%d", output);
    return 0;
}