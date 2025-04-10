#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define MAX_HOPS 30
#define PACKET_SIZE 64
#define TIMEOUT_SEC 1

// Compute checksum for ICMP packet
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <destination IP>\n", argv[0]);
        return 1;
    }

    const char *dest_ip = argv[1];
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", dest_ip);
        return 1;
}

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct timeval timeout = {TIMEOUT_SEC, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    for (int ttl = 1; ttl <= MAX_HOPS; ++ttl) {
        setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        char packet[PACKET_SIZE];
        memset(packet, 0, PACKET_SIZE);
        struct icmphdr *icmp = (struct icmphdr *)packet;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = getpid();
        icmp->un.echo.sequence = ttl;
        icmp->checksum = checksum(packet, PACKET_SIZE);

        struct timeval start, end;
        gettimeofday(&start, NULL);
        sendto(sockfd, packet, PACKET_SIZE, 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        char recv_buf[512];
        struct sockaddr_in reply_addr;
        socklen_t addr_len = sizeof(reply_addr);
        int received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr *)&reply_addr, &addr_len);

        gettimeofday(&end, NULL);

        double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                     (end.tv_usec - start.tv_usec) / 1000.0;

        if (received > 0) {
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(reply_addr.sin_addr), addr_str, sizeof(addr_str));
            printf("%2d  %s  %.3f ms\n", ttl, addr_str, rtt);
            if (strcmp(addr_str, dest_ip) == 0)
                break;
        } else {
            printf("%2d  *  (timeout)\n", ttl);
        }
    }

    close(sockfd);
    return 0;
}
