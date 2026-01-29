#ifndef TCP_H
#define TCP_H

#include "header.h"

// Error code
#define TCP_RAW_SUCCESS 0
#define TCP_RAW_ERR_SOCKET -1
#define TCP_RAW_ERR_SETSOCKOPT -2
#define TCP_RAW_ERR_SEND -3
#define TCP_RAW_ERR_INVALID -4

#define MAX_PACKET_ID 65535

// TCP Packet
typedef struct {
    char datagram[4096];
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *payload;
    size_t total_len;
    struct sockaddr_in dest_addr;
} tcp_packet_t;

// Build TCP Packet
int build_tcp_packet(tcp_packet_t *packet, const char *source_ip, const char *dest_ip, int src_port, int dest_port, int flag, const char *payload, size_t payload_len);

// Send packet
int socket_send(int sockfd, tcp_packet_t *packet);

void clean_tcp_packet(tcp_packet_t *packet);

# endif
