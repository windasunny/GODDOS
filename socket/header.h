#ifndef HEADER_H
#define HEADER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

/* 96-bit pseudo header needed for TCP checksum calculation */
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;

    struct tcphdr tcp;
};

/* Checksum calculation */
unsigned short csum(unsigned short *ptr, int nbytes);

unsigned short generate_random_packet_id();

#endif
