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
#include <time.h>

#define MAX_PACKET_ID 65535
#define SEQ_ID 4294967295

/* 96-bit pseudo header needed for TCP checksum calculation */
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    u_int16_t tcp_length;

    struct tcphdr tcp;
};

/* Checksum calculation */
static unsigned short csum(unsigned short *ptr, int nbytes);

#endif
