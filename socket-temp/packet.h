#ifndef PACKET_H
#define PACKET_H

#include "header.h"

/* Function to send TCP packet */
static void create_ip_header(struct iphdr *iph, const char *source_ip, unsigned short packet_id, const char *dest_ip, int payload_size);
static void create_tcp_header(struct tcphdr *tcph, int source_port, int dest_port, int flags, int payload_size);
void create_syn_header(struct tcphdr *tcph, int source_port, int dest_port);
static void calculate_tcp_checksum(struct tcphdr *tcph, const char *source_ip, const char *dest_ip, char *data, int data_len);
int send_tcp_packet(const char *source_ip, const char *dest_ip, int source_port, int dest_port, int flags, const char *payload);
int send_syn_packet(const char *source_ip, const char *dest_ip, int source_port, int dest_port);

#endif
