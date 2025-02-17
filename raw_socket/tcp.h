#ifndef TCP_H
#define TCP_H

#include "header.h"

/* Function to send TCP packet */
int send_tcp_packet(const char *source_ip, const char *dest_ip, int dest_port, const char *data);

#endif
