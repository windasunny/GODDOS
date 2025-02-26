#ifndef SYN_H
#define SYN_H

#include "header.h"

/* Function to send TCP packet */
int send_syn_packet(const char *source_ip, const char *dest_ip, int source_port, int dest_port);

#endif
