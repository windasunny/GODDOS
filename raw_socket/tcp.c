#include "tcp.h"
#include <unistd.h>  // for close()

int send_tcp_packet(const char *source_ip, const char *dest_ip, int dest_port, const char *data) {
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s == -1) {
        perror("Failed to create socket");
        return -1;
    }

    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    unsigned short packet_id = generate_random_packet_id();
    unsigned short source_port = generate_random_packet_id();

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dest_port);
    sin.sin_addr.s_addr = inet_addr(dest_ip);

    strcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr), data);

    // Fill in IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
    iph->id = htonl(packet_id);
    iph->frag_off = 0;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = csum((unsigned short *)datagram, iph->tot_len);

    // Fill in TCP Header
    tcph->source = htons(source_port);
    tcph->dest = htons(dest_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Pseudo Header
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));

    tcph->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    // Set IP_HDRINCL
    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        return -1;
    }

    // Send Packet
    if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto failed");
        return -1;
    }

    printf("Packet Sent. Length: %d\n", iph->tot_len);
    close(s);
    return 0;
}
