#include "syn.h"

// Ip header
void create_ip_header(struct iphdr *iph, const char *source_ip, unsigned short packet_id, const char *dest_ip) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(packet_id);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = inet_addr(dest_ip);
}

// Tcp header
void create_tcp_header(struct tcphdr *tcph, int source_port, int dest_port) {
    tcph->source = htons(source_port);
    tcph->dest = htons(dest_port);
    tcph->seq = htonl(0);
    tcph->ack_seq = htonl(0);
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;
}

void create_pseudo_header(struct pseudo_header *psh, struct tcphdr *tcph, const char *source_ip, const char *dest_ip) {
    psh->source_address = inet_addr(source_ip);
    psh->dest_address = inet_addr(dest_ip);
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(sizeof(struct tcphdr));
    memcpy(&psh->tcp, tcph, sizeof(struct tcphdr));
    tcph->check = csum((unsigned short*) psh, sizeof(struct pseudo_header));
}

int send_syn_packet(const char *source_ip, const char *dest_ip, int source_port, int dest_port) {

    //Create a raw socket
    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        printf("Socket creation failed. Error: %d\n", errno);
        return -1;
    }

    //Datagram to represent the packet
    char datagram[4096];
    memset(datagram, 0, 4096);

    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dest_port);
    sin.sin_addr.s_addr = inet_addr(dest_ip);

    unsigned short packet_id = generate_random_packet_id();
    printf("Packet: %d", packet_id);

    //Fill in the IP Header
    create_ip_header(iph, source_ip, packet_id, dest_ip);
    //Fill in the TCP Header
    create_tcp_header(tcph, source_port, dest_port);
    // Pseudo Header
    calculate_tcp_checksum(&psh, tcph, source_ip, dest_ip);

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        printf("Error setting IP_HDRINCL. Error: %d\n", errno);
        close(sock);
        return -1;
    }

    // Send Packet
    if (sendto(sock, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        printf("Packet sending failed. Error: %d\n", errno);
        close(sock);
        return -1;
    }

    printf("SYN Packet Sent from %s:%d to %s:%d\n", source_ip, source_port, dest_ip, dest_port);
    close(sock);
    return 0;
}
