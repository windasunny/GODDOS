#include "header.h"

// Ip header
void create_ip_header(struct iphdr *iph, const char *source_ip, const char *dest_ip, unsigned short packet_id, const char *data) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons(packet_id);  //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = inet_addr(dest_ip);
}

// Tcp header
void create_tcp_header(struct tcphdr *tcph, unsigned short source_port, unsigned short dest_port) {
    tcph->source = htons (source_port);
    tcph->dest = htons (dest_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;      /* first and only tcp segment */
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840); /* maximum allowed window size */
    tcph->check = 0; /* if you set a checksum to zero, your kernel's IP stack
                      should fill in the correct checksum during transmission */
    tcph->urg_ptr = 0;
}

void create_pseudo_header(struct pseudo_header *psh, const char *source_ip, const char *dest_ip, unsigned short tcp_length) {
    psh->source_address = inet_addr(source_ip);
    psh->dest_address = inet_addr(dest_ip);
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(tcp_length);
}

int send_tcp_packet(const char *source_ip, const char *dest_ip, int dest_port, const char *data)
{
    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s == -1) {
        perror("Failed to create socket");
        return -1;
    }
    //Datagram to represent the packet
    char datagram[4096];
    //IP header
    struct iphdr *iph = (struct iphdr *)datagram;
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    unsigned short packet_id = generate_random_packet_id();
    unsigned short source_port = generate_random_packet_id();

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dest_port);
    sin.sin_addr.s_addr = inet_addr(dest_ip);

    memset (datagram, 0, 4096); /* zero out the buffer */

    //Fill in the IP Header
    create_ip_header(iph, source_ip, dest_ip, packet_id, data);
    iph->check = csum((unsigned short *)datagram, iph->tot_len);

    //TCP Header
    create_tcp_header(tcph, source_port, dest_port);

    //Now the IP checksum
    create_pseudo_header(&psh, source_ip, dest_ip, sizeof(struct tcphdr) + strlen(data));

    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }

    if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto failed");
        return -1;
    }

    printf("Packet Sent. Length: %d\n", iph->tot_len);
    close(s);
    return 0;
}
