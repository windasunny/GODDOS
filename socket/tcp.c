#include "header.h"

// Ip header
void create_ip_header(struct iphdr *iph, const char *source_ip, unsigned short packet_id, const char *dest_ip, int tcp_payload_size) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_payload_size);
    iph->id = htons(packet_id);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = inet_addr(dest_ip);
}

// Tcp header
void create_tcp_header(struct tcphdr *tcph, int source_port, int dest_port, int flags, int data_len) {
    tcph->source = htons(source_port);
    tcph->dest = htons(dest_port);
    tcph->seq = htonl(rand() % 4294967295);
    tcph->ack_seq = 0;
    tcph->doff = 5;

    tcph->fin = (flags & 0x01) ? 1 : 0;
    tcph->syn = (flags & 0x02) ? 1 : 0;
    tcph->rst = (flags & 0x04) ? 1 : 0;
    tcph->psh = (flags & 0x08) ? 1 : 0;
    tcph->ack = (flags & 0x10) ? 1 : 0;
    tcph->urg = (flags & 0x20) ? 1 : 0;

    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;
}

void create_pseudo_header(struct pseudo_header *psh, struct tcphdr *tcph, const char *source_ip, const char *dest_ip, unsigned short tcp_length) {
    psh->source_address = inet_addr(source_ip);
    psh->dest_address = inet_addr(dest_ip);
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(tcp_length);
}

void calculate_tcp_checksum(struct tcphdr *tcph, const char *source_ip, const char *dest_ip, char *data, int data_len) {
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + data_len;
    char *pseudogram = malloc(psize);
    struct pseudo_header *psh = (struct pseudo_header *)pseudogram;

    psh->source_address = inet_addr(source_ip);
    psh->dest_address = inet_addr(dest_ip);
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(sizeof(struct tcphdr) + data_len);

    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data, data_len);

    tcph->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);
}

int send_tcp_packet(const char *source_ip, const char *dest_ip, int source_port, int dest_port, int flags, const char *payload) {
    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        printf("Socket creation failed. Error: %d\n", errno);
        return -1;
    }

    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dest_port);
    sin.sin_addr.s_addr = inet_addr(dest_ip);

    unsigned short packet_id = rand() % 65535;
    printf("Sending TCP Packet: ID=%d, Flags=%d, Data=%s\n", packet_id, flags, payload);

    // 設定 Payload
    char *data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    int data_len = strlen(payload);
    memcpy(data, payload, data_len);

    // 設置 IP Header 和 TCP Header
    create_ip_header(iph, source_ip, packet_id, dest_ip, data_len);
    create_tcp_header(tcph, source_port, dest_port, flags, data_len);

    // 計算 TCP Checksum
    calculate_tcp_checksum(tcph, source_ip, dest_ip, data, data_len);

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        printf("Error setting IP_HDRINCL. Error: %d\n", errno);
        close(sock);
        return -1;
    }

    // 發送封包
    if (sendto(sock, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        printf("Packet sending failed. Error: %d\n", errno);
        close(sock);
        return -1;
    }

    printf("TCP Packet Sent from %s:%d to %s:%d\n", source_ip, source_port, dest_ip, dest_port);
    close(sock);
    return 0;
}

int main() {
    const char *source_ip = "10.211.55.17";
    const char *dest_ip = "10.211.55.2";
    int source_port = 12345;
    int dest_port = 12345;

    send_tcp_packet(source_ip, dest_ip, source_port, dest_port, 0x18, "Hello, Server!");  // PSH + ACK

    return 0;
}
