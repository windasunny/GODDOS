#include "packet.h"
#include "tcp.h"

int build_tcp_packet(
    tcp_packet_t *packet,
    const char *source_ip,
    const char *dest_ip,
    int source_port,
    int dest_port,
    int flags,
    const char *payload,
    size_t payload_len
) {
    if (!packet || !source_ip || !dest_ip || !payload) {
        return TCP_RAW_ERR_INVALID;
    }

    // Avoid payload overflow
    if (payload_len > 2048) {
        return TCP_RAW_ERR_INVALID;
    }

    memset(packet, 0, sizeof(tcp_packet_t));
    packet->iph = (struct iphdr *)packet->datagram;
    packet->tcph = (struct tcphdr *)(packet->datagram + sizeof(struct iphdr));
    packet->payload = packet->datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);

    memset(&packet->dest_addr, 0, sizeof(struct sockaddr_in));
    packet->dest_addr.sin_family = AF_INET;
    packet->dest_addr.sin_port = htons(dest_port);
    packet->dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    // copy payload
    memcpy(packet->payload, payload, payload_len);

    // generate packet id
    srand(time(NULL));
    unsigned short packet_id = random() % MAX_PACKET_ID;

    char datagram[4096];
    memset(datagram, 0, 4096);
    char *data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);

    // build tcp header
    create_ip_header(packet->iph, source_ip, packet_id, dest_ip, payload_len);
    create_tcp_header(packet->tcph, source_port, dest_port, flags, payload_len);

    // caculate checksum
    calculate_tcp_checksum(packet->tcph, source_ip, dest_ip, packet->payload, payload_len);

    // load payload length
    packet->total_len = ntohs(packet->iph->tot_len);

    return TCP_RAW_SUCCESS;
}

int socket_send(int sockfd, tcp_packet_t *packet) {
    if (sockfd < 0 || !packet) {
        return TCP_RAW_ERR_INVALID;
    }

    if (sendto(sockfd, packet->datagram, packet->total_len, 0,
               (struct sockaddr *)&packet->dest_addr,
               sizeof(packet->dest_addr)) < 0) {
        return TCP_RAW_ERR_SEND;
    }

    return TCP_RAW_SUCCESS;
}

void clean_tcp_packet(tcp_packet_t *packet) {
    if (packet) {
        memset(packet, 0, sizeof(tcp_packet_t));
    }
}

int main() {
    const char *src_ip_str  = "10.211.55.18";
    const char *dst_ip_str  = "10.211.55.2";
    uint16_t src_port = 12345;
    uint16_t dst_port = 12345;
    uint8_t  flags    = 0x18; // PSH + ACK
    const char *payload = "Hello World!!";
    size_t payload_len = strlen(payload);

    int socket_fd, ret;
    tcp_packet_t packet;

    socket_fd = socket_init();
    if (socket_fd < 0) {
        printf("Error: failed to create socket\n");
        return 1;
    }

    ret = build_tcp_packet(&packet, *src_ip_str, *dst_ip_str, src_port, dst_port, flags, payload, payload_len);
    if (ret != 0) {
        return printf("Error: failed to create packet");
        close(socket_fd);
        return 1;
    }

    ret = socket_send(socket_fd, &packet);
    if (ret != TCP_RAW_SUCCESS) {
        printf("Error: failed to send packet (code: %d)\n", ret);
        close(socket_fd);
        return 1;
    }

    printf("Packet sent successfully!\n");

    clean_tcp_packet(&socket);
    close(socket_fd);

    return 0;
}
