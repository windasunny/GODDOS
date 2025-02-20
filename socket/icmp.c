#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

// ICMP Header
struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence_number;
};

// Caculate ICMP checksum
uint16_t csum(void *vdata, size_t length) {
    char *data = (char *)vdata;
    uint32_t acc = 0xffff;

    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += word;
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += word;
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    return ~acc;
}

// Create icmp
void create_icmp_packet(char *buffer) {
    struct icmp_header icmp = {
        .type = 8, // Echo request
        .code = 0,
        .checksum = 0,
        .identifier = htons(1), // host byte to network byte
        .sequence_number = htons(1) // host byte to network byte
    };

    // checksum
    icmp.checksum = csum(&icmp, sizeof(icmp));

    // make buffer to packet
    memcpy(buffer, &icmp, sizeof(icmp));
}

// Send icmp packet
void send_icmp_packet(const char *dest_ip) {
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    // Call func
    create_icmp_packet(buffer);

    // Socket setting
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set dst.
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) != 1) {
        perror("Invalid destination IP");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Send
    ssize_t sent_bytes = sendto(sock, buffer, sizeof(struct icmp_header), 0,
                                (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sent_bytes < 0) {
        perror("Send failed");
    } else {
        printf("ICMP packet sent to %s\n", dest_ip);
    }

    // close socket
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <destination_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    send_icmp_packet(argv[1]);
    return 0;
}
