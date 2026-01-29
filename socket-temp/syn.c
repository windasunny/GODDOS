#include "packet.h"

int main() {
    const char *source_ip = "10.211.55.10";
    const char *dest_ip = "10.211.55.2";
    int source_port = 12345;
    int dest_port = 12345;

    int len;

    unsigned char *packet = send_syn_packet(source_ip, dest_ip, source_port, dest_port, &len);

    printf("Packet created, size: %d bytes\n", len);
    printf("[]byte{\n");
    for (int i = 0; i < len; i++) {
        printf("\t0x%02X", packet[i]);
        if (i < len - 1) {
            printf(", ");
        }
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }
    printf("\n};\n");

    return 0;
}
