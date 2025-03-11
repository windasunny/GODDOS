#include "packet.h"

int main() {
    const char *source_ip = "10.211.55.17";
    const char *dest_ip = "10.211.55.2";
    int source_port = 12345;
    int dest_port = 12345;

    send_tcp_packet(source_ip, dest_ip, source_port, dest_port, 0x18, "ABCDEFGHIJKLMN"); // PSH+ACK

    return 0;
}
