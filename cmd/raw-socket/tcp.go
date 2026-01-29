package rawsocket

/*
#cgo CFLAGS: -I${SRCDIR}/../../socket
#cgo LDFLAGS: -L${SRCDIR} -ltcp
#include "tcp.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type TcpPacket struct {
    ptr *C.tcp_packet_t
}

type TcpInfo struct {
    sockfd C.int
    sourceIP *C.char
    destIp *C.char
    sourcePort C.int
    destPort C.int
}

/**
 * Initial socket
*/
func SocketInit(sourceIP string, destIP string, sourcePort int, destPort int) (*TcpInfo, error) {
    sockfd := C.socket_init()
    if sockfd < 0 {
        return nil, fmt.Errorf("Failed to create new socket: error code %d", sockfd)
    }

    return &TcpInfo{
        sockfd: sockfd,
        sourceIP: C.CString(sourceIP),
        destIp: C.CString(destIP),
        sourcePort: C.int(sourcePort),
        destPort: C.int(destPort),
    }, nil
}

func (t *TcpInfo) Close() {
    if t.sourceIP != nil {
        C.free(unsafe.Pointer(t.sourceIP))
    }
    if t.destIp != nil {
        C.free(unsafe.Pointer(t.destIp))
    }
    if t.sockfd >= 0 {
        C.close(t.sockfd)
    }
}

/**
 * Build Packet
*/
func (t *TcpInfo) BuildTcpPacket(flags uint, payload []byte) (*TcpPacket, error) {

    pkt := &TcpPacket{ptr: C.tcp_packet_new()}

    if pkt.ptr == nil {
        return nil, fmt.Errorf("Failed to alloc tcp packet")
    }

    ret := C.build_tcp_packet(pkt.ptr, t.sourceIP, t.destIp, t.sourcePort, t.destPort, C.int(flags), (*C.char)(unsafe.Pointer(&payload[0])), C.size_t(len(payload)))

    if ret != C.TCP_RAW_SUCCESS {
        C.tcp_packet_free(pkt.ptr)
        return nil, fmt.Errorf("Failed to build tcp packet, error code: %d", ret)
    }

    return pkt, nil
}

/**
* Send packet
*/
func (t *TcpInfo) SendPacket(packet *TcpPacket) error {

    if t == nil {
        return fmt.Errorf("Tcp info is empty")
    }

    if packet == nil {
        return fmt.Errorf("Tcp packet is empty")
    }

    if packet.ptr == nil {
        return fmt.Errorf("Tcp packet pointer is empty")
    }

    ret := C.socket_send(t.sockfd, packet.ptr)
    if ret != C.TCP_RAW_SUCCESS {
        return fmt.Errorf("Failed to build tcp packet, error code: %d", ret)
    }

    return nil
}

/**
* Free packet
*/
// func (p *TcpPacket) Free() {
//     if p.ptr != nil {
//         C.tcp_packet_free(p.ptr)
//         p.ptr == nil
//     }
// }
