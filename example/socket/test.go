package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {
	dstIP := "192.168.1.100"

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)

	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], net.ParseIP(dstIP).To4())

	packet := []byte{
        0x45,   0x00,   0x00,   0x28,   0xB0,   0xF2,   0x00,   0x00,
        0x40,   0x06,   0x00,   0x00,   0x0A,   0xD3,   0x37,   0x11,
        0x0A,   0xD3,   0x37,   0x02,   0x30,   0x39,   0x30,   0x39,
        0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,
        0x50,   0x02,   0x16,   0xD0,   0xB4,   0xE7,   0x00,   0x00,
	};

	// Send Packet
	err = syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		panic(err)
	}

	fmt.Println("Packet sent successfully!")
}
