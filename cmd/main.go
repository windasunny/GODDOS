package main

import (
	"log"

	socket "github.com/windasunny/go-ddos/cmd/raw-socket"
)

func main() {

	sourceIP := "10.211.55.18"
	destIp := "10.211.55.2"
	sourcePort := 12345
	destPort := 12345
	payload := []byte("Hello here!")

	raw, err := socket.SocketInit(sourceIP, destIp, sourcePort, destPort)

	if err != nil {
		println("Make sure using root!!")
		log.Println(err)
	}
	defer raw.Close()

	pkt := &socket.TcpPacket{}
	pkt, err = raw.BuildTcpPacket(0x18, payload)
	if err != nil {
		log.Println(err)
	}
	_ = raw.SendPacket(pkt)
}
