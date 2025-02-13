package main

/*
#cgo CFLAGS: -I../../raw_socket
#include "tcp.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func main() {

	srcIP := C.CString("10.211.55.2")
	dstIP := C.CString("10.211.55.17")
	port := C.int(80)

	data_string := C.CString("ABCDEFGHI")
	defer C.free(unsafe.Pointer(data_string))

	C.send_raw_packet(srcIP, dstIP, port, data_string)

	C.free(unsafe.Pointer(srcIP))
	C.free(unsafe.Pointer(dstIP))

	fmt.Println("TCP Packet Sent!")
}
