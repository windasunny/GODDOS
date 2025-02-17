package main

/*
#cgo CFLAGS: -I../../raw_socket
#cgo LDFLAGS: -L. -ltcp
#include "tcp.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func main() {
    sourceIP := C.CString("10.211.55.2")
    destIP := C.CString("10.211.55.17")
    destPort := C.int(80)
    data := C.CString("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    defer C.free(unsafe.Pointer(sourceIP))
    defer C.free(unsafe.Pointer(destIP))
    defer C.free(unsafe.Pointer(data))

    fmt.Println("Sending TCP packet...")
    result := C.send_tcp_packet(sourceIP, destIP, destPort, data)
    if result == 0 {
        fmt.Println("Packet sent successfully!")
    } else {
        fmt.Println("Failed to send packet.")
    }
}
