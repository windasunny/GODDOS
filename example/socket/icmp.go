package main

/*
#cgo CFLAGS: -I../../socket
#cgo LDFLAGS: -L. -ltcp
#include "icmp.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func main() {
    destIP := C.CString("10.211.55.2")

    defer C.free(unsafe.Pointer(destIP))

    fmt.Println("Sending ICMP packet...")
    result := C.send_icmp_packet(destIP)
    if result == 0 {
        fmt.Println("Packet sent successfully!")
    } else {
        fmt.Println("Failed to send packet.")
    }
}
