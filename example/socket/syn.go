package main

/*
#cgo CFLAGS: -I../../socket
#cgo LDFLAGS: -L. -ltcp
#include "syn.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func main() {
    sourceIP := C.CString("10.211.55.17")
    destIP := C.CString("10.211.55.2")
    source_port := C.int(12345)
    destPort := C.int(12345)

    defer C.free(unsafe.Pointer(sourceIP))
    defer C.free(unsafe.Pointer(destIP))

    fmt.Println("Sending TCP packet...")
    result := C.send_syn_packet(sourceIP, destIP, source_port, destPort)
    if result == 0 {
        fmt.Println("Packet sent successfully!")
    } else {
        fmt.Println("Failed to send packet.")
    }
}
