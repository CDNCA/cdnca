// Sample third-party node plugin for the ADR 0017 PoC (not product code).
//
// Built as a WASI reactor:
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm ./plugin
//
// ABI (cdnca-owned, deliberately tiny; not proxy-wasm):
//
//	cdnca_alloc(size u32) -> ptr u32         host writes the request here
//	cdnca_on_request(ptr u32, len u32) -> u64 (ptr<<32 | len) of the decision
//
// The request is "METHOD URI\nheader: value\n..."; the decision is one line
// "allow", "deny <status>" or "header <name> <value>". The URI path selects
// misbehaviour so the host can be tested against it:
//
//	/loop   spins forever          (host must time out and recycle the instance)
//	/trap   panics                 (wasm trap; host must recycle the instance)
//	/oom    grows memory unbounded (host memory limit must stop it)
//	/deny   returns "deny 403"
package main

import (
	"strings"
	"unsafe"
)

var (
	inbox  []byte
	outbox []byte
	hoard  [][]byte
)

//go:wasmexport cdnca_alloc
func cdnca_alloc(size uint32) uint32 {
	inbox = make([]byte, size)
	return uint32(uintptr(unsafe.Pointer(&inbox[0])))
}

//go:wasmexport cdnca_on_request
func cdnca_on_request(ptr, length uint32) uint64 {
	request := string(inbox[:length])
	line, _, _ := strings.Cut(request, "\n")
	_, uri, _ := strings.Cut(line, " ")
	path, _, _ := strings.Cut(uri, "?")
	path = path[strings.LastIndexByte(path, '/'):]
	decision := "header x-plugin-seen 1"
	switch path {
	case "/loop":
		for counter := 0; ; counter++ {
			if counter < 0 {
				break
			}
		}
	case "/trap":
		panic("plugin bug")
	case "/oom":
		for {
			hoard = append(hoard, make([]byte, 1<<20))
		}
	case "/deny":
		decision = "deny 403"
	}
	outbox = []byte(decision)
	return uint64(uintptr(unsafe.Pointer(&outbox[0])))<<32 | uint64(len(outbox))
}

func main() {}
