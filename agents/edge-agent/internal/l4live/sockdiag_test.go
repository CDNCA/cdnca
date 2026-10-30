package l4live

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// runFilter is the kernel's inet_diag_bc_audit + inet_diag_bc_run for the
// ops portFilter emits.
func runFilter(t *testing.T, code []byte, sport uint16) bool {
	t.Helper()
	// audit: walk the yes chain, check no targets.
	onChain := map[int]bool{}
	for offset := 0; offset < len(code); {
		onChain[offset] = true
		length := len(code) - offset
		yes, no := int(code[offset+1]), int(binary.NativeEndian.Uint16(code[offset+2:]))
		minimum := 4
		if code[offset] == bcSEQ {
			minimum = 8
		}
		if yes < minimum || yes > length+4 || yes%4 != 0 || no < minimum || no > length+4 || no%4 != 0 {
			t.Fatalf("audit rejects op at %d", offset)
		}
		offset += yes
	}
	for offset := 0; offset < len(code); {
		length := len(code) - offset
		no := int(binary.NativeEndian.Uint16(code[offset+2:]))
		if no < length && !onChain[offset+no] {
			t.Fatalf("no of op at %d lands off the chain", offset)
		}
		offset += int(code[offset+1])
	}
	// run
	length, offset := len(code), 0
	for length > 0 {
		yes := false
		switch code[offset] {
		case bcSEQ:
			yes = sport == binary.NativeEndian.Uint16(code[offset+6:])
		case bcJMP:
			yes = false
		}
		step := int(binary.NativeEndian.Uint16(code[offset+2:]))
		if yes {
			step = int(code[offset+1])
		}
		length -= step
		offset += step
	}
	return length == 0
}

func TestPortFilterMatchesOnlyItsPorts(t *testing.T) {
	for _, ports := range [][]uint16{{443}, {443, 8443}, {1, 2, 3, 65535}} {
		code := portFilter(ports)
		for _, port := range ports {
			if !runFilter(t, code, port) {
				t.Fatalf("%v rejected %d", ports, port)
			}
		}
		for _, port := range []uint16{80, 4, 65534} {
			if runFilter(t, code, port) {
				t.Fatalf("%v accepted %d", ports, port)
			}
		}
	}
}

func TestParseDiagMessage(t *testing.T) {
	message := make([]byte, inetDiagMsgBytes)
	message[0] = 2
	binary.BigEndian.PutUint16(message[4:], 18480)
	binary.BigEndian.PutUint16(message[6:], 40001)
	copy(message[8:], []byte{10, 0, 0, 1})
	copy(message[24:], []byte{198, 51, 100, 7})
	binary.NativeEndian.PutUint32(message[68:], 4242)
	info := make([]byte, 4+tcpInfoBytesReceived+8+4)
	binary.NativeEndian.PutUint16(info[0:], uint16(len(info)))
	binary.NativeEndian.PutUint16(info[2:], inetDiagInfo)
	binary.NativeEndian.PutUint64(info[4+tcpInfoBytesAcked:], 1200)
	binary.NativeEndian.PutUint64(info[4+tcpInfoBytesReceived:], 300)
	socket, err := parseDiagMessage(append(message, info...))
	if err != nil || socket.Local != netip.MustParseAddrPort("10.0.0.1:18480") || socket.Peer != netip.MustParseAddrPort("198.51.100.7:40001") ||
		socket.Inode != 4242 || *socket.BytesSent != 1200 || *socket.BytesReceived != 300 {
		t.Fatalf("socket = %+v %v", socket, err)
	}
	if _, err := parseDiagMessage(message[:10]); err == nil {
		t.Fatal("short message accepted")
	}
}

// Without ports the request carries no bytecode: every socket is dumped.
func TestDiagRequestWithoutPortsHasNoFilter(t *testing.T) {
	if request := diagRequest(2, nil); len(request) != inetDiagReqBytes {
		t.Fatalf("unfiltered request is %d bytes, want %d", len(request), inetDiagReqBytes)
	}
	if request := diagRequest(2, []uint16{1, 2}); len(request) != inetDiagReqBytes+4+20 {
		t.Fatalf("filtered request is %d bytes", len(request))
	}
}
