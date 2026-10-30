package l4live

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// inet_diag wire format (linux/inet_diag.h, linux/sock_diag.h).
const (
	sockDiagByFamily  = 20
	inetDiagReqBytes  = 4 + 4 + 48 // family, protocol, ext, pad, states; inet_diag_sockid
	inetDiagMsgBytes  = 72
	inetDiagInfo      = 2  // INET_DIAG_INFO: struct tcp_info
	inetDiagReqBytes2 = 1  // INET_DIAG_REQ_BYTECODE attribute type
	bcSEQ             = 11 // INET_DIAG_BC_S_EQ (Linux 4.16+; 9 is DEV_COND)
	bcJMP             = 1  // INET_DIAG_BC_JMP
	tcpEstablished    = 1
	tcpCloseWait      = 8
	// tcp_info offsets of tcpi_bytes_acked / tcpi_bytes_received (Linux 4.1+).
	tcpInfoBytesAcked    = 120
	tcpInfoBytesReceived = 128
)

var errDiagMessage = errors.New("invalid inet_diag message")

// portFilter is inet_diag bytecode accepting a socket whose source (local)
// port is one of ports, the shape ss compiles "sport = a or sport = b" to:
// per port an 8-byte S_EQ (op yes:8 no:12, then op[1].no = port), and
// between ports a JMP (yes:4 no:<to the end>) taken after a match. A failed
// last S_EQ jumps 4 bytes past the end, which rejects. The kernel's audit
// walks the yes chain (every op is on it) and checks each no.
func portFilter(ports []uint16) []byte {
	total := 12*len(ports) - 4
	code := make([]byte, 0, total)
	for index, port := range ports {
		block := make([]byte, 8)
		block[0], block[1] = bcSEQ, 8
		binary.NativeEndian.PutUint16(block[2:], 12)
		binary.NativeEndian.PutUint16(block[6:], port)
		code = append(code, block...)
		if index != len(ports)-1 {
			jump := make([]byte, 4)
			jump[0], jump[1] = bcJMP, 4
			binary.NativeEndian.PutUint16(jump[2:], uint16(total-(12*index+8)))
			code = append(code, jump...)
		}
	}
	return code
}

// diagRequest is the netlink payload of a dump of IPv4 or IPv6 TCP sockets
// in ESTABLISHED or CLOSE_WAIT whose local port is one of ports, with
// tcp_info.
func diagRequest(family uint8, ports []uint16) []byte {
	request := make([]byte, inetDiagReqBytes)
	request[0] = family
	request[1] = 6 // IPPROTO_TCP
	request[2] = 1 << (inetDiagInfo - 1)
	binary.NativeEndian.PutUint32(request[4:], 1<<tcpEstablished|1<<tcpCloseWait)
	if len(ports) == 0 {
		return request // no filter: every socket in those states
	}
	code := portFilter(ports)
	attribute := make([]byte, 4, 4+len(code))
	binary.NativeEndian.PutUint16(attribute[0:], uint16(4+len(code)))
	binary.NativeEndian.PutUint16(attribute[2:], inetDiagReqBytes2)
	return append(append(request, attribute...), code...)
}

// parseDiagMessage decodes one inet_diag_msg with its attributes.
func parseDiagMessage(data []byte) (Socket, error) {
	if len(data) < inetDiagMsgBytes {
		return Socket{}, errDiagMessage
	}
	family := data[0]
	port := func(offset int) uint16 { return binary.BigEndian.Uint16(data[offset:]) }
	address := func(offset int) netip.Addr {
		if family == 2 {
			return netip.AddrFrom4([4]byte(data[offset : offset+4]))
		}
		return netip.AddrFrom16([16]byte(data[offset : offset+16]))
	}
	if family != 2 && family != 10 {
		return Socket{}, errDiagMessage
	}
	socket := Socket{
		Local: netip.AddrPortFrom(address(8).Unmap(), port(4)), Peer: netip.AddrPortFrom(address(24).Unmap(), port(6)),
		Inode: uint64(binary.NativeEndian.Uint32(data[68:])),
	}
	for rest := data[inetDiagMsgBytes:]; len(rest) >= 4; {
		length := int(binary.NativeEndian.Uint16(rest[0:]))
		kind := binary.NativeEndian.Uint16(rest[2:])
		if length < 4 || length > len(rest) {
			return Socket{}, errDiagMessage
		}
		if kind == inetDiagInfo {
			info := rest[4:length]
			if len(info) >= tcpInfoBytesReceived+8 {
				acked := binary.NativeEndian.Uint64(info[tcpInfoBytesAcked:])
				received := binary.NativeEndian.Uint64(info[tcpInfoBytesReceived:])
				socket.BytesSent, socket.BytesReceived = &acked, &received
			}
		}
		aligned := (length + 3) &^ 3
		if aligned > len(rest) {
			break
		}
		rest = rest[aligned:]
	}
	return socket, nil
}
