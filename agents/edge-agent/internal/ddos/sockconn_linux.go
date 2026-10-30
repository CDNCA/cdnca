//go:build linux

package ddos

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// Connections lists the established TCP connections of ports (auto defense
// layer 4 statistics: per client concurrency and empty connections). Idle
// is how long a connection that never received a byte has been idle; 0 for
// a connection that received data.
func (SockDiag) Connections(ctx context.Context, ports []PortRange) ([]EmptySocket, error) {
	var sockets []EmptySocket
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		found, err := dump(ctx, family, func(message []byte) (EmptySocket, bool) {
			return connection(message, family, ports)
		})
		if err != nil {
			return nil, err
		}
		sockets = append(sockets, found...)
	}
	return sockets, nil
}

func connection(message []byte, family uint8, ports []PortRange) (EmptySocket, bool) {
	if len(message) < inetDiagMsgSize || message[0] != family || message[1] != tcpEstablished {
		return EmptySocket{}, false
	}
	sourcePort := binary.BigEndian.Uint16(message[4:6])
	if !inPorts(sourcePort, ports) {
		return EmptySocket{}, false
	}
	var remote netip.Addr
	if family == unix.AF_INET {
		remote = netip.AddrFrom4([4]byte(message[24:28]))
	} else {
		remote = netip.AddrFrom16([16]byte(message[24:40]))
	}
	socket := EmptySocket{Client: remote.Unmap(), Remote: netip.AddrPortFrom(remote, binary.BigEndian.Uint16(message[6:8])),
		Local: netip.AddrPortFrom(netip.Addr{}, sourcePort)}
	for attributes := message[inetDiagMsgSize:]; len(attributes) >= unix.SizeofRtAttr; {
		length := int(binary.NativeEndian.Uint16(attributes[0:2]))
		kind := binary.NativeEndian.Uint16(attributes[2:4])
		if length < unix.SizeofRtAttr || length > len(attributes) {
			break
		}
		if kind == inetDiagInfo {
			info := attributes[unix.SizeofRtAttr:length]
			if len(info) >= tcpInfoBytesRecv+8 && binary.NativeEndian.Uint64(info[tcpInfoBytesRecv:]) == 0 {
				socket.Idle = time.Duration(binary.NativeEndian.Uint32(info[tcpInfoLastDataRecv:])) * time.Millisecond
			}
			break
		}
		attributes = attributes[(length+unix.NLMSG_ALIGNTO-1)&^(unix.NLMSG_ALIGNTO-1):]
	}
	return socket, true
}
