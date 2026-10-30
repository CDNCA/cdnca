//go:build linux

package ddos

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// SockDiag lists TCP sockets through NETLINK_SOCK_DIAG (what ss uses) and
// closes them with SOCK_DESTROY. Kernels without CONFIG_INET_DIAG_DESTROY
// refuse it (ErrDestroyUnsupported): the ban alone then cuts the client's
// packets and OpenResty's own timeouts close those connections.
type SockDiag struct{}

// inet_diag_req_v2 / inet_diag_msg layout (linux/inet_diag.h).
const (
	inetDiagReqV2Size = 56
	inetDiagMsgSize   = 72
	inetDiagInfo      = 2 // INET_DIAG_INFO: struct tcp_info
	tcpEstablished    = 1
	// tcp_info offsets (linux/tcp.h): tcpi_last_data_recv u32 at 44,
	// tcpi_bytes_received u64 at 128 (kernel 4.1+).
	tcpInfoLastDataRecv = 44
	tcpInfoBytesRecv    = 128
	maxDiagBytes        = 64 << 20
)

func (SockDiag) EmptySockets(ctx context.Context, ports []PortRange, idle time.Duration) ([]EmptySocket, error) {
	var sockets []EmptySocket
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		found, err := dump(ctx, family, func(message []byte) (EmptySocket, bool) {
			return emptySocket(message, family, ports, idle)
		})
		if err != nil {
			return nil, err
		}
		sockets = append(sockets, found...)
	}
	return sockets, nil
}

func inPorts(port uint16, ports []PortRange) bool {
	for _, value := range ports {
		if port >= value.First && port <= value.Last {
			return true
		}
	}
	return false
}

// emptySocket decodes one inet_diag_msg with its attributes.
func emptySocket(message []byte, family uint8, ports []PortRange, idle time.Duration) (EmptySocket, bool) {
	if len(message) < inetDiagMsgSize || message[0] != family || message[1] != tcpEstablished {
		return EmptySocket{}, false
	}
	sourcePort := binary.BigEndian.Uint16(message[4:6])
	destinationPort := binary.BigEndian.Uint16(message[6:8])
	if !inPorts(sourcePort, ports) {
		return EmptySocket{}, false
	}
	var local, remote netip.Addr
	if family == unix.AF_INET {
		local = netip.AddrFrom4([4]byte(message[8:12]))
		remote = netip.AddrFrom4([4]byte(message[24:28]))
	} else {
		local = netip.AddrFrom16([16]byte(message[8:24]))
		remote = netip.AddrFrom16([16]byte(message[24:40]))
	}
	cookie := uint64(binary.NativeEndian.Uint32(message[44:48])) | uint64(binary.NativeEndian.Uint32(message[48:52]))<<32
	for attributes := message[inetDiagMsgSize:]; len(attributes) >= unix.SizeofRtAttr; {
		length := int(binary.NativeEndian.Uint16(attributes[0:2]))
		kind := binary.NativeEndian.Uint16(attributes[2:4])
		if length < unix.SizeofRtAttr || length > len(attributes) {
			break
		}
		if kind == inetDiagInfo {
			info := attributes[unix.SizeofRtAttr:length]
			if len(info) < tcpInfoBytesRecv+8 {
				return EmptySocket{}, false
			}
			lastReceive := time.Duration(binary.NativeEndian.Uint32(info[tcpInfoLastDataRecv:])) * time.Millisecond
			received := binary.NativeEndian.Uint64(info[tcpInfoBytesRecv:])
			if received != 0 || lastReceive < idle {
				return EmptySocket{}, false
			}
			return EmptySocket{Client: remote.Unmap(), Local: netip.AddrPortFrom(local, sourcePort),
				Remote: netip.AddrPortFrom(remote, destinationPort), Cookie: cookie, Idle: lastReceive}, true
		}
		attributes = attributes[(length+unix.NLMSG_ALIGNTO-1)&^(unix.NLMSG_ALIGNTO-1):]
	}
	return EmptySocket{}, false
}

// request is a SOCK_DIAG_BY_FAMILY (dump) or SOCK_DESTROY message.
func request(kind uint16, flags uint16, family uint8, states uint32, socket *EmptySocket) []byte {
	message := make([]byte, unix.SizeofNlMsghdr+inetDiagReqV2Size)
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], kind)
	binary.NativeEndian.PutUint16(message[6:8], flags)
	body := message[unix.SizeofNlMsghdr:]
	body[0], body[1] = family, unix.IPPROTO_TCP
	if socket == nil {
		body[3] = 0
		binary.NativeEndian.PutUint32(body[4:8], states)
		body[2] = 1 << (inetDiagInfo - 1) // idiag_ext: INET_DIAG_INFO
		return message
	}
	binary.NativeEndian.PutUint32(body[4:8], states)
	id := body[8:]
	binary.BigEndian.PutUint16(id[0:2], socket.Local.Port())
	binary.BigEndian.PutUint16(id[2:4], socket.Remote.Port())
	local, remote := socket.Local.Addr(), socket.Remote.Addr()
	if family == unix.AF_INET {
		address := local.As4()
		copy(id[4:8], address[:])
		address = remote.As4()
		copy(id[20:24], address[:])
	} else {
		address := local.As16()
		copy(id[4:20], address[:])
		address = remote.As16()
		copy(id[20:36], address[:])
	}
	binary.NativeEndian.PutUint32(id[40:44], uint32(socket.Cookie))
	binary.NativeEndian.PutUint32(id[44:48], uint32(socket.Cookie>>32))
	return message
}

func dump(ctx context.Context, family uint8, decode func([]byte) (EmptySocket, bool)) ([]EmptySocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if deadline, ok := ctx.Deadline(); ok {
		timeout := unix.NsecToTimeval(time.Until(deadline).Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)
	}
	if err := unix.Sendto(fd, request(unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, family, 1<<tcpEstablished, nil),
		0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var sockets []EmptySocket
	buffer := make([]byte, 1<<20)
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		read, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			return nil, err
		}
		total += read
		if total > maxDiagBytes {
			return nil, errors.New("sock_diag dump exceeds its bound")
		}
		messages, err := syscallParse(buffer[:read])
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			switch message.Header.Type {
			case unix.NLMSG_DONE:
				return sockets, nil
			case unix.NLMSG_ERROR:
				if len(message.Data) >= 4 {
					if code := int32(binary.NativeEndian.Uint32(message.Data[:4])); code != 0 {
						return nil, fmt.Errorf("sock_diag: %w", unix.Errno(-code))
					}
				}
				return sockets, nil
			default:
				if socket, ok := decode(message.Data); ok {
					sockets = append(sockets, socket)
				}
			}
		}
	}
}

// Destroy closes sockets (RST to the client). Sockets already gone are fine.
func (SockDiag) Destroy(_ context.Context, sockets []EmptySocket) error {
	if len(sockets) == 0 {
		return nil
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var failure error
	buffer := make([]byte, 4096)
	for index := range sockets {
		family := uint8(unix.AF_INET)
		if sockets[index].Local.Addr().Is6() {
			family = unix.AF_INET6
		}
		if err := unix.Sendto(fd, request(unix.SOCK_DESTROY, unix.NLM_F_REQUEST|unix.NLM_F_ACK, family, 0xffffffff, &sockets[index]),
			0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			return err
		}
		read, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			return err
		}
		messages, err := syscallParse(buffer[:read])
		if err != nil {
			return err
		}
		for _, message := range messages {
			if message.Header.Type == unix.NLMSG_ERROR && len(message.Data) >= 4 {
				code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
				switch errno := unix.Errno(-code); {
				case code == 0 || errno == unix.ENOENT:
				case errno == unix.EOPNOTSUPP:
					return ErrDestroyUnsupported
				default:
					failure = fmt.Errorf("sock_destroy: %w", errno)
				}
			}
		}
	}
	return failure
}

type netlinkMessage struct {
	Header unix.NlMsghdr
	Data   []byte
}

// syscallParse splits a netlink datagram into its messages.
func syscallParse(buffer []byte) ([]netlinkMessage, error) {
	var messages []netlinkMessage
	for len(buffer) >= unix.SizeofNlMsghdr {
		length := binary.NativeEndian.Uint32(buffer[0:4])
		if length < unix.SizeofNlMsghdr || int(length) > len(buffer) {
			return nil, errors.New("netlink message is truncated")
		}
		messages = append(messages, netlinkMessage{
			Header: unix.NlMsghdr{Len: length, Type: binary.NativeEndian.Uint16(buffer[4:6]),
				Flags: binary.NativeEndian.Uint16(buffer[6:8]), Seq: binary.NativeEndian.Uint32(buffer[8:12]),
				Pid: binary.NativeEndian.Uint32(buffer[12:16])},
			Data: buffer[unix.SizeofNlMsghdr:length],
		})
		aligned := (int(length) + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
		if aligned > len(buffer) {
			break
		}
		buffer = buffer[aligned:]
	}
	return messages, nil
}
