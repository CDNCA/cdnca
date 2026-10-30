package xdp

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// Block is one auto defense L5 entry (docs/edge/autodefense-contract.md
// section 3.5: kind ip or cidr, IPv4 at least /24, IPv6 at least /48, at
// most 24 hours): every packet from Prefix is dropped at the NIC until TTL
// ends. A node without XDP executes L5 as L4 (autodefense.NodeLevel).
type Block struct {
	Prefix netip.Prefix
	TTL    time.Duration
}

// L5 is the hook the auto defense executor writes blocks through (Manager
// implements it; Running false = execute as L4).
type L5 interface {
	Running() bool
	Block([]Block) error
	Unblock([]netip.Prefix) error
}

// MaxBlockTTL bounds Block.TTL (the contract's single entry duration).
const MaxBlockTTL = 24 * time.Hour

func (block Block) validate() error {
	prefix := block.Prefix
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() ||
		block.TTL < time.Second || block.TTL > MaxBlockTTL {
		return ErrInvalid
	}
	if prefix.Addr().Is4() && prefix.Bits() < 24 || prefix.Addr().Is6() && prefix.Bits() < 48 {
		return ErrInvalid
	}
	if prefix.Addr().IsLoopback() || prefix.Addr().IsUnspecified() {
		return ErrInvalid
	}
	return nil
}

// TestFrame is an Ethernet frame carrying a TCP segment (IPv4 or IPv6, no
// options) with the given flags: BPF_PROG_TEST_RUN input. Checksums are
// left zero, the program never reads them.
func TestFrame(source, destination netip.Addr, port uint16, flags uint8) []byte {
	frame := make([]byte, 14, 14+40+20)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], port)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	if source.Is4() {
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
		header := make([]byte, 20)
		header[0] = 0x45
		binary.BigEndian.PutUint16(header[2:4], 40)
		header[8] = 64
		header[9] = 6
		copy(header[12:16], source.AsSlice())
		copy(header[16:20], destination.AsSlice())
		frame = append(frame, header...)
	} else {
		binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
		header := make([]byte, 40)
		header[0] = 0x60
		binary.BigEndian.PutUint16(header[4:6], 20)
		header[6] = 6
		header[7] = 64
		copy(header[8:24], source.AsSlice())
		copy(header[24:40], destination.AsSlice())
		frame = append(frame, header...)
	}
	return append(frame, tcp...)
}
