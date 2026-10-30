// Package toa loads the node-side TOA eBPF programs (bpf/toa.bpf.c) and
// decides whether this node may declare CAPABILITY_NAME_L4_TOA.
//
// The programs are attached to the agent's own cgroup v2, which the L4
// OpenResty it spawns inherits. They only touch sockets on which the patched
// stream proxy (proxy_toa on) made the private setsockopt call, so attaching
// never changes unrelated or already established connections. Any failure
// leaves the node without the capability; forwarding is never affected.
package toa

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SockoptName must match CDNCA_TOA_SOCKOPT in bpf/toa.bpf.c and
// NGX_CDNCA_TOA_SOCKOPT in edge/openresty/native/patches/*-cdnca-stream-toa.patch.
const SockoptName = 0x43464c54

// Directive is the stream proxy directive added by the OpenResty patch.
const Directive = "proxy_toa"

// MinKernel is the first kernel with sockops TCP header option callbacks
// (BPF_SOCK_OPS_HDR_OPT_LEN_CB / WRITE_HDR_OPT_CB, bpf_store_hdr_opt).
var MinKernel = [2]int{5, 10}

// Stat indexes mirror enum toa_stat in bpf/toa.bpf.c.
const (
	StatStored = iota
	StatSkipV6Client
	StatSkipV6Upstream
	StatBadOptlen
	StatWritten
	StatNoSpace
	StatDone
	statCount
)

// Stats are cumulative counters since the programs were loaded.
type Stats [statCount]uint64

// Status is the probe outcome reported in logs and used for the capability.
type Status struct {
	Ready  bool
	Reason string
	Cgroup string
	Kernel string
}

var (
	ErrUnsupported   = errors.New("TOA requires Linux")
	ErrKernelTooOld  = errors.New("kernel lacks sockops TCP header options (needs 5.10+)")
	ErrNoProxyTOA    = errors.New("OpenResty lacks the proxy_toa directive")
	ErrSelfTest      = errors.New("TOA self-test did not write the option")
	ErrCgroupUnknown = errors.New("cannot determine the agent cgroup v2 path")
)

// kernelAtLeast parses a uname release such as "6.8.0-45-generic".
func kernelAtLeast(release string, want [2]int) (bool, error) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false, fmt.Errorf("unrecognised kernel release %q", release)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, fmt.Errorf("unrecognised kernel release %q", release)
	}
	minorText := parts[1]
	if i := strings.IndexFunc(minorText, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minorText = minorText[:i]
	}
	minor, err := strconv.Atoi(minorText)
	if err != nil {
		return false, fmt.Errorf("unrecognised kernel release %q", release)
	}
	return major > want[0] || (major == want[0] && minor >= want[1]), nil
}

// cgroupV2Path returns the unified-hierarchy path from /proc/<pid>/cgroup
// content ("0::/system.slice/x.service").
func cgroupV2Path(content string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			path := strings.TrimSpace(rest)
			if strings.HasPrefix(path, "/") && !strings.Contains(path, "..") {
				return path, nil
			}
		}
	}
	return "", ErrCgroupUnknown
}

// binaryHasDirective reports whether an OpenResty binary was built with the
// proxy_toa patch: the directive name is a NUL-terminated string in its
// command table (an unpatched NGINX contains no "proxy_toa" at all).
func binaryHasDirective(binary []byte) bool {
	return strings.Contains(string(binary), Directive+"\x00")
}

// EncodeSockopt builds the 20-byte private setsockopt value
// (struct cdnca_toa_sockopt: family u16 host order, port u16 network
// order, addr[16]) that the patched stream proxy passes before connect().
func EncodeSockopt(ip net.IP, port uint16) []byte {
	value := make([]byte, 20)
	family := uint16(10) // AF_INET6
	if v4 := ip.To4(); v4 != nil {
		family = 2 // AF_INET
		copy(value[4:8], v4)
	} else {
		copy(value[4:20], ip.To16())
	}
	binary.NativeEndian.PutUint16(value[0:2], family)
	binary.BigEndian.PutUint16(value[2:4], port)
	return value
}
