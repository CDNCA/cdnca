package toa

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKernelAtLeast(t *testing.T) {
	for release, want := range map[string]bool{
		"5.10.0-32-amd64":       true,
		"5.9.16":                false,
		"4.18.0-553.el8_10":     false,
		"6.8.0-45-generic":      true,
		"5.14.0-503.el9.x86_64": true,
		"6.10.14-linuxkit":      true,
		"5.10":                  true,
		"5.10rc1":               true,
	} {
		got, err := kernelAtLeast(release, MinKernel)
		if err != nil || got != want {
			t.Errorf("kernelAtLeast(%q) = %v, %v; want %v", release, got, err, want)
		}
	}
	for _, bad := range []string{"", "linux", "x.10"} {
		if _, err := kernelAtLeast(bad, MinKernel); err == nil {
			t.Errorf("kernelAtLeast(%q) accepted an invalid release", bad)
		}
	}
}

func TestCgroupV2Path(t *testing.T) {
	got, err := cgroupV2Path("12:pids:/legacy\n0::/system.slice/cdnca-edge-agent-root.service\n")
	if err != nil || got != "/system.slice/cdnca-edge-agent-root.service" {
		t.Fatalf("cgroupV2Path = %q, %v", got, err)
	}
	for _, bad := range []string{"", "1:name=systemd:/x\n", "0::relative\n", "0::/a/../b\n"} {
		if _, err := cgroupV2Path(bad); !errors.Is(err, ErrCgroupUnknown) {
			t.Errorf("cgroupV2Path(%q) err = %v; want ErrCgroupUnknown", bad, err)
		}
	}
}

func TestBinaryHasDirective(t *testing.T) {
	if !binaryHasDirective([]byte("\x00proxy_socket_keepalive\x00proxy_toa\x00proxy_connect_timeout\x00")) {
		t.Fatal("patched binary not recognised")
	}
	if binaryHasDirective([]byte("\x00proxy_socket_keepalive\x00proxy_toa_extra\x00")) {
		t.Fatal("unrelated string recognised as proxy_toa")
	}
}

// The layout is shared with the nginx patch and the BPF program.
func TestEncodeSockopt(t *testing.T) {
	v4 := EncodeSockopt(net.ParseIP("203.0.113.7"), 51234)
	if len(v4) != 20 || binary.NativeEndian.Uint16(v4[0:2]) != 2 ||
		binary.BigEndian.Uint16(v4[2:4]) != 51234 || net.IP(v4[4:8]).String() != "203.0.113.7" {
		t.Fatalf("IPv4 encoding = %x", v4)
	}
	for _, b := range v4[8:] {
		if b != 0 {
			t.Fatalf("IPv4 encoding has trailing bytes: %x", v4)
		}
	}
	v6 := EncodeSockopt(net.ParseIP("2001:db8::1"), 443)
	if binary.NativeEndian.Uint16(v6[0:2]) != 10 || net.IP(v6[4:20]).String() != "2001:db8::1" {
		t.Fatalf("IPv6 encoding = %x", v6)
	}
}

// bpf/SHA256SUMS pins the committed object to the source it was built from
// (bpf/build.sh is reproducible); editing toa.bpf.c without rebuilding fails.
func TestBPFObjectMatchesPinnedSource(t *testing.T) {
	sums, err := os.ReadFile("bpf/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		want, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("malformed SHA256SUMS line %q", line)
		}
		data, err := os.ReadFile(filepath.Join("bpf", name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
			t.Fatalf("%s sha256 = %s, pinned %s: rebuild with bpf/build.sh and update SHA256SUMS", name, got, want)
		}
	}
}
