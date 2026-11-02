//go:build linux

package xdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Verifier complexity guard (scripts/edge-xdp-smoke.sh, before a node
// package ships): the kernel the test runs on loads cdnca_xdp_filter with the
// verifier statistics, twice:
//   - as built: kernels that verify the global SNI functions on their own;
//   - every global subprogram demoted to static: the verifier walks them in
//     the caller's context, the case that reached the 1000000 instruction
//     limit on some nodes ("BPF program is too large", load_failed).
//
// Each must stay under maxVerifierInsns, a fifth of the kernel limit: older
// verifiers prune less than the test kernel. More kernels: run the same
// binary in VMs of each kernel (see the note on TestKernelVerifierComplexity).
const maxVerifierInsns = 200000

var processedInsns = regexp.MustCompile(`processed (\d+) insns`)

// loadFilter loads the program of object (static: global subprograms
// demoted) with the verifier statistics; the instructions processed.
func loadFilter(t *testing.T, object []byte, static bool) (*ebpf.Collection, int) {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	if static {
		program := spec.Programs[programName]
		for i, ins := range program.Instructions {
			if fn := btf.FuncMetadata(&ins); fn != nil && fn.Linkage == btf.GlobalFunc && fn.Name != programName {
				copied := *fn
				copied.Linkage = btf.StaticFunc
				program.Instructions[i] = btf.WithFuncMetadata(ins, &copied)
			}
		}
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) && len(verr.Log) > 0 {
			t.Logf("verifier: %s", verr.Log[len(verr.Log)-1])
		}
		t.Fatalf("static=%v: %v", static, err)
	}
	match := processedInsns.FindStringSubmatch(collection.Programs[programName].VerifierLog)
	if match == nil {
		collection.Close()
		t.Fatal("no statistics in the verifier log")
	}
	n, _ := strconv.Atoi(match[1])
	return collection, n
}

// TestKernelVerifierComplexity: see maxVerifierInsns. Other kernels: build
// the test binary (go test -c, GOOS=linux) and run it as root in a VM of each
// kernel, e.g. virtme-ng (vng -r v5.10 -- CDNCA_XDP_KERNEL_TEST=1
// ./xdp.test -test.run VerifierComplexity) or one cloud image per supported
// distribution; the Docker VM gives only its own kernel.
func TestKernelVerifierComplexity(t *testing.T) {
	kernelTest(t)
	if os.Getenv("CDNCA_XDP_EXPECT") == "nftables" {
		t.Skip("fallback run")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	for _, static := range []bool{false, true} {
		collection, n := loadFilter(t, bpfObject, static)
		collection.Close()
		t.Logf("static=%v: %d instructions processed (limit %d)", static, n, maxVerifierInsns)
		if n > maxVerifierInsns {
			t.Errorf("static=%v: the verifier processed %d instructions, over %d", static, n, maxVerifierInsns)
		}
	}
}

// clientHello is an Ethernet frame (vlan: 802.1Q tag, options: IPv4 option
// words) carrying one TCP segment with a TLS ClientHello: extra extensions
// before server_name, names in the server_name list (none: no extension).
func clientHello(source netip.Addr, port uint16, vlan bool, options int, extra int, names ...string) []byte {
	var ext []byte
	for i := 0; i < extra; i++ {
		ext = append(ext, 0xff, byte(i), 0, 4, 1, 2, 3, 4)
	}
	if len(names) > 0 {
		var list []byte
		for _, name := range names {
			list = append(list, 0)
			list = binary.BigEndian.AppendUint16(list, uint16(len(name)))
			list = append(list, name...)
		}
		ext = append(ext, 0, 0)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(list)+2))
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(list)))
		ext = append(ext, list...)
	}
	hello := []byte{3, 3}
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 32)
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0, 4, 0x13, 1, 0x13, 2, 1, 0)
	hello = binary.BigEndian.AppendUint16(hello, uint16(len(ext)))
	hello = append(hello, ext...)
	handshake := append([]byte{1, 0, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	record := append([]byte{0x16, 3, 1}, binary.BigEndian.AppendUint16(nil, uint16(len(handshake)))...)
	record = append(record, handshake...)

	base := TestFrame(source, netip.MustParseAddr("192.0.2.100"), port, 0x18)
	if !source.Is4() {
		base = TestFrame(source, netip.MustParseAddr("2001:db8::100"), port, 0x18)
	}
	frame := append([]byte{}, base[:14]...)
	l3 := base[14 : len(base)-20]
	if source.Is4() && options > 0 {
		l3 = append(append([]byte{}, l3...), make([]byte, 4*options)...)
		l3[0] = 0x45 + byte(options)
	}
	if vlan {
		frame = append(frame[:12], 0x81, 0, 0, 7, frame[12], frame[13])
	}
	frame = append(frame, l3...)
	frame = append(frame, base[len(base)-20:]...)
	return append(frame, record...)
}

// TestKernelSiteDropVerdictsMatchObject runs one set of frames through the
// program. With CDNCA_XDP_COMPARE_OBJECT (another xdp.bpf.o, e.g. the
// previous release's) every frame must get the same verdict from both.
func TestKernelSiteDropVerdictsMatchObject(t *testing.T) {
	kernelTest(t)
	if os.Getenv("CDNCA_XDP_EXPECT") == "nftables" {
		t.Skip("fallback run")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	drop := SiteDrop{Ports: []uint16{8443}, SNIPorts: []uint16{443},
		DropNames: []string{"a.example.com", "*.example.com", "shop.example.net", "*.deep.example.org"},
		KeepNames: []string{"keep.example.com", "*.x.example.com", "*.example.org"}}
	v4, v6 := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8::7")
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 59) + ".example.com"
	type frame struct {
		name  string
		bytes []byte
	}
	var frames []frame
	for _, source := range []netip.Addr{v4, v6} {
		for _, vlan := range []bool{false, true} {
			for _, options := range []int{0, 3} {
				if options > 0 && !source.Is4() {
					continue
				}
				for _, extra := range []int{0, 5, 70} {
					for _, names := range [][]string{nil, {"a.example.com"}, {"A.Example.COM"}, {"b.example.com"}, {"example.com"},
						{"keep.example.com"}, {"y.x.example.com"}, {"shop.example.net"}, {"other.test"}, {"z.deep.example.org"},
						{"w.example.org"}, {"." + "example.com"}, {long}, {strings.Repeat("e", 254)}, {"other.test", "a.example.com"}} {
						for _, port := range []uint16{443, 8443, 80} {
							frames = append(frames, frame{fmt.Sprintf("%s vlan=%v opt=%d ext=%d port=%d %.20q", source, vlan, options, extra, port, names),
								clientHello(source, port, vlan, options, extra, names...)})
						}
					}
				}
			}
		}
	}
	// Truncated ClientHellos and headers.
	full := clientHello(v4, 443, false, 0, 0, "a.example.com")
	for _, n := range []int{14, 30, 54, 60, 100, len(full) - 3} {
		frames = append(frames, frame{fmt.Sprintf("truncated %d", n), full[:n]})
	}

	verdicts := func(object []byte) []uint32 {
		collection, _ := loadFilter(t, object, false)
		defer collection.Close()
		manager := &Manager{collection: collection, links: map[string]link.Link{}}
		if err := manager.writeConfig(Config{}); err != nil {
			t.Fatal(err)
		}
		if err := manager.writeSiteDrop(drop); err != nil {
			t.Fatal(err)
		}
		var out []uint32
		for _, f := range frames {
			got, _, err := collection.Programs[programName].Test(f.bytes)
			if err != nil {
				t.Fatalf("%s: %v", f.name, err)
			}
			out = append(out, got)
		}
		return out
	}
	current := verdicts(bpfObject)
	drops := 0
	for _, v := range current {
		if v == 1 {
			drops++
		}
	}
	t.Logf("%d frames, %d dropped", len(frames), drops)
	if drops == 0 || drops == len(frames) {
		t.Fatal("the frames do not exercise the site drop")
	}
	path := os.Getenv("CDNCA_XDP_COMPARE_OBJECT")
	if path == "" {
		return
	}
	other, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	previous := verdicts(other)
	for i, f := range frames {
		if current[i] != previous[i] {
			t.Errorf("%s: verdict %d, %s gives %d", f.name, current[i], path, previous[i])
		}
	}
}
