package xdp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestEmbeddedObjectMatchesPinnedHashes(t *testing.T) {
	sums, err := os.ReadFile("bpf/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		fields := strings.Fields(line)
		content, err := os.ReadFile("bpf/" + fields[1])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != fields[0] {
			t.Errorf("%s does not match SHA256SUMS: rebuild with bpf/build.sh", fields[1])
		}
	}
}

func TestConfigOfMapsTheDDoSProtection(t *testing.T) {
	protection := edgeconfig.DDoSProtection{TCPFlagFilter: true, TCPFlagTypes: edgeconfig.DDoSTCPFlagTypes,
		DropInvalid: true, NewConnectionsPerSecond: 20, NewConnectionsPerMinute: 600, RateBanSeconds: 60}
	config := ConfigOf(protection, []PortRange{{80, 80}, {443, 444}}, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if config.TCPFlags != FlagNull|FlagXmas|FlagSynFin|FlagSynRst|FlagAll || config.SYNRate != 20 || config.SYNBan != time.Minute {
		t.Fatalf("config = %+v", config)
	}
	// fin is conntrack's; the switch off filters nothing.
	protection.TCPFlagFilter = false
	protection.NewConnectionsPerSecond = 0
	if config := ConfigOf(protection, nil, nil); config.TCPFlags != 0 || config.SYNRate != 0 || config.SYNBan != 0 {
		t.Fatalf("off = %+v", config)
	}
	words := ConfigOf(edgeconfig.DDoSProtection{}, []PortRange{{80, 80}, {443, 444}, {65535, 65535}}, nil).portWords()
	for port := range 65536 {
		set := words[port>>5]&(1<<(port&31)) != 0
		if want := port == 80 || port == 443 || port == 444 || port == 65535; set != want {
			t.Fatalf("port %d set=%v", port, set)
		}
	}
}

func TestKeysMapIPv4AndMaskPrefixes(t *testing.T) {
	key, ok := keyOf(netip.MustParsePrefix("10.1.2.3/24"))
	if !ok || key.PrefixLen != 120 || key.Addr != netip.MustParseAddr("::ffff:10.1.2.0").As16() {
		t.Fatalf("v4 key = %+v", key)
	}
	key, _ = keyOf(netip.MustParsePrefix("2001:db8::1/48"))
	if key.PrefixLen != 48 || key.Addr != netip.MustParseAddr("2001:db8::").As16() {
		t.Fatalf("v6 key = %+v", key)
	}
	if got := clientPrefix(netip.MustParseAddr("2001:db8:1:2:3::9")); got != netip.MustParsePrefix("2001:db8:1:2::/64") {
		t.Fatal(got)
	}
	if got := clientPrefix(netip.MustParseAddr("::ffff:192.0.2.9")); got != netip.MustParsePrefix("192.0.2.9/32") {
		t.Fatal(got)
	}
	keys := Config{Exempt: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.0.0.1/8"),
		netip.MustParsePrefix("::1/128")}}.exemptKeys()
	if len(keys) != 2 || keys[0].PrefixLen != 104 {
		t.Fatalf("exempt keys = %+v", keys)
	}
}

func TestBlocksFollowTheAutoDefenseBounds(t *testing.T) {
	for _, valid := range []Block{
		{netip.MustParsePrefix("198.51.100.7/32"), time.Second},
		{netip.MustParsePrefix("198.51.100.0/24"), MaxBlockTTL},
		{netip.MustParsePrefix("2001:db8::/48"), time.Hour},
	} {
		if err := valid.validate(); err != nil {
			t.Errorf("%v refused", valid)
		}
	}
	for _, invalid := range []Block{
		{netip.MustParsePrefix("198.51.0.0/16"), time.Hour},
		{netip.MustParsePrefix("198.51.100.1/24"), time.Hour},
		{netip.MustParsePrefix("2001:db8::/32"), time.Hour},
		{netip.MustParsePrefix("198.51.100.7/32"), MaxBlockTTL + time.Second},
		{netip.MustParsePrefix("198.51.100.7/32"), 0},
		{netip.MustParsePrefix("127.0.0.1/32"), time.Hour},
		{netip.MustParsePrefix("::ffff:198.51.100.7/128"), time.Hour},
		{},
	} {
		if err := invalid.validate(); err == nil {
			t.Errorf("%v accepted", invalid)
		}
	}
}

func TestKernelReleaseParsing(t *testing.T) {
	for release, want := range map[string]bool{"5.9.0": true, "5.8.18-100": false, "6.10.14-linuxkit": true, "4.19.0-25-amd64": false, "5.10": true} {
		if got, err := kernelAtLeast(release, MinKernel); err != nil || got != want {
			t.Errorf("%s: %v %v", release, got, err)
		}
	}
	if _, err := kernelAtLeast("x", MinKernel); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestTestFrameLayout(t *testing.T) {
	v4 := TestFrame(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 443, 0x12)
	if len(v4) != 54 || v4[12] != 0x08 || v4[23] != 6 || v4[34+2] != 0x01 || v4[34+3] != 0xbb || v4[34+13] != 0x12 {
		t.Fatalf("v4 frame % x", v4)
	}
	v6 := TestFrame(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 80, 0x02)
	if len(v6) != 74 || v6[12] != 0x86 || v6[20] != 6 || v6[54+13] != 0x02 {
		t.Fatalf("v6 frame % x", v6)
	}
}

func TestDisabledAndKindsAreKnown(t *testing.T) {
	if status := Probe(Options{Disabled: true}).Status(); status.Mode != ModeDisabled || status.Reason != ReasonDisabled {
		t.Fatalf("disabled = %+v", status)
	}
	if !slices.IsSorted(DropKinds) || len(DropKinds) != statCount {
		t.Fatalf("drop kinds %v", DropKinds)
	}
	for _, kind := range statKinds {
		if !slices.Contains(DropKinds, kind) {
			t.Errorf("%s missing", kind)
		}
	}
	if status := fallback(ReasonLoadFailed, errorString(strings.Repeat("x", 1000))); len(status.Detail) != MaxDetail {
		t.Fatal("detail not bounded")
	}
	var nilManager *Manager
	if nilManager.Running() || nilManager.Status().Mode != ModeNFTables {
		t.Fatal("nil manager")
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
