package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestXDPSettingsValidate(t *testing.T) {
	for _, good := range []xdpSettings{{}, {Disabled: true}, {Interfaces: []string{"eth0", "ens3f1"}}} {
		if err := good.validate(); err != nil {
			t.Errorf("%+v: %v", good, err)
		}
	}
	for _, bad := range []xdpSettings{
		{Interfaces: []string{""}}, {Interfaces: []string{"eth0", "eth0"}}, {Interfaces: []string{"a/b"}},
		{Interfaces: []string{"averyveryverylongname"}}, {Interfaces: make([]string, xdpMaxInterfaces+1)},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// A node that cannot attach the filter (here: disabled, or not Linux) does
// not declare XDP_FILTER, and reports why in telemetry.
func TestXDPNotAttachedIsNotDeclaredAndReportsTheReason(t *testing.T) {
	manager := probeXDP(xdpSettings{Disabled: true}, &bytes.Buffer{})
	if capability := xdpCapability(manager); capability.Ready() || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER ||
		capability.APIVersion != 1 {
		t.Fatalf("declared %+v ready=%v", capability, capability.Ready())
	}
	metrics := xdpStatusMetrics(manager)(t.Context())
	if metrics.Mode != "disabled" || metrics.Reason != "disabled" || metrics.Drops != nil {
		t.Fatalf("metrics = %+v", metrics)
	}
	var output bytes.Buffer
	logXDPStatus(&output, xdp.Status{Mode: xdp.ModeNFTables, Reason: xdp.ReasonBPFUnavailable, Detail: "function not implemented"})
	if !strings.Contains(output.String(), "nftables (bpf_unavailable): function not implemented") {
		t.Fatalf("log = %q", output.String())
	}
	output.Reset()
	if code := xdpProbeCommand([]string{"--interface=eth0"}, &output); code != 0 {
		t.Fatalf("probe command exit %d", code)
	}
	var status xdp.Status
	if err := json.Unmarshal(output.Bytes(), &status); err != nil || !status.Mode.Valid() {
		t.Fatalf("probe output %q: %v", output.String(), err)
	}
	if code := xdpProbeCommand([]string{"--bogus"}, &output); code != 2 {
		t.Fatalf("bad argument exit %d", code)
	}
}

// Each site's pending CC bans are mirrored to the XDP filter on the site's
// ports, alongside the firewall merge.
func TestCCKernelBansMirrorToTheXDPFilter(t *testing.T) {
	tenant, site := uuid.NewString(), uuid.NewString()
	now := time.Unix(1_800_000_000, 0).UTC()
	fw := &ccBanFirewall{active: map[string][]firewall.Entry{}}
	bans := newCCKernelBans(fw, func(_, siteID string) []uint16 { return []uint16{80, 443} }, func() time.Time { return now })
	var mirrored []string
	bans.mirror = func(clients map[netip.Addr]time.Time, ports []uint16) {
		for client, until := range clients {
			mirrored = append(mirrored, fmt.Sprintf("%s %v %d", client, ports, until.Unix()))
		}
	}
	bans.step(t.Context(), []byte(fmt.Sprintf("%s|%s|198.51.100.7|%d", tenant, site, now.Add(time.Hour).Unix())))
	if len(mirrored) != 1 || mirrored[0] != fmt.Sprintf("198.51.100.7 [80 443] %d", now.Add(time.Hour).Unix()) {
		t.Fatalf("mirrored %v", mirrored)
	}
}

// The installer detects XDP after writing the configuration and passes
// --disable-xdp into it.
func TestNodeInstallerDisableXDP(t *testing.T) {
	content, err := os.ReadFile("../../../../scripts/install-node.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--disable-xdp) DISABLE_XDP=true", "xdp: {disabled: $disableXDP}", "  detect_xdp\n", `"$AGENT_BINARY" xdp-probe`} {
		if !strings.Contains(string(content), want) {
			t.Fatalf("installer lacks %q", want)
		}
	}
}
