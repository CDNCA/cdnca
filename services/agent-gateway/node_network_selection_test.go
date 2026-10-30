package gateway

import (
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestNodeNetworkSelectionValidation(t *testing.T) {
	for _, test := range []struct {
		source string
		names  []string
		valid  bool
	}{
		{"default_route", []string{"ens17"}, true}, {"unavailable", nil, true},
		{"guess", []string{"ens17"}, false}, {"default_route", nil, false},
		{"default_route", []string{"docker0"}, false}, {"default_route", []string{"ens17", "ens17"}, false},
		{"unavailable", []string{"ens17"}, false},
	} {
		value := &agentv1.NodeTelemetryV1{SchemaVersion: 1, NetworkInterfaces: []*agentv1.NodeNetworkInterfaceMetricsV1{{Name: "ens17"}},
			NetworkSelection: &agentv1.NodeNetworkSelectionV1{Source: test.source, Interfaces: test.names}}
		if validateNodeTelemetry(value) != test.valid {
			t.Fatalf("invalid validation: %+v", value.NetworkSelection)
		}
	}
}

func TestNodeDDoSDropValidation(t *testing.T) {
	drop := func(kind string, packets uint64) *agentv1.NodeDDoSDropV1 {
		return &agentv1.NodeDDoSDropV1{Kind: kind, Packets: packets, Bytes: packets * 40}
	}
	for name, test := range map[string]struct {
		drops []*agentv1.NodeDDoSDropV1
		valid bool
	}{
		"none":       {nil, true},
		"sorted":     {[]*agentv1.NodeDDoSDropV1{drop("ct_invalid", 1), drop("tcp_fin", 2), drop("tcp_xmas", 3)}, true},
		"unsorted":   {[]*agentv1.NodeDDoSDropV1{drop("tcp_xmas", 1), drop("ct_invalid", 1)}, false},
		"duplicate":  {[]*agentv1.NodeDDoSDropV1{drop("tcp_null", 1), drop("tcp_null", 1)}, false},
		"unknown":    {[]*agentv1.NodeDDoSDropV1{drop("tcp_ack", 1)}, false},
		"overflow":   {[]*agentv1.NodeDDoSDropV1{drop("tcp_null", 1<<63)}, false},
		"nil member": {[]*agentv1.NodeDDoSDropV1{nil}, false},
	} {
		if validateNodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, DdosDrops: test.drops}) != test.valid {
			t.Errorf("%s: validation != %v", name, test.valid)
		}
	}
}

func TestNodeXDPStatusValidation(t *testing.T) {
	drop := func(kind string) *agentv1.NodeDDoSDropV1 {
		return &agentv1.NodeDDoSDropV1{Kind: kind, Packets: 1, Bytes: 60}
	}
	for name, test := range map[string]struct {
		status *agentv1.NodeXDPStatusV1
		valid  bool
	}{
		"absent":         {nil, true},
		"native":         {&agentv1.NodeXDPStatusV1{Mode: "native", Interfaces: []string{"eth0=native"}, Drops: []*agentv1.NodeDDoSDropV1{drop("tcp_null"), drop("xdp_block")}}, true},
		"mixed generic":  {&agentv1.NodeXDPStatusV1{Mode: "generic", Interfaces: []string{"eth0=native", "eth1=generic"}}, true},
		"fallback":       {&agentv1.NodeXDPStatusV1{Mode: "nftables", Reason: "verify_failed", Detail: "link on eth0 is detached"}, true},
		"disabled":       {&agentv1.NodeXDPStatusV1{Mode: "disabled", Reason: "disabled"}, true},
		"unknown mode":   {&agentv1.NodeXDPStatusV1{Mode: "offload", Interfaces: []string{"eth0=native"}}, false},
		"no interfaces":  {&agentv1.NodeXDPStatusV1{Mode: "native"}, false},
		"no reason":      {&agentv1.NodeXDPStatusV1{Mode: "nftables"}, false},
		"unknown reason": {&agentv1.NodeXDPStatusV1{Mode: "nftables", Reason: "other"}, false},
		"drops off":      {&agentv1.NodeXDPStatusV1{Mode: "nftables", Reason: "load_failed", Drops: []*agentv1.NodeDDoSDropV1{drop("xdp_ban")}}, false},
		"bad nic":        {&agentv1.NodeXDPStatusV1{Mode: "native", Interfaces: []string{"eth0"}}, false},
		"unsorted nics":  {&agentv1.NodeXDPStatusV1{Mode: "native", Interfaces: []string{"eth1=native", "eth0=native"}}, false},
		"unknown drop":   {&agentv1.NodeXDPStatusV1{Mode: "native", Interfaces: []string{"eth0=native"}, Drops: []*agentv1.NodeDDoSDropV1{drop("ct_invalid")}}, false},
		"detail newline": {&agentv1.NodeXDPStatusV1{Mode: "nftables", Reason: "load_failed", Detail: "a\nb"}, false},
	} {
		if got := validateNodeXDPStatus(test.status); got != test.valid {
			t.Errorf("%s: valid=%v", name, got)
		}
	}
	if !validateNodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, Xdp: &agentv1.NodeXDPStatusV1{Mode: "disabled", Reason: "disabled"}}) ||
		validateNodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, Xdp: &agentv1.NodeXDPStatusV1{Mode: "x"}}) {
		t.Fatal("telemetry does not validate xdp")
	}
}

func TestNodeSiteDropValidation(t *testing.T) {
	const a, b = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	for name, test := range map[string]struct {
		drop  *agentv1.NodeSiteDropV1
		valid bool
	}{
		"absent":    {nil, true},
		"sorted":    {&agentv1.NodeSiteDropV1{SiteIds: []string{a, b}, Packets: 3, Bytes: 180}, true},
		"empty":     {&agentv1.NodeSiteDropV1{Packets: 3}, false},
		"unsorted":  {&agentv1.NodeSiteDropV1{SiteIds: []string{b, a}}, false},
		"duplicate": {&agentv1.NodeSiteDropV1{SiteIds: []string{a, a}}, false},
		"upper":     {&agentv1.NodeSiteDropV1{SiteIds: []string{"AAAAAAAA-1111-4111-8111-111111111111"}}, false},
		"overflow":  {&agentv1.NodeSiteDropV1{SiteIds: []string{a}, Bytes: 1 << 63}, false},
	} {
		if validateNodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, SiteDrop: test.drop}) != test.valid {
			t.Errorf("%s: validation != %v", name, test.valid)
		}
	}
}

// NodeDDoSProtectionV1 vocabulary.
func TestNodeDDoSProtectionValidation(t *testing.T) {
	for name, test := range map[string]struct {
		status *agentv1.NodeDDoSProtectionV1
		valid  bool
	}{
		"absent":         {nil, true},
		"applied":        {&agentv1.NodeDDoSProtectionV1{State: "applied"}, true},
		"failed":         {&agentv1.NodeDDoSProtectionV1{State: "failed", Detail: "nft: Error: syntax error"}, true},
		"unavailable":    {&agentv1.NodeDDoSProtectionV1{State: "unavailable", Reason: "nft_missing", Detail: "nft command not found"}, true},
		"unknown state":  {&agentv1.NodeDDoSProtectionV1{State: "degraded"}, false},
		"no reason":      {&agentv1.NodeDDoSProtectionV1{State: "unavailable"}, false},
		"unknown reason": {&agentv1.NodeDDoSProtectionV1{State: "unavailable", Reason: "gone"}, false},
		"stray reason":   {&agentv1.NodeDDoSProtectionV1{State: "applied", Reason: "nft_missing"}, false},
		"stray detail":   {&agentv1.NodeDDoSProtectionV1{State: "pending", Detail: "x"}, false},
		"newline":        {&agentv1.NodeDDoSProtectionV1{State: "failed", Detail: "a\nb"}, false},
		"too long":       {&agentv1.NodeDDoSProtectionV1{State: "failed", Detail: strings.Repeat("x", 257)}, false},
	} {
		if got := validateNodeDDoSProtection(test.status); got != test.valid {
			t.Errorf("%s: valid = %v", name, got)
		}
	}
}

// fz-x11: NODE_TELEMETRY_DETAIL mounts and port group override receipts.
func TestValidateNodeTelemetryDetail(t *testing.T) {
	valid := &agentv1.NodeTelemetryV1{SchemaVersion: 1,
		Mounts: []*agentv1.NodeMountV1{{Path: "/", Device: "8:1", Fstype: "ext4"},
			{Path: "/snap/x", Device: "7:0", Fstype: "squashfs", ReadOnly: true, FilterReason: "squashfs"}},
		PortGroupOverrides: []*agentv1.NodePortGroupOverrideV1{{PortGroupId: "stream-1", State: "applied"},
			{PortGroupId: "web-tcp", State: "inactive", Reason: "manual"}}}
	if !validateNodeTelemetry(valid) {
		t.Fatal("valid telemetry detail refused")
	}
	for name, value := range map[string]*agentv1.NodeTelemetryV1{
		"unsorted mounts": {SchemaVersion: 1, Mounts: []*agentv1.NodeMountV1{{Path: "/b", Device: "8:1"}, {Path: "/a", Device: "8:1"}}},
		"bad device":      {SchemaVersion: 1, Mounts: []*agentv1.NodeMountV1{{Path: "/", Device: "sda"}}},
		"unknown reason":  {SchemaVersion: 1, Mounts: []*agentv1.NodeMountV1{{Path: "/", Device: "8:1", FilterReason: "x"}}},
		"inactive no reason": {SchemaVersion: 1, PortGroupOverrides: []*agentv1.NodePortGroupOverrideV1{
			{PortGroupId: "web-tcp", State: "inactive"}}},
		"reason when applied": {SchemaVersion: 1, PortGroupOverrides: []*agentv1.NodePortGroupOverrideV1{
			{PortGroupId: "web-tcp", State: "applied", Reason: "manual"}}},
		"bad group id": {SchemaVersion: 1, PortGroupOverrides: []*agentv1.NodePortGroupOverrideV1{{PortGroupId: "Web", State: "applied"}}},
	} {
		if validateNodeTelemetry(value) {
			t.Fatalf("%s accepted", name)
		}
	}
}
