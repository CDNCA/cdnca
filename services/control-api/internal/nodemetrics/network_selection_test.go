package nodemetrics

import (
	"google.golang.org/protobuf/proto"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestNetworkSelectionDecoderRejectsInventedInterfaces(t *testing.T) {
	for _, test := range []struct {
		name, source string
		names        []string
		valid        bool
	}{
		{"default", "default_route", []string{"ens17"}, true},
		{"unavailable", "unavailable", nil, true},
		{"unknown source", "guess", []string{"ens17"}, false},
		{"missing NIC", "default_route", []string{"eth0"}, false},
		{"duplicates", "default_route", []string{"ens17", "ens17"}, false},
		{"unavailable cannot select", "unavailable", []string{"ens17"}, false},
		{"default cannot be empty", "default_route", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := &agentv1.NodeTelemetryV1{SchemaVersion: 1,
				NetworkInterfaces: []*agentv1.NodeNetworkInterfaceMetricsV1{{Name: "ens17"}},
				NetworkSelection:  &agentv1.NodeNetworkSelectionV1{Source: test.source, Interfaces: test.names}}
			got, err := decodeTelemetry(value)
			if (err == nil) != test.valid {
				t.Fatalf("decode=%+v error=%v", got, err)
			}
			if test.valid && (!validTelemetry(got) || got.NetworkSelection.Source != test.source) {
				t.Fatalf("selection lost: %+v", got)
			}
		})
	}
	if got, err := decodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1}); err != nil || got.NetworkSelection != nil {
		t.Fatal("old Agent compatibility lost")
	}
}

func TestExternalTrafficRouteChangeDoesNotCreateCounterSpike(t *testing.T) {
	start := time.Now().UTC()
	history := []HistoryView{
		{Known: true, ObservedAt: start, Telemetry: &Telemetry{NetworkSelection: &NetworkSelection{Source: "default_route", Interfaces: []string{"ens17"}}, NetworkInterfaces: []NetworkInterface{{Name: "ens17", RXBytes: 100}, {Name: "ens18", RXBytes: 900000}}}},
		{Known: true, ObservedAt: start.Add(time.Minute), Telemetry: &Telemetry{NetworkSelection: &NetworkSelection{Source: "default_route", Interfaces: []string{"ens18"}}, NetworkInterfaces: []NetworkInterface{{Name: "ens17", RXBytes: 200}, {Name: "ens18", RXBytes: 900030}}}},
	}
	items, err := externalTrafficIntervals(history, nil)
	if err != nil || len(items) != 1 || items[0].BytesReceived != 30 {
		t.Fatalf("route switch traffic = %+v, %v", items, err)
	}
}

func TestExternalTrafficUnavailableResetAndMultipleExits(t *testing.T) {
	for _, test := range []struct {
		name      string
		selection *NetworkSelection
		previous  []NetworkInterface
		excluded  map[string]struct{}
		count     int
		rx        uint64
	}{
		{"unknown", nil, nil, nil, 0, 0},
		{"unavailable", &NetworkSelection{Source: "unavailable"}, nil, nil, 0, 0},
		{"new NIC has no baseline", &NetworkSelection{Source: "default_route", Interfaces: []string{"eth0"}}, nil, nil, 0, 0},
		{"counter reset", &NetworkSelection{Source: "default_route", Interfaces: []string{"eth0"}}, []NetworkInterface{{Name: "eth0", RXBytes: 9000}}, nil, 1, 20},
		{"two exits", &NetworkSelection{Source: "default_route", Interfaces: []string{"eth0", "eth1"}}, []NetworkInterface{{Name: "eth0", RXBytes: 10}, {Name: "eth1", RXBytes: 50}}, nil, 1, 30},
		{"one missing baseline invalidates interval", &NetworkSelection{Source: "default_route", Interfaces: []string{"eth0", "eth1"}}, []NetworkInterface{{Name: "eth0", RXBytes: 10}}, nil, 0, 0},
		{"explicit exclusion is true zero", &NetworkSelection{Source: "default_route", Interfaces: []string{"eth0"}}, []NetworkInterface{{Name: "eth0", RXBytes: 10}}, map[string]struct{}{"eth0": {}}, 1, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			start := time.Unix(100, 0).UTC()
			history := []HistoryView{
				{Known: true, ObservedAt: start, Telemetry: &Telemetry{NetworkInterfaces: test.previous}},
				{Known: true, ObservedAt: start.Add(time.Minute), Telemetry: &Telemetry{NetworkSelection: test.selection,
					NetworkInterfaces: []NetworkInterface{{Name: "eth0", RXBytes: 20}, {Name: "eth1", RXBytes: 70}}}},
			}
			items, err := externalTrafficIntervals(history, test.excluded)
			if err != nil || len(items) != test.count || len(items) > 0 && items[0].BytesReceived != test.rx {
				t.Fatalf("intervals = %+v, %v", items, err)
			}
		})
	}
}

func TestTelemetryDecoderCarriesDDoSDrops(t *testing.T) {
	got, err := decodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, DdosDrops: []*agentv1.NodeDDoSDropV1{
		{Kind: "ct_invalid", Packets: 3, Bytes: 120}, {Kind: "tcp_syn_rst", Packets: 5, Bytes: 200}}})
	if err != nil || len(got.DDoSDrops) != 2 || got.DDoSDrops[1] != (DDoSDrop{"tcp_syn_rst", 5, 200}) || !validTelemetry(got) {
		t.Fatalf("decode = %+v, %v", got, err)
	}
	for _, bad := range [][]*agentv1.NodeDDoSDropV1{
		{{Kind: "tcp_xmas"}, {Kind: "tcp_null"}}, {{Kind: "rst"}}, {nil}, {{Kind: "tcp_all", Bytes: 1 << 63}},
	} {
		if _, err := decodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, DdosDrops: bad}); err == nil {
			t.Errorf("drops %v accepted", bad)
		}
	}
	var stored *Telemetry
	if err := decodeStoredTelemetry([]byte(`{"schema_version":1,"total_rx_bytes":0,"total_tx_bytes":0,"ddos_drops":[{"kind":"tcp_null","packets":1,"bytes":40}]}`), &stored); err != nil ||
		stored == nil || len(stored.DDoSDrops) != 1 {
		t.Fatalf("stored telemetry = %+v, %v", stored, err)
	}
}

func TestTelemetryDecoderCarriesXDPStatus(t *testing.T) {
	got, err := decodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, Xdp: &agentv1.NodeXDPStatusV1{
		Mode: "generic", Interfaces: []string{"eth0=generic"}, Drops: []*agentv1.NodeDDoSDropV1{{Kind: "xdp_block", Packets: 4, Bytes: 240}}}})
	if err != nil || got.XDP == nil || got.XDP.Mode != "generic" || got.XDP.Drops[0] != (DDoSDrop{"xdp_block", 4, 240}) || !validTelemetry(got) {
		t.Fatalf("decode = %+v, %v", got, err)
	}
	for _, bad := range []*agentv1.NodeXDPStatusV1{
		{Mode: "nftables"}, {Mode: "native"}, {Mode: "nftables", Reason: "verify_failed", Drops: []*agentv1.NodeDDoSDropV1{{Kind: "xdp_ban"}}},
		{Mode: "generic", Interfaces: []string{"eth0=generic"}, Drops: []*agentv1.NodeDDoSDropV1{nil}},
	} {
		if _, err := decodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, Xdp: bad}); err == nil {
			t.Errorf("xdp %v accepted", bad)
		}
	}
	var stored *Telemetry
	if err := decodeStoredTelemetry([]byte(`{"schema_version":1,"total_rx_bytes":0,"total_tx_bytes":0,"xdp":{"mode":"nftables","reason":"bpf_unavailable","detail":"function not implemented"}}`), &stored); err != nil ||
		stored == nil || stored.XDP == nil || stored.XDP.Reason != "bpf_unavailable" {
		t.Fatalf("stored telemetry = %+v, %v", stored, err)
	}
}

func TestTelemetryDecoderCarriesSiteDrop(t *testing.T) {
	const site = "11111111-1111-4111-8111-111111111111"
	got, err := decodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1,
		SiteDrop: &agentv1.NodeSiteDropV1{SiteIds: []string{site}, Packets: 7, Bytes: 420}})
	if err != nil || got.SiteDrop == nil || got.SiteDrop.Packets != 7 || got.SiteDrop.SiteIDs[0] != site || !validTelemetry(got) {
		t.Fatalf("decodeTelemetry() = %#v, %v", got, err)
	}
	for _, bad := range []*agentv1.NodeSiteDropV1{{}, {SiteIds: []string{"x"}}, {SiteIds: []string{site, site}}} {
		if _, err := decodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, SiteDrop: bad}); err == nil {
			t.Fatalf("site drop %v accepted", bad)
		}
	}
	var stored *Telemetry
	if err := decodeStoredTelemetry([]byte(`{"schema_version":1,"total_rx_bytes":0,"total_tx_bytes":0,"site_drop":{"site_ids":["`+site+`"],"packets":1,"bytes":60}}`), &stored); err != nil ||
		stored == nil || stored.SiteDrop == nil || stored.SiteDrop.Bytes != 60 {
		t.Fatalf("stored = %#v, %v", stored, err)
	}
}

// The node DDoS protection state is decoded, stored and refused
// when malformed.
func TestTelemetryDecoderCarriesDDoSProtection(t *testing.T) {
	got, err := decodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1,
		DdosProtection: &agentv1.NodeDDoSProtectionV1{State: "unavailable", Reason: "nft_missing", Detail: "nft command not found"}})
	if err != nil || got.DDoSProtection == nil || got.DDoSProtection.Reason != "nft_missing" || !validTelemetry(got) {
		t.Fatalf("decode = %+v, %v", got, err)
	}
	for _, bad := range []*agentv1.NodeDDoSProtectionV1{
		{State: "broken"}, {State: "unavailable"}, {State: "unavailable", Reason: "why"},
		{State: "applied", Reason: "nft_missing"}, {State: "off", Detail: "x"}, {State: "failed", Detail: "a\nb"},
	} {
		if _, err := decodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, DdosProtection: bad}); err == nil {
			t.Errorf("ddos protection %v accepted", bad)
		}
	}
	var stored *Telemetry
	if err := decodeStoredTelemetry([]byte(`{"schema_version":1,"total_rx_bytes":0,"total_tx_bytes":0,"ddos_protection":{"state":"failed","detail":"nft: Error"}}`), &stored); err != nil ||
		stored == nil || stored.DDoSProtection == nil || stored.DDoSProtection.State != "failed" {
		t.Fatalf("stored telemetry = %+v, %v", stored, err)
	}
}

// fz-x11: NODE_TELEMETRY_DETAIL mounts and port group override receipts round-trip and are validated.
func TestTelemetryDecoderCarriesMountsAndPortGroupOverrides(t *testing.T) {
	got, err := decodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1,
		Mounts: []*agentv1.NodeMountV1{{Path: "/", Device: "8:1", Fstype: "ext4"},
			{Path: "/etc", Device: "8:1", Fstype: "ext4", Bind: true, FilterReason: "bind_duplicate"}},
		PortGroupOverrides: []*agentv1.NodePortGroupOverrideV1{{PortGroupId: "web-tcp", State: "inactive", Reason: "suggest"}}})
	if err != nil || len(got.Mounts) != 2 || !got.Mounts[1].Bind || got.Mounts[1].FilterReason != "bind_duplicate" ||
		len(got.PortGroupOverrides) != 1 || got.PortGroupOverrides[0].Reason != "suggest" || !validTelemetry(got) {
		t.Fatalf("decodeTelemetry() = %+v, %v", got, err)
	}
	for _, bad := range []*agentv1.NodeTelemetryV1{
		{SchemaVersion: 1, Mounts: []*agentv1.NodeMountV1{{Path: "/", Device: "x"}}},
		{SchemaVersion: 1, Mounts: []*agentv1.NodeMountV1{nil}},
		{SchemaVersion: 1, PortGroupOverrides: []*agentv1.NodePortGroupOverrideV1{{PortGroupId: "web-tcp", State: "standby", Reason: "manual"}}},
	} {
		if _, err := decodeTelemetry(bad); err == nil {
			t.Fatalf("decodeTelemetry(%v) accepted", bad)
		}
	}
	var stored *Telemetry
	if err := decodeStoredTelemetry([]byte(`{"schema_version":1,"total_rx_bytes":0,"total_tx_bytes":0,"mounts":[{"path":"/","device":"8:1","fstype":"ext4","read_only":false,"bind":false}],"port_group_overrides":[{"port_group_id":"web-tcp","state":"applied"}]}`), &stored); err != nil ||
		len(stored.Mounts) != 1 || stored.PortGroupOverrides[0].State != "applied" {
		t.Fatalf("decodeStoredTelemetry() = %+v, %v", stored, err)
	}
}

func TestDeclaresTelemetryDetail(t *testing.T) {
	encode := func(features ...*agentv1.Capability) []byte {
		payload, err := proto.Marshal(&agentv1.AgentCapabilities{Features: features})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	if !DeclaresTelemetryDetail(encode(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_TELEMETRY_DETAIL, ApiVersion: 1})) {
		t.Fatal("v1 declared")
	}
	if DeclaresTelemetryDetail(nil) || DeclaresTelemetryDetail([]byte{0xff}) ||
		DeclaresTelemetryDetail(encode(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING, ApiVersion: 1})) {
		t.Fatal("old agent / no snapshot must read as not declared")
	}
}
