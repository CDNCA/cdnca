package edgepublish

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func v2Snapshot(t *testing.T, site string, mutate func(*siteRuntimeV2Document)) []byte {
	t.Helper()
	document := siteRuntimeV2Document{Schema: siteRuntimeV2Schema, ConfigurationScopeID: site, Sites: []siteRuntimeV2Site{{
		ID: "site-" + site, Domains: []string{site + ".example"},
		Listeners: []siteRuntimeV2Listener{{ID: "l1", AddressFamily: "dual_stack", Port: 80}},
	}}}
	if mutate != nil {
		mutate(&document)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func footprintOf(t *testing.T, raw []byte) scopeFootprint {
	t.Helper()
	footprint, err := decodeScopeFootprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	return footprint
}

func streams(protocol string, port int) func(*siteRuntimeV2Document) {
	return func(d *siteRuntimeV2Document) {
		d.Streams = &edgeconfig.StreamRuntime{StreamsV2: []edgeconfig.L4StreamRuntimeV2{{
			Listener: edgeconfig.L4ListenerV2{Protocol: protocol, Port: port}}}}
	}
}

func passthrough(port int, names ...string) func(*siteRuntimeV2Document) {
	return func(d *siteRuntimeV2Document) {
		d.Streams = &edgeconfig.StreamRuntime{StreamsV2: []edgeconfig.L4StreamRuntimeV2{{
			Listener: edgeconfig.L4ListenerV2{Protocol: "tcp", Port: port}, TLSPassthrough: true, ServerNames: names}}}
	}
}

func tlsSite(port int64) func(*siteRuntimeV2Document) {
	return func(d *siteRuntimeV2Document) {
		d.Sites[0].Listeners = []siteRuntimeV2Listener{{ID: "l2", AddressFamily: "ipv4", Port: port,
			Protocols: []string{"http1", "http2", "http3"}, TLS: &siteRuntimeV2ListenerTLS{CertificateVersionID: "cert"}}}
	}
}

func both(changes ...func(*siteRuntimeV2Document)) func(*siteRuntimeV2Document) {
	return func(d *siteRuntimeV2Document) {
		for _, change := range changes {
			change(d)
		}
	}
}

// TestCrossScopeCompositionRules keeps only what two scopes physically cannot
// share on one node (decisions/multitenant-composition-compat-2026-10-16): a
// domain, a site, a plain L4 socket, a plain TCP stream with a plaintext
// website, a plain UDP stream with HTTP/3, and one SNI on one TLS port.
func TestCrossScopeCompositionRules(t *testing.T) {
	tlsOn80 := tlsSite(80)
	ccV2 := func(d *siteRuntimeV2Document) {
		d.Sites[0].Listeners[0].Security = &edgeconfig.ListenerSecurity{CC: &edgeconfig.CCV2SiteBinding{}}
	}
	for name, c := range map[string]struct {
		mine, theirs []byte
		reason       string
	}{
		"distinct tenants share the node": {v2Snapshot(t, "b", nil), v2Snapshot(t, "a", nil), ""},
		"plaintext and TLS on one port":   {v2Snapshot(t, "b", tlsOn80), v2Snapshot(t, "a", nil), ""},
		"both carry CC v2":                {v2Snapshot(t, "b", ccV2), v2Snapshot(t, "a", ccV2), ""},
		"both carry L4 on different ports": {v2Snapshot(t, "b", streams("tcp", 9001)),
			v2Snapshot(t, "a", streams("tcp", 9000)), ""},
		"TCP and UDP on the same number": {v2Snapshot(t, "b", streams("udp", 9000)),
			v2Snapshot(t, "a", streams("tcp", 9000)), ""},
		"same domain in another case": {v2Snapshot(t, "b", func(d *siteRuntimeV2Document) {
			d.Sites[0].Domains = []string{"A.example"}
		}), v2Snapshot(t, "a", nil), "domain a.example"},
		"same site": {v2Snapshot(t, "b", func(d *siteRuntimeV2Document) { d.Sites[0].ID = "site-a" }),
			v2Snapshot(t, "a", nil), "site site-a"},
		"same plain TCP L4 port": {v2Snapshot(t, "b", streams("tcp", 9000)),
			v2Snapshot(t, "a", streams("tcp", 9000)), "tcp port 9000 is already used by another tenant's L4 forwarding"},
		"same UDP L4 port": {v2Snapshot(t, "b", streams("udp", 5353)),
			v2Snapshot(t, "a", streams("udp", 5353)), "udp port 5353 is already used"},
		"website on another tenant's TCP L4 port": {v2Snapshot(t, "b", nil),
			v2Snapshot(t, "a", streams("tcp", 80)), "tcp port 80 is already used by another tenant's L4 forwarding"},
		"TCP L4 on another tenant's website port": {v2Snapshot(t, "b", streams("tcp", 80)),
			v2Snapshot(t, "a", nil), "tcp port 80 is already used by another tenant's website"},
		"plain TCP L4 on another tenant's TLS website port": {v2Snapshot(t, "b", streams("tcp", 443)),
			v2Snapshot(t, "a", tlsSite(443)), ""},
		"TLS website on another tenant's plain TCP L4 port": {v2Snapshot(t, "b", tlsSite(443)),
			v2Snapshot(t, "a", streams("tcp", 443)), ""},
		"UDP L4 on another tenant's HTTP/3 port": {v2Snapshot(t, "b", streams("udp", 443)),
			v2Snapshot(t, "a", tlsSite(443)), "udp port 443 is already used by another tenant's HTTP/3 website"},
		"HTTP/3 website on another tenant's UDP L4 port": {v2Snapshot(t, "b", tlsSite(443)),
			v2Snapshot(t, "a", streams("udp", 443)), "udp port 443 is already used by another tenant's L4 forwarding"},
		"TLS passthrough split by SNI": {v2Snapshot(t, "b", passthrough(8443, "b.example.com")),
			v2Snapshot(t, "a", passthrough(8443, "a.example.com", "c.example.com")), ""},
		"TLS passthrough next to plain TCP L4": {v2Snapshot(t, "b", passthrough(8443, "b.example.com")),
			v2Snapshot(t, "a", streams("tcp", 8443)), ""},
		"TLS passthrough on a plaintext website port": {v2Snapshot(t, "b", passthrough(80, "b.example.com")),
			v2Snapshot(t, "a", nil), ""},
		"TLS passthrough next to a TLS website": {v2Snapshot(t, "b", passthrough(443, "b.example.com")),
			v2Snapshot(t, "a", tlsSite(443)), ""},
		"same SNI on one TLS passthrough port": {v2Snapshot(t, "b", passthrough(8443, "c.example.com")),
			v2Snapshot(t, "a", passthrough(8443, "a.example.com", "C.example.com")),
			"SNI c.example.com on tcp port 8443 is already used by another tenant's L4 forwarding"},
		"same wildcard on one TLS passthrough port": {v2Snapshot(t, "b", passthrough(8443, "*.example.com")),
			v2Snapshot(t, "a", passthrough(8443, "*.example.com")),
			"SNI *.example.com on tcp port 8443 is already used by another tenant's L4 forwarding"},
		"wildcard next to a name it covers": {v2Snapshot(t, "b", passthrough(8443, "*.example.com")),
			v2Snapshot(t, "a", passthrough(8443, "x.example.com")), ""},
		"PROXY stream on a port shared with another tenant": {v2Snapshot(t, "b", func(d *siteRuntimeV2Document) {
			streams("tcp", 8443)(d)
			d.Streams.StreamsV2[0].ProxyProtocolOutbound = true
		}), v2Snapshot(t, "a", passthrough(8443, "a.example.com")),
			"tcp port 8443 is shared with another tenant, so its streams cannot use PROXY protocol"},
		"same SNI on different ports": {v2Snapshot(t, "b", passthrough(8443, "c.example.com")),
			v2Snapshot(t, "a", passthrough(9443, "c.example.com")), ""},
		"SNI of another tenant's TLS website": {v2Snapshot(t, "b", passthrough(443, "a.example")),
			v2Snapshot(t, "a", tlsSite(443)), "SNI a.example on tcp port 443 is already used by another tenant's website"},
		"TLS website on another tenant's SNI": {v2Snapshot(t, "b", both(tlsSite(443))),
			v2Snapshot(t, "a", passthrough(443, "b.example")), "SNI b.example on tcp port 443 is already used by another tenant's L4 forwarding"},
		"SNI of another tenant's website on another port": {v2Snapshot(t, "b", passthrough(8443, "a.example")),
			v2Snapshot(t, "a", tlsSite(443)), ""},
	} {
		got := footprintOf(t, c.mine).conflict(footprintOf(t, c.theirs))
		if c.reason == "" && got != "" || c.reason != "" && !strings.Contains(got, c.reason) {
			t.Errorf("%s: conflict %q, want %q", name, got, c.reason)
		}
	}

	if _, err := decodeScopeFootprint([]byte(`{"schema":"unknown"}`)); err == nil {
		t.Error("unknown schema decoded")
	}
}

// TestCrossScopeSharesManagedWAF (waf-share, 73 adm-fix-a2: tenant B retried
// 349 times against tenant A's managed WAF on node 667d0b7b): dynamic routing
// composes managed WAF scopes like any other (one tier location per CRS
// profile pack and limits, the site's exclusions in the request's
// transaction ID), so a managed WAF on either side, or both with different
// profiles and exclusions, shares the node. The other rules still apply.
func TestCrossScopeSharesManagedWAF(t *testing.T) {
	managedWAF := func(pack string, exclusions ...int) func(*siteRuntimeV2Document) {
		return func(d *siteRuntimeV2Document) {
			d.Sites[0].Listeners[0].Security = &edgeconfig.ListenerSecurity{ManagedWAF: &edgeconfig.ManagedWAF{
				Profile: edgeconfig.CRSProfileRef{PackID: pack, Version: "1.0.0", SHA256: strings.Repeat("a", 64)}, Exclusions: exclusions}}
		}
	}
	for name, c := range map[string]struct {
		mine, theirs []byte
		reason       string
	}{
		"mine has a managed WAF":   {v2Snapshot(t, "b", managedWAF("system/crs-pl1")), v2Snapshot(t, "a", nil), ""},
		"theirs has a managed WAF": {v2Snapshot(t, "b", nil), v2Snapshot(t, "a", managedWAF("system/crs-pl1")), ""},
		"both, other profiles and exclusions": {v2Snapshot(t, "b", managedWAF("system/crs-pl2", 941100)),
			v2Snapshot(t, "a", managedWAF("system/crs-pl1", 942100)), ""},
		"a managed WAF does not lift the domain rule": {v2Snapshot(t, "b", both(managedWAF("system/crs-pl1"), func(d *siteRuntimeV2Document) {
			d.Sites[0].Domains = []string{"a.example"}
		})), v2Snapshot(t, "a", managedWAF("system/crs-pl1")), "domain a.example is already served by another tenant"},
	} {
		got := footprintOf(t, c.mine).conflict(footprintOf(t, c.theirs))
		if c.reason == "" && got != "" || c.reason != "" && !strings.Contains(got, c.reason) {
			t.Errorf("%s: conflict %q, want %q", name, got, c.reason)
		}
	}
	if err := firstCrossScopeConflict(t.Context(), footprintOf(t, v2Snapshot(t, "b", managedWAF("system/crs-pl2"))),
		[]colocatedConfiguration{{node: uuid.New(), snapshot: v2Snapshot(t, "a", managedWAF("system/crs-pl1", 942100))}}); err != nil {
		t.Fatalf("managed WAF scopes refused on a shared node: %v", err)
	}
}

// TestCrossScopeConflictSkipsUnreadableNeighbour: another tenant's
// unreadable configuration on the node does not block this publication,
// while a readable one still refuses a real conflict.
func TestCrossScopeConflictSkipsUnreadableNeighbour(t *testing.T) {
	node := uuid.New()
	mine := footprintOf(t, v2Snapshot(t, "b", streams("tcp", 9000)))
	unreadable := colocatedConfiguration{node: node, snapshot: []byte(`{"schema":"unknown"}`)}
	if err := firstCrossScopeConflict(t.Context(), mine, []colocatedConfiguration{unreadable}); err != nil {
		t.Fatalf("unreadable neighbour blocked the publication: %v", err)
	}
	conflicting := colocatedConfiguration{node: node, snapshot: v2Snapshot(t, "a", streams("tcp", 9000))}
	err := firstCrossScopeConflict(t.Context(), mine, []colocatedConfiguration{unreadable, conflicting})
	var conflict *CrossScopeConflictError
	if !errors.As(err, &conflict) || conflict.NodeID != node {
		t.Fatalf("readable conflict behind an unreadable neighbour: %v", err)
	}
}
