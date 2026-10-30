package ddos

import (
	"slices"
	"strings"
	"testing"
)

func TestSiteDropPortsOutliveSpecAndAreOutsideItsDigest(t *testing.T) {
	runner := &fakeRunner{}
	manager, err := NewManager(t.Context(), runner, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetSiteDropPorts(t.Context(), []uint16{8443, 0, 443, 8443}); err != nil {
		t.Fatal(err)
	}
	if got := manager.SiteDropPorts(); !slices.Equal(got, []uint16{443, 8443}) {
		t.Fatalf("ports = %v", got)
	}
	first := runner.batches[len(runner.batches)-1]
	for _, want := range []string{
		"add chain inet cdnca_ddos site_drop { type filter hook input priority -6; policy accept; }",
		"add element inet cdnca_ddos site_drop_ports { 443, 8443 }",
		`add rule inet cdnca_ddos site_drop meta iif != lo meta l4proto tcp tcp dport @site_drop_ports counter name "site_drop" drop`,
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("batch lacks %q:\n%s", want, first)
		}
	}

	spec, _ := NewSpec(testDDoS(t), []PortRange{{80, 80}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	if batch := runner.batches[len(runner.batches)-1]; strings.Contains(batch, "site_drop") {
		t.Fatalf("spec batch touches the site drop:\n%s", batch)
	}
	// Removing the spec re-creates the site drop in the same batch.
	if err := manager.Apply(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	removal := runner.batches[len(runner.batches)-1]
	if !strings.Contains(removal, "delete table inet cdnca_ddos") ||
		strings.Index(removal, "site_drop_ports { 443, 8443 }") < strings.Index(removal, "delete table") {
		t.Fatalf("removal lost the site drop:\n%s", removal)
	}

	// Lifting it deletes its objects (the table stays for a spec).
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetSiteDropPorts(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	lift := runner.batches[len(runner.batches)-1]
	if !strings.Contains(lift, "delete chain inet cdnca_ddos site_drop") || strings.Contains(lift, "delete table") {
		t.Fatalf("lift batch:\n%s", lift)
	}
	if len(manager.SiteDropPorts()) != 0 {
		t.Fatal("ports kept after lift")
	}
}

func TestSiteDropFailedBatchKeepsPreviousPorts(t *testing.T) {
	runner := &fakeRunner{}
	manager, _ := NewManager(t.Context(), runner, t.TempDir())
	if err := manager.SetSiteDropPorts(t.Context(), []uint16{443}); err != nil {
		t.Fatal(err)
	}
	runner.fail = "--check"
	if err := manager.SetSiteDropPorts(t.Context(), []uint16{8443}); err == nil {
		t.Fatal("failed batch reported success")
	}
	if got := manager.SiteDropPorts(); !slices.Equal(got, []uint16{443}) {
		t.Fatalf("ports = %v", got)
	}
}

func TestSiteDropCounterReadsNamedCounter(t *testing.T) {
	runner := &fakeRunner{}
	manager, err := NewManager(t.Context(), runner, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// No site drop ports: no counter, no nft call.
	calls := len(runner.calls)
	if _, ok, err := manager.SiteDropCounter(t.Context()); ok || err != nil || len(runner.calls) != calls {
		t.Fatalf("SiteDropCounter() without ports = %v, %v (calls %d→%d)", ok, err, calls, len(runner.calls))
	}
	got, ok, err := parseSiteDropCounter([]byte(`{"nftables":[{"metainfo":{}},{"counter":{"family":"inet","name":"drop_tcp_null","table":"cdnca_ddos","packets":1,"bytes":40}},{"counter":{"family":"inet","name":"site_drop","table":"cdnca_ddos","packets":12,"bytes":720}}]}`))
	if err != nil || !ok || got != (AutoCounter{Packets: 12, Bytes: 720}) {
		t.Fatalf("parseSiteDropCounter() = %v, %v, %v", got, ok, err)
	}
	if _, ok, err := parseSiteDropCounter([]byte(`{"nftables":[{"metainfo":{}}]}`)); ok || err != nil {
		t.Fatalf("missing counter = %v, %v", ok, err)
	}
	if _, _, err := parseSiteDropCounter([]byte(`not json`)); err == nil {
		t.Fatal("garbage listing accepted")
	}
	if err := manager.SetSiteDropPorts(t.Context(), []uint16{443}); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	_, _, _ = manager.SiteDropCounter(t.Context())
	if len(runner.calls) != 1 || strings.Join(runner.calls[0], " ") != "--json list counter inet cdnca_ddos site_drop" {
		t.Fatalf("calls = %v", runner.calls)
	}
}
