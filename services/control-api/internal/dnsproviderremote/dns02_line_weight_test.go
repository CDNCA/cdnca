package dnsproviderremote

import (
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

type dns02DNSPodFixture struct {
	t         *testing.T
	mu        sync.Mutex
	line      string
	weight    uint32
	mutations atomic.Int32
}

func (fixture *dns02DNSPodFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fixture.t.Fatal(err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	record := map[string]any{
		"id": "record-1", "sub_domain": "www", "record_type": "A",
		"value": "192.0.2.10", "ttl": "300", "record_line": fixture.line, "weight": strconv.FormatUint(uint64(fixture.weight), 10),
	}
	switch r.URL.Path {
	case "/Record.Info":
		writeTestJSON(fixture.t, w, map[string]any{
			"status": map[string]any{"code": "1"}, "record": record,
		})
	case "/Record.Modify":
		fixture.mutations.Add(1)
		if r.Form.Get("record_line") != "境外" || r.Form.Get("weight") != "80" {
			fixture.t.Errorf("modify routing = line %q weight %q", r.Form.Get("record_line"), r.Form.Get("weight"))
		}
		fixture.line = r.Form.Get("record_line")
		weight, _ := strconv.ParseUint(r.Form.Get("weight"), 10, 32)
		fixture.weight = uint32(weight)
		writeTestJSON(fixture.t, w, map[string]any{
			"status": map[string]any{"code": "1"}, "record": map[string]any{"id": "record-1"},
		})
	default:
		fixture.t.Fatalf("unexpected path %q", r.URL.Path)
	}
}

func TestDNS02DNSPodUsesExactLineAndWeightForReplay(t *testing.T) {
	fixture := &dns02DNSPodFixture{t: t, line: "默认", weight: 20}
	config := completeTestConfig(reconcileHTTPProviderConfig(providerDNSPodCN))
	providerAdapter, _ := newProviderTestAdapter(t, config, fixture, time.Second)
	remote := &providerReconcileRemote{adapter: providerAdapter}
	operation := dnscheck.ProviderOperation{
		Action: dnscheck.ProviderUpdate, RecordID: "record-1", Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: "境外", Weight: 80,
		PreviousValue: "192.0.2.10", PreviousTTL: 300, PreviousLine: "默认", PreviousWeight: 20,
	}

	before, err := remote.Lookup(t.Context(), config, operation)
	if err != nil || before.TargetComplete || before.Conflict || before.Ambiguous {
		t.Fatalf("before lookup = (%+v, %v)", before, err)
	}
	if recordID, err := remote.Mutate(t.Context(), config, operation); err != nil || recordID != "record-1" {
		t.Fatalf("mutate = (%q, %v)", recordID, err)
	}
	after, err := remote.Lookup(t.Context(), config, operation)
	if err != nil || !after.TargetComplete || after.RecordID != "record-1" {
		t.Fatalf("after lookup = (%+v, %v)", after, err)
	}
	if fixture.mutations.Load() != 1 {
		t.Fatalf("mutations = %d", fixture.mutations.Load())
	}
}

func TestDNS02UnsupportedProviderRoutingFailsBeforeNetwork(t *testing.T) {
	for _, providerType := range []string{providerCloudflare, providerAliyun, providerHuawei, providerDNSCom, providerDNSLA} {
		t.Run(providerType, func(t *testing.T) {
			calls := atomic.Int32{}
			config := completeTestConfig(reconcileHTTPProviderConfig(providerType))
			providerAdapter, _ := newProviderTestAdapter(t, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				calls.Add(1)
			}), time.Second)
			remote := &providerReconcileRemote{adapter: providerAdapter}
			operation := dnscheck.ProviderOperation{
				Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
				Value: "192.0.2.10", TTL: 300, Line: "境外", Weight: 80,
			}
			if _, err := remote.Mutate(t.Context(), config, operation); ErrorCodeOf(err) != CodeUnsupported {
				t.Fatalf("Mutate() error = %v", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("network calls = %d", calls.Load())
			}
		})
	}
}

var _ http.Handler = (*dns02DNSPodFixture)(nil)
