package dnsproviderremote

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// DNSPod answers a write on a line outside the account's plan (province
// lines below 企业版) with status 26 记录线路错误: not in plan, so the smart
// schedule falls back to the carrier line instead of retrying a malformed
// response.
func TestDNSPodRecordLineRefusedIsNotInPlan(t *testing.T) {
	var writes atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Record.Create", "/Record.Modify":
			writes.Add(1)
			writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "26", "message": "记录线路错误"}})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	config := completeTestConfig(reconcileHTTPProviderConfig(providerDNSPodCN))
	providerAdapter, _ := newProviderTestAdapter(t, config, handler, time.Second)
	remote := &providerReconcileRemote{adapter: providerAdapter}
	for _, operation := range []dnscheck.ProviderOperation{
		{Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: "广东移动"},
		{Action: dnscheck.ProviderUpdate, RecordID: "target", Name: "www.example.test.", Type: dnscheck.RecordA,
			Value: "192.0.2.20", TTL: 300, Line: "广东移动", PreviousValue: "192.0.2.10", PreviousTTL: 300, PreviousLine: "广东移动"},
	} {
		if _, err := remote.Mutate(t.Context(), config, operation); ErrorCodeOf(err) != CodeLineNotInPlan {
			t.Fatalf("%s: error %v, want %s", operation.Action, err, CodeLineNotInPlan)
		}
	}
	if writes.Load() != 2 {
		t.Fatalf("writes = %d, want 2", writes.Load())
	}
}
