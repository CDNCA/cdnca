package dnsproviderremote

import (
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

func TestHuaweiReconcileDelete404AfterLookupIsIdempotent(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		wantResult string
	}{
		{name: "confirmed delete", status: http.StatusNoContent, wantResult: "target"},
		{name: "record disappeared after lookup", status: http.StatusNotFound, wantResult: "target"},
	} {
		t.Run(test.name, func(t *testing.T) {
			zoneCalls := 0
			deleteCalls := 0
			handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch {
				case request.Method == http.MethodGet && request.URL.Path == "/v2/zones":
					zoneCalls++
					writeTestJSON(t, writer, map[string]any{"zones": []any{
						map[string]any{"id": "zone-hw", "name": "example.test."},
					}})
				case request.Method == http.MethodGet && request.URL.Path == "/v2.1/zones/zone-hw/recordsets/target":
					writeTestJSON(t, writer, map[string]any{"id": "target", "zone_id": "zone-hw", "name": "www.example.test.",
						"type": "A", "ttl": 300, "records": []string{"192.0.2.10"}})
				case request.Method == http.MethodDelete &&
					request.URL.Path == "/v2.1/zones/zone-hw/recordsets/target":
					deleteCalls++
					writer.WriteHeader(test.status)
				default:
					t.Errorf("unexpected Huawei request %s %s", request.Method, request.URL.RequestURI())
					writer.WriteHeader(http.StatusInternalServerError)
				}
			})
			config := reconcileHTTPProviderConfig(providerHuawei)
			adapter, _ := newProviderTestAdapter(t, config, handler, time.Second)
			result, err := (&providerReconcileRemote{adapter: adapter}).Mutate(t.Context(), completeTestConfig(config),
				dnscheck.ProviderOperation{
					Action: dnscheck.ProviderDelete, RecordID: "target", Name: "www.example.test.",
					Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300,
				})
			if err != nil || result != test.wantResult {
				t.Fatalf("Mutate()=(%q,%v), want (%q,nil)", result, err, test.wantResult)
			}
			if zoneCalls != 1 || deleteCalls != 1 {
				t.Fatalf("calls zone/delete=%d/%d, want 1/1", zoneCalls, deleteCalls)
			}
		})
	}
}
