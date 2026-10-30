package dnsproviderremote

import (
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// N5: dnsapi.cn Record.List returns name/type/line with string id/ttl, and
// Record.Info returns sub_domain/record_type/record_line. Both must decode.
func TestDecodeDNSPodRecordRealWireShapes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want reconcileRecord
	}{
		{name: "Record.List live response (live-retest2 N5)",
			raw: `{"id":"2435866202","name":"4sgu4ydh.cdn","line":"默认","line_id":"0","type":"A","ttl":"600",` +
				`"value":"198.51.100.78","weight":null,"mx":"0","enabled":"1","status":"enabled",` +
				`"monitor_status":"","remark":"","updated_on":"2026-10-24 04:17:08","use_aqb":"no"}`,
			want: reconcileRecord{ID: "2435866202", Name: "4sgu4ydh.cdn", Type: "A", Value: "198.51.100.78", TTL: 600, Line: "默认"}},
		{name: "Record.Info documented response",
			raw: `{"id":"50","sub_domain":"@","record_type":"A","record_line":"默认","value":"96.126.115.73",` +
				`"mx":"0","ttl":"600","enabled":"1","monitor_status":"","remark":"","updated_on":"2014-06-05 09:47:59","domain_id":"9"}`,
			want: reconcileRecord{ID: "50", Name: "@", Type: "A", Value: "96.126.115.73", TTL: 600, Line: "默认"}},
		{name: "numeric id ttl and string weight",
			raw:  `{"id":16894439,"name":"www","type":"A","line":"默认","ttl":300,"value":"192.0.2.10","weight":"20"}`,
			want: reconcileRecord{ID: "16894439", Name: "www", Type: "A", Value: "192.0.2.10", TTL: 300, Line: "默认", Weight: 20}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeDNSPodReconcileRecord([]byte(test.raw))
			if err != nil || got != test.want {
				t.Fatalf("decode = (%+v, %v), want %+v", got, err, test.want)
			}
		})
	}
	for name, raw := range map[string]string{
		"conflicting name spellings": `{"id":"1","name":"a","sub_domain":"b","type":"A","line":"默认","ttl":"600","value":"192.0.2.1"}`,
		"non-numeric ttl":            `{"id":"1","name":"a","type":"A","line":"默认","ttl":"6x","value":"192.0.2.1"}`,
		"weight above 100":           `{"id":"1","name":"a","type":"A","line":"默认","ttl":"600","weight":"101","value":"192.0.2.1"}`,
		"missing line":               `{"id":"1","name":"a","type":"A","ttl":"600","value":"192.0.2.1"}`,
	} {
		if _, err := decodeDNSPodReconcileRecord([]byte(raw)); ErrorCodeOf(err) != CodeInvalidResponse {
			t.Fatalf("%s: error = %v, want invalid response", name, err)
		}
	}
}

// The post-mutation Lookup of a created CNAME owner reads Record.List; with
// the live response shape it must see the record as complete, not malformed.
func TestDNSPodReconcileLookupAcceptsLiveRecordList(t *testing.T) {
	const body = `{"status":{"code":"1","message":"Action completed successful"},` +
		`"info":{"sub_domains":"1","record_total":"1","records_num":"1"},"records":[` +
		`{"id":"2435866202","name":"www","line":"默认","line_id":"0","type":"A","ttl":"600",` +
		`"value":"192.0.2.10","weight":null,"mx":"0","enabled":"1","status":"enabled",` +
		`"monitor_status":"","remark":"","updated_on":"2026-10-24 04:17:08","use_aqb":"no"}]}`
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/Record.List" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	config := completeTestConfig(reconcileHTTPProviderConfig(providerDNSPodCN))
	providerAdapter, _ := newProviderTestAdapter(t, config, handler, time.Second)
	remote := &providerReconcileRemote{adapter: providerAdapter}
	lookup, err := remote.Lookup(t.Context(), config, dnscheck.ProviderOperation{
		Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
		Value: "192.0.2.10", TTL: 600,
	})
	if err != nil || !lookup.TargetComplete || lookup.RecordID != "2435866202" || lookup.Conflict || lookup.Ambiguous {
		t.Fatalf("Lookup() = (%+v, %v), want complete record 2435866202", lookup, err)
	}
}
