package dnsproviderremote

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeleteTXTTreatsProviderMissingRecordAsIdempotent(t *testing.T) {
	var removeCalls atomic.Int32
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerDNSPodCN,
		ZoneName:     testZone,
		Credentials:  map[string]string{"dp_id": "12345", "dp_key": "secret-key"},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path == "/Record.Remove" {
			removeCalls.Add(1)
		}
		writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "10"}})
	}), time.Second)
	handle, err := encodeTestHandle(t, testChallenge(), ProviderConfig{
		ProviderType: providerDNSPodCN,
		ZoneName:     testZone,
		Credentials:  map[string]string{"dp_id": "12345", "dp_key": "secret-key"},
	}, recordHandle{
		Provider: providerDNSPodCN,
		Zone:     testZone,
		ZoneID:   testZone,
		RecordID: "missing-record",
		Owner:    testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge := testChallengeWithHandle(handle)
	if err := adapter.ObserveTXT(context.Background(), challenge); ErrorCodeOf(err) != CodeRecordNotFound {
		t.Fatalf("ObserveTXT error = %v, want %s", err, CodeRecordNotFound)
	}
	if err := adapter.DeleteTXT(context.Background(), challenge); err != nil {
		t.Fatalf("DeleteTXT missing record: %v", err)
	}
	if got := removeCalls.Load(); got != 0 {
		t.Fatalf("Record.Remove calls = %d, want 0", got)
	}
}
