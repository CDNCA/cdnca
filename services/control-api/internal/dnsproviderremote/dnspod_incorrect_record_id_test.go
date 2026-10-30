package dnsproviderremote

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// dnsapi.cn answer for Record.Info on a deleted record_id, captured read-only
// 2026-10-27 (record 2437516767 after the fix-acmedns 73 run removed it).
var dnsPodIncorrectRecordID = map[string]any{
	"status": map[string]any{"code": "8", "message": "Incorrect record ID"},
}

func dnsPodInfoTXT(id string) map[string]any {
	return map[string]any{
		"status": map[string]any{"code": "1"},
		"domain": map[string]any{"id": "86733245", "domain": testZone},
		"record": map[string]any{
			"id": id, "sub_domain": testRelative, "record_type": "TXT", "record_line": "默认",
			"record_line_id": "0", "value": testValue, "ttl": "600", "enabled": "1",
		},
	}
}

// Cleanup of a record already gone (code 8) succeeds without Record.Remove,
// so a retry is not stuck at acme_challenge_cleanup_failed forever.
func TestDNSPodDeleteTreatsIncorrectRecordIDAsAbsent(t *testing.T) {
	var removeCalls atomic.Int32
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/Record.Info":
			writeTestJSON(t, writer, dnsPodIncorrectRecordID)
		case "/Record.Remove":
			removeCalls.Add(1)
			writeTestJSON(t, writer, map[string]any{"status": map[string]any{"code": "1"}})
		default:
			t.Errorf("unexpected DNSPod path %q", request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	config := ProviderConfig{
		ProviderType: providerDNSPodCN, ZoneName: testZone,
		Credentials: map[string]string{"dp_id": "123456", "dp_key": "cleanup-secret"},
	}
	adapter, _ := newProviderTestAdapter(t, config, handler, time.Second)
	handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
		Provider: providerDNSPodCN, Zone: testZone, ZoneID: testZone, RecordID: "2437516767", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.DeleteTXT(t.Context(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("DeleteTXT() error = %v, want nil for an already deleted record", err)
	}
	if removeCalls.Load() != 0 {
		t.Fatalf("Record.Remove calls = %d, want 0", removeCalls.Load())
	}
}

// Create answers with a numeric id and its own name/status spelling; the
// handle is built once Record.Info confirms the record, even when the first
// Info read of the fresh record says code 8.
func TestDNSPodPresentConfirmsCreatedRecordThroughInfo(t *testing.T) {
	previousDelay := dnsPodCreatedInfoDelay
	dnsPodCreatedInfoDelay = time.Millisecond
	t.Cleanup(func() { dnsPodCreatedInfoDelay = previousDelay })

	var infoCalls atomic.Int32
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/Record.Create":
			writeTestJSON(t, writer, map[string]any{
				"status": map[string]any{"code": "1", "message": "Action completed successful"},
				"record": map[string]any{"id": 2437516767, "name": testRelative + "." + testZone, "status": "enabled"},
			})
		case "/Record.Info":
			if infoCalls.Add(1) == 1 {
				writeTestJSON(t, writer, dnsPodIncorrectRecordID)
				return
			}
			writeTestJSON(t, writer, dnsPodInfoTXT("2437516767"))
		default:
			t.Errorf("unexpected DNSPod path %q", request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerDNSPodCN, ZoneName: testZone,
		Credentials: map[string]string{"dp_id": "123456", "dp_key": "present-secret"},
	}, handler, time.Second)

	handle, err := adapter.PresentTXT(t.Context(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT() error = %v", err)
	}
	if handle.RecordRef == "" || infoCalls.Load() != 2 {
		t.Fatalf("handle=%+v info calls=%d", handle, infoCalls.Load())
	}
}
