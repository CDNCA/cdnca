package dnsproviderremote

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSPodObserveAndDeleteRequireDefaultLineAndTTL(t *testing.T) {
	for _, test := range []struct {
		name        string
		line        string
		ttl         int
		omitLine    bool
		omitTTL     bool
		wantSuccess bool
	}{
		{name: "matching identity", line: "默认", ttl: 600, wantSuccess: true},
		{name: "missing line", ttl: 600, omitLine: true},
		{name: "empty line", ttl: 600},
		{name: "wrong line", line: "境外", ttl: 600},
		{name: "missing ttl", line: "默认", omitTTL: true},
		{name: "zero ttl", line: "默认"},
		{name: "wrong ttl", line: "默认", ttl: 300},
	} {
		for _, lifecycle := range []string{"observe", "delete"} {
			t.Run(lifecycle+"/"+test.name, func(t *testing.T) {
				var infoCalls, removeCalls atomic.Int32
				handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					if request.ParseForm() != nil {
						t.Fatal("failed to parse DNSPod request")
					}
					switch request.URL.Path {
					case "/Record.Info":
						if infoCalls.Add(1) > 1 {
							writeTestJSON(t, writer, map[string]any{"status": map[string]any{"code": "10"}})
							return
						}
						record := map[string]any{
							"id": "record-dnspod-cleanup", "sub_domain": testRelative,
							"record_type": "TXT", "value": testValue,
						}
						if !test.omitLine {
							record["record_line"] = test.line
						}
						if !test.omitTTL {
							record["ttl"] = test.ttl
						}
						writeTestJSON(t, writer, map[string]any{
							"status": map[string]any{"code": "1"},
							"domain": map[string]any{"id": "zone-dnspod-cleanup", "domain": testZone},
							"record": record,
						})
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
				adapter, source := newProviderTestAdapter(t, config, handler, time.Second)
				handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
					Provider: providerDNSPodCN, Zone: testZone, ZoneID: testZone,
					RecordID: "record-dnspod-cleanup", Owner: testOwner,
				})
				if err != nil {
					t.Fatal(err)
				}
				challenge := testChallengeWithHandle(handle)
				if lifecycle == "observe" {
					err = adapter.ObserveTXT(t.Context(), challenge)
				} else {
					err = adapter.DeleteTXT(t.Context(), challenge)
				}
				if test.wantSuccess {
					if err != nil {
						t.Fatalf("%s error = %v", lifecycle, err)
					}
				} else if ErrorCodeOf(err) != CodeRecordMismatch {
					t.Fatalf("%s error = %v, want %s", lifecycle, err, CodeRecordMismatch)
				}
				wantInfo, wantRemove := int32(1), int32(0)
				if lifecycle == "delete" && test.wantSuccess {
					wantInfo, wantRemove = 2, 1
				}
				if infoCalls.Load() != wantInfo || removeCalls.Load() != wantRemove {
					t.Fatalf("info/remove calls=%d/%d, want %d/%d",
						infoCalls.Load(), removeCalls.Load(), wantInfo, wantRemove)
				}
				if !source.credentialsCleared() {
					t.Fatal("credentials were retained")
				}
			})
		}
	}
}
