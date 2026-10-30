package dnsproviderremote

import (
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestHuaweiZoneLookupRejectsPaginationIdentityDrift(t *testing.T) {
	const (
		zoneID    = "zone-hw-authoritative"
		projectID = "0123456789abcdef0123456789abcdef"
	)
	for _, test := range []struct {
		name        string
		total       int
		next        string
		wantSuccess bool
	}{
		{name: "stable unique zone", total: 1, wantSuccess: true},
		{name: "total count reveals another zone", total: 2},
		{name: "next link reveals another page", total: 1, next: "/v2/zones?marker=next"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var zoneCalls, recordCalls, mutationCalls atomic.Int32
			handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch {
				case request.Method == http.MethodGet && request.URL.Path == "/v2/zones":
					zoneCalls.Add(1)
					writeTestJSON(t, writer, map[string]any{
						"zones":    []any{map[string]any{"id": zoneID, "name": testZone + "."}},
						"metadata": map[string]any{"total_count": test.total},
						"links":    map[string]any{"next": test.next},
					})
				case request.Method == http.MethodGet && request.URL.Path == "/v2.1/zones/"+zoneID+"/recordsets":
					recordCalls.Add(1)
					writeTestJSON(t, writer, map[string]any{
						"recordsets": []any{}, "metadata": map[string]any{"total_count": 0},
						"links": map[string]any{"next": ""},
					})
				case request.Method == http.MethodPost && request.URL.Path == "/v2.1/zones/"+zoneID+"/recordsets":
					mutationCalls.Add(1)
					writer.WriteHeader(http.StatusCreated)
					writeTestJSON(t, writer, huaweiZoneIdentityRecord(zoneID))
				case request.Method == http.MethodGet && request.URL.Path == "/v2.1/zones/"+zoneID+"/recordsets/record-hw-zone":
					recordCalls.Add(1)
					writeTestJSON(t, writer, huaweiZoneIdentityRecord(zoneID))
				default:
					t.Errorf("unexpected Huawei request %s %s", request.Method, request.URL.String())
					writer.WriteHeader(http.StatusNotFound)
				}
			})
			adapter, source := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerHuawei, ZoneName: testZone,
				Credentials: map[string]string{
					"access_key": "zone-access", "secret_key": "zone-secret",
					"region": "cn-north-4", "project_id": projectID,
				},
			}, handler, time.Second)

			handle, err := adapter.PresentTXT(t.Context(), testChallenge())
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("PresentTXT() error = %v", err)
				}
				payload, decodeErr := decodeHandle(handle.RecordRef, testHandleKeyring(t))
				remoteID, _, _, legacy, recordErr := decodeHuaweiRecordID(payload.RemoteRecordID)
				if decodeErr != nil || recordErr != nil || legacy || payload.ProviderType != providerHuawei ||
					payload.RemoteZoneID != zoneID || remoteID != "record-hw-zone" {
					t.Fatalf("decoded handle payload=%+v remote=%q legacy=%t errors=%v/%v",
						payload, remoteID, legacy, decodeErr, recordErr)
				}
				if recordCalls.Load() != 2 || mutationCalls.Load() != 1 {
					t.Fatalf("record calls=%d mutations=%d, want 2/1", recordCalls.Load(), mutationCalls.Load())
				}
			} else {
				var remote *Error
				if !errors.As(err, &remote) || remote.Code != CodeRecordMismatch || remote.Temporary ||
					handle.RecordRef != "" {
					t.Fatalf("PresentTXT() = (%+v,%+v), want permanent record mismatch", handle, err)
				}
				if recordCalls.Load() != 0 || mutationCalls.Load() != 0 {
					t.Fatalf("record calls=%d mutations=%d, want zero after ambiguous zone", recordCalls.Load(), mutationCalls.Load())
				}
			}
			if zoneCalls.Load() != 1 || !source.credentialsCleared() {
				t.Fatalf("zone calls=%d credentials cleared=%t", zoneCalls.Load(), source.credentialsCleared())
			}
		})
	}
}

func huaweiZoneIdentityRecord(zoneID string) map[string]any {
	return map[string]any{
		"id": "record-hw-zone", "zone_id": zoneID, "name": testOwner,
		"type": "TXT", "ttl": 300, "records": []string{`"` + testValue + `"`},
	}
}
