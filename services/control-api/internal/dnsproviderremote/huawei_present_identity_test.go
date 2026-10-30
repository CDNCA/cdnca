package dnsproviderremote

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
)

func TestHuaweiPresentVerifiesCreatedRecordIdentity(t *testing.T) {
	const (
		accessKey = "huawei-present-access-sensitive"
		secretKey = "huawei-present-secret-sensitive"
		projectID = "0123456789abcdef0123456789abcdef"
		zoneID    = "zone-hw-present"
		recordID  = "record-hw-present"
	)
	record := func(overrides map[string]any) map[string]any {
		value := map[string]any{
			"id": recordID, "zone_id": zoneID, "name": testOwner,
			"type": "TXT", "ttl": 300, "records": []string{`"` + testValue + `"`},
		}
		for name, override := range overrides {
			value[name] = override
		}
		return value
	}
	tests := []struct {
		name          string
		createStatus  int
		getStatus     int
		getBody       map[string]any
		wantCode      ErrorCode
		wantTemporary bool
		wantSuccess   bool
	}{
		{
			name: "201 exact authoritative get succeeds", createStatus: http.StatusCreated,
			getBody: record(nil), wantSuccess: true,
		},
		{
			name: "202 exact authoritative get succeeds", createStatus: http.StatusAccepted,
			getBody: record(nil), wantSuccess: true,
		},
		{
			name: "accepted record not found remains temporary unknown", createStatus: http.StatusAccepted,
			getStatus: http.StatusNotFound, wantCode: CodeUnavailable, wantTemporary: true,
		},
		{
			name: "accepted foreign record is a mismatch", createStatus: http.StatusAccepted,
			getBody: record(map[string]any{"id": "record-hw-foreign"}), wantCode: CodeRecordMismatch,
		},
		{
			name: "accepted identity drift is a mismatch", createStatus: http.StatusAccepted,
			getBody: record(map[string]any{"name": "_other.example.test."}), wantCode: CodeRecordMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var zoneCalls, listCalls, createCalls, getCalls, deleteCalls atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "dns.cn-north-4.myhuaweicloud.com" || r.Header.Get("X-Project-Id") != projectID ||
					!strings.HasPrefix(r.Header.Get("Authorization"), "SDK-HMAC-SHA256 Access="+accessKey+",") {
					t.Errorf("unexpected Huawei authentication")
				}
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/v2/zones":
					zoneCalls.Add(1)
					if r.URL.Query().Get("name") != testZone+"." || r.URL.Query().Get("type") != "public" {
						t.Errorf("zone query = %q", r.URL.RawQuery)
					}
					writeTestJSON(t, w, map[string]any{"zones": []any{map[string]any{"id": zoneID, "name": testZone + "."}}})
				case r.Method == http.MethodGet && r.URL.Path == "/v2.1/zones/"+zoneID+"/recordsets":
					listCalls.Add(1)
					if r.URL.Query().Get("name") != testOwner || r.URL.Query().Get("type") != "TXT" ||
						r.URL.Query().Get("limit") != strconv.Itoa(recoveryPageSize) || r.URL.Query().Get("offset") != "0" {
						t.Errorf("recordset query = %q", r.URL.RawQuery)
					}
					writeTestJSON(t, w, map[string]any{
						"recordsets": []any{}, "metadata": map[string]any{"total_count": 0},
						"links": map[string]any{"next": ""},
					})
				case r.Method == http.MethodPost && r.URL.Path == "/v2.1/zones/"+zoneID+"/recordsets":
					createCalls.Add(1)
					var body struct {
						Name    string   `json:"name"`
						Type    string   `json:"type"`
						TTL     int      `json:"ttl"`
						Records []string `json:"records"`
					}
					if err := decodeJSONBody(r, &body); err != nil || body.Name != testOwner || body.Type != "TXT" ||
						body.TTL != 300 || len(body.Records) != 1 || body.Records[0] != `"`+testValue+`"` {
						t.Errorf("create body = %+v", body)
					}
					w.WriteHeader(test.createStatus)
					writeTestJSON(t, w, record(nil))
				case r.Method == http.MethodGet && r.URL.Path == "/v2.1/zones/"+zoneID+"/recordsets/"+recordID:
					getCalls.Add(1)
					if test.getStatus == http.StatusNotFound {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					if test.getStatus != 0 {
						w.WriteHeader(test.getStatus)
						return
					}
					writeTestJSON(t, w, test.getBody)
				case r.Method == http.MethodDelete:
					deleteCalls.Add(1)
					t.Errorf("unexpected delete after failed identity recheck")
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected Huawei request %s %s", r.Method, r.URL.String())
					w.WriteHeader(http.StatusNotFound)
				}
			})
			adapter, source := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerHuawei, ZoneName: testZone,
				Credentials: map[string]string{
					"access_key": accessKey, "secret_key": secretKey, "region": "cn-north-4", "project_id": projectID,
				},
			}, handler, time.Second)

			handle, err := adapter.PresentTXT(t.Context(), testChallenge())
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("PresentTXT: %v", err)
				}
				if handle.ProviderRef != testProviderRef {
					t.Fatalf("unexpected provider ref: %+v", handle)
				}
				payload, err := decodeHandle(handle.RecordRef, testHandleKeyring(t))
				if err != nil || payload.ProviderType != providerHuawei || payload.RemoteZoneID != zoneID {
					t.Fatalf("decoded Huawei handle: payload=%+v error=%v", payload, err)
				}
				remoteID, ownDigest, expectedDigest, legacy, err := decodeHuaweiRecordID(payload.RemoteRecordID)
				if err != nil || legacy || remoteID != recordID || !digestMatches(ownDigest, testValue) ||
					!huaweiValuesDigestMatches(expectedDigest, []string{testValue}) {
					t.Fatalf("Huawei record handle id=%q legacy=%t error=%v", remoteID, legacy, err)
				}
			} else {
				if handle != (acmeworker.RemoteTXTHandle{}) {
					t.Fatalf("failed present returned handle %+v", handle)
				}
				assertRemoteError(t, err, test.wantCode)
				var remoteError *Error
				if !errors.As(err, &remoteError) || remoteError.Temporary != test.wantTemporary {
					t.Fatalf("error = %+v, want temporary=%v", err, test.wantTemporary)
				}
			}
			if zoneCalls.Load() != 1 || listCalls.Load() != 1 || createCalls.Load() != 1 ||
				getCalls.Load() != 1 || deleteCalls.Load() != 0 {
				t.Fatalf("calls zone/list/create/get/delete=%d/%d/%d/%d/%d, want 1/1/1/1/0",
					zoneCalls.Load(), listCalls.Load(), createCalls.Load(), getCalls.Load(), deleteCalls.Load())
			}
			if !source.credentialsCleared() {
				t.Fatal("provider credentials were retained")
			}
		})
	}
}
