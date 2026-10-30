package dnsproviderremote

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeleteTXTConfirmsPostMutationAbsence(t *testing.T) {
	tests := []struct {
		name          string
		postGetStatus int
		postGetRecord map[string]any
		wantCode      ErrorCode
		wantTemporary bool
	}{
		{
			name:          "provider confirms not found",
			postGetStatus: http.StatusNotFound,
		},
		{
			name: "record remains present",
			postGetRecord: map[string]any{
				"id": "record-cf-target", "zone_id": "zone-cf", "name": testOwner,
				"type": "TXT", "content": testValue,
			},
			wantCode: CodeUnavailable, wantTemporary: true,
		},
		{
			name: "record identity drifts",
			postGetRecord: map[string]any{
				"id": "record-cf-target", "zone_id": "zone-cf", "name": testOwner,
				"type": "TXT", "content": testOtherValue,
			},
			wantCode: CodeRecordMismatch,
		},
		{
			name:          "post-delete read is temporary",
			postGetStatus: http.StatusBadGateway,
			wantCode:      CodeUnavailable,
			wantTemporary: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var getCalls, deleteCalls atomic.Int32
			requestOrder := make([]string, 0, 3)
			config := ProviderConfig{
				ProviderType: providerCloudflare,
				ZoneName:     testZone,
				Credentials:  map[string]string{"api_token": "delete-confirmation-secret"},
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "api.cloudflare.com" || r.Header.Get("Authorization") != "Bearer delete-confirmation-secret" {
					t.Errorf("unexpected Cloudflare request identity: host=%q authorization=%q", r.Host, r.Header.Get("Authorization"))
				}
				const path = "/zones/zone-cf/dns_records/record-cf-target"
				if r.URL.Path != path {
					t.Errorf("unexpected request path %q", r.URL.Path)
				}
				switch r.Method {
				case http.MethodGet:
					call := getCalls.Add(1)
					requestOrder = append(requestOrder, "get")
					if call == 1 {
						writeCloudflareDeleteConfirmationRecord(t, w, testValue)
						return
					}
					if test.postGetStatus != 0 {
						w.WriteHeader(test.postGetStatus)
						if test.postGetStatus == http.StatusNotFound {
							writeTestJSON(t, w, map[string]any{
								"success": false, "result": nil, "errors": []map[string]any{{"code": 81044}},
							})
						}
						return
					}
					writeTestJSON(t, w, map[string]any{
						"success": true,
						"result":  test.postGetRecord,
					})
				case http.MethodDelete:
					deleteCalls.Add(1)
					requestOrder = append(requestOrder, "delete")
					writeTestJSON(t, w, map[string]any{
						"success": true,
						"result":  map[string]any{"id": "record-cf-target"},
					})
				default:
					t.Errorf("unexpected method %s", r.Method)
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			})
			adapter, source := newProviderTestAdapter(t, config, handler, time.Second)
			handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
				Provider: providerCloudflare, Zone: testZone, ZoneID: "zone-cf", RecordID: "record-cf-target", Owner: testOwner,
			})
			if err != nil {
				t.Fatal(err)
			}

			err = adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle))
			if test.wantCode == "" {
				if err != nil {
					t.Fatalf("DeleteTXT: %v", err)
				}
			} else {
				assertRemoteError(t, err, test.wantCode)
				var remoteErr *Error
				if !errors.As(err, &remoteErr) || remoteErr.Temporary != test.wantTemporary {
					t.Fatalf("error = %+v, temporary want %t", err, test.wantTemporary)
				}
			}
			if got := getCalls.Load(); got != 2 {
				t.Fatalf("Record read calls = %d, want exactly 2 (preflight and one post-delete confirmation)", got)
			}
			if got := deleteCalls.Load(); got != 1 {
				t.Fatalf("Record delete calls = %d, want exactly 1", got)
			}
			if len(requestOrder) != 3 || requestOrder[0] != "get" || requestOrder[1] != "delete" || requestOrder[2] != "get" {
				t.Fatalf("request order = %v, want [get delete get]", requestOrder)
			}
			if !source.credentialsCleared() {
				t.Fatal("provider credentials were retained")
			}
		})
	}
}

func TestDeleteTXTConfirmsDNSPodNotFoundAfterSuccessfulRemove(t *testing.T) {
	const (
		dpID  = "123456"
		dpKey = "delete-confirmation-dp-key"
	)
	var getCalls, removeCalls atomic.Int32
	requestOrder := make([]string, 0, 3)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "dnsapi.cn" || r.Method != http.MethodPost || r.ParseForm() != nil ||
			r.Form.Get("login_token") != dpID+","+dpKey {
			t.Errorf("unexpected DNSPod request authentication")
		}
		switch r.URL.Path {
		case "/Record.Info":
			call := getCalls.Add(1)
			requestOrder = append(requestOrder, "info")
			if call == 1 {
				writeTestJSON(t, w, map[string]any{
					"status": map[string]any{"code": "1"},
					"domain": map[string]any{"id": "example.test", "domain": testZone},
					"record": map[string]any{"id": "record-dnspod-target", "sub_domain": testRelative,
						"record_type": "TXT", "value": testValue, "record_line": "默认", "ttl": "600"},
				})
				return
			}
			writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "10"}})
		case "/Record.Remove":
			removeCalls.Add(1)
			requestOrder = append(requestOrder, "remove")
			writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "1"}})
		default:
			t.Errorf("unexpected DNSPod request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	config := ProviderConfig{
		ProviderType: providerDNSPodCN,
		ZoneName:     testZone,
		Credentials:  map[string]string{"dp_id": dpID, "dp_key": dpKey},
	}
	adapter, source := newProviderTestAdapter(t, config, handler, time.Second)
	handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
		Provider: providerDNSPodCN, Zone: testZone, ZoneID: testZone, RecordID: "record-dnspod-target", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("DeleteTXT DNSPod absence: %v", err)
	}
	if getCalls.Load() != 2 || removeCalls.Load() != 1 {
		t.Fatalf("Record.Info calls = %d, Record.Remove calls = %d, want 2/1", getCalls.Load(), removeCalls.Load())
	}
	if len(requestOrder) != 3 || requestOrder[0] != "info" || requestOrder[1] != "remove" || requestOrder[2] != "info" {
		t.Fatalf("request order = %v, want [info remove info]", requestOrder)
	}
	if !source.credentialsCleared() {
		t.Fatal("provider credentials were retained")
	}
}

func TestDeleteTXTConfirmsHuaweiPostMutationIdentityDrift(t *testing.T) {
	const (
		zoneID    = "zone-hw-delete-confirmation"
		remoteID  = "record-hw-delete-confirmation"
		projectID = "0123456789abcdef0123456789abcdef"
		accessKey = "delete-confirmation-hw-access"
		secretKey = "delete-confirmation-hw-secret"
	)
	var listCalls, directCalls, deleteCalls atomic.Int32
	requestOrder := make([]string, 0, 6)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "dns.cn-north-4.myhuaweicloud.com" || r.Header.Get("X-Project-Id") != projectID ||
			r.Header.Get("Authorization") == "" {
			t.Errorf("unexpected Huawei request identity")
		}
		ownerPath := "/v2.1/zones/" + zoneID + "/recordsets"
		directPath := ownerPath + "/" + remoteID
		switch {
		case r.Method == http.MethodGet && r.URL.Path == ownerPath:
			call := listCalls.Add(1)
			requestOrder = append(requestOrder, "list")
			query := r.URL.Query()
			if query.Get("limit") != strconv.Itoa(recoveryPageSize) || query.Get("offset") != "0" ||
				query.Get("name") != testOwner || query.Get("type") != "TXT" {
				t.Errorf("Huawei owner query = %q", r.URL.RawQuery)
			}
			writeTestJSON(t, w, map[string]any{
				"recordsets": []any{map[string]any{
					"id": remoteID, "zone_id": zoneID, "name": testOwner, "type": "TXT",
					"records": []string{strconv.Quote(testValue)},
				}},
				"metadata": map[string]any{"total_count": 1}, "links": map[string]any{"next": ""},
			})
			if call > 3 {
				t.Errorf("unexpected Huawei owner-list call %d", call)
			}
		case r.Method == http.MethodGet && r.URL.Path == directPath:
			call := directCalls.Add(1)
			requestOrder = append(requestOrder, "get")
			recordValues := []string{strconv.Quote(testValue)}
			if call == 2 {
				recordValues = []string{strconv.Quote(testValue), strconv.Quote(testOtherValue)}
			}
			writeTestJSON(t, w, map[string]any{
				"id": remoteID, "zone_id": zoneID, "name": testOwner, "type": "TXT",
				"records": recordValues,
			})
		case r.Method == http.MethodDelete && r.URL.Path == directPath:
			deleteCalls.Add(1)
			requestOrder = append(requestOrder, "delete")
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected Huawei request %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	})
	config := ProviderConfig{
		ProviderType: providerHuawei,
		ZoneName:     testZone,
		Credentials: map[string]string{
			"access_key": accessKey, "secret_key": secretKey, "region": "cn-north-4", "project_id": projectID,
		},
	}
	adapter, source := newProviderTestAdapter(t, config, handler, time.Second)
	recordID, err := encodeHuaweiRecordID(remoteID, testValue, []string{testValue})
	if err != nil {
		t.Fatal(err)
	}
	handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
		Provider: providerHuawei, Zone: testZone, ZoneID: zoneID, RecordID: recordID, Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle))
	assertRemoteError(t, err, CodeRecordMismatch)
	if listCalls.Load() != 3 || directCalls.Load() != 2 || deleteCalls.Load() != 1 {
		t.Fatalf("Huawei calls list=%d direct=%d delete=%d, want 3/2/1", listCalls.Load(), directCalls.Load(), deleteCalls.Load())
	}
	wantOrder := []string{"list", "get", "list", "delete", "list", "get"}
	if len(requestOrder) != len(wantOrder) {
		t.Fatalf("Huawei request order = %v, want %v", requestOrder, wantOrder)
	}
	for index, want := range wantOrder {
		if requestOrder[index] != want {
			t.Fatalf("Huawei request order = %v, want %v", requestOrder, wantOrder)
		}
	}
	if !source.credentialsCleared() {
		t.Fatal("Huawei operation retained decrypted credentials")
	}
}

func TestDeleteTXTConfirmsDNSLAPostMutationIdentityDrift(t *testing.T) {
	const (
		apiID     = "delete-confirmation-dnsla-id"
		apiSecret = "delete-confirmation-dnsla-secret"
		zoneID    = "zone-dnsla-delete-confirmation"
		recordID  = "record-dnsla-delete-confirmation"
	)
	var listCalls, deleteCalls atomic.Int32
	requestOrder := make([]string, 0, 3)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if r.Host != "api.dns.la" || !ok || username != apiID || password != apiSecret {
			t.Errorf("unexpected DNS.LA authentication")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/recordList":
			call := listCalls.Add(1)
			requestOrder = append(requestOrder, "list")
			query := r.URL.Query()
			if query.Get("pageIndex") != "1" || query.Get("pageSize") != strconv.Itoa(dnsLARecordPageSize) ||
				query.Get("domainId") != zoneID || query.Get("type") != "16" ||
				query.Get("host") != testRelative {
				t.Errorf("DNS.LA record-list query = %q", r.URL.RawQuery)
			}
			recordValue := testValue
			if call == 2 {
				recordValue = testOtherValue
			}
			writeTestJSON(t, w, map[string]any{"code": http.StatusOK, "data": map[string]any{
				"total": 1, "results": []map[string]any{{
					"id": recordID, "domainId": zoneID, "host": testRelative,
					"type": 16, "data": recordValue, "ttl": 600,
				}},
			}})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/record":
			deleteCalls.Add(1)
			requestOrder = append(requestOrder, "delete")
			if r.URL.Query().Get("id") != recordID {
				t.Errorf("DNS.LA delete id = %q, want %q", r.URL.Query().Get("id"), recordID)
			}
			writeTestJSON(t, w, map[string]any{"code": http.StatusOK, "data": nil})
		default:
			t.Errorf("unexpected DNS.LA request %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	})
	config := ProviderConfig{
		ProviderType: providerDNSLA, ZoneName: testZone,
		Credentials: map[string]string{"api_id": apiID, "api_secret": apiSecret},
	}
	adapter, source := newProviderTestAdapter(t, config, handler, time.Second)
	handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
		Provider: providerDNSLA, Zone: testZone, ZoneID: zoneID, RecordID: recordID, Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle))
	assertRemoteError(t, err, CodeRecordMismatch)
	if listCalls.Load() != 2 || deleteCalls.Load() != 1 {
		t.Fatalf("DNS.LA calls list=%d delete=%d, want 2/1", listCalls.Load(), deleteCalls.Load())
	}
	wantOrder := []string{"list", "delete", "list"}
	if len(requestOrder) != len(wantOrder) {
		t.Fatalf("DNS.LA request order = %v, want %v", requestOrder, wantOrder)
	}
	for index, want := range wantOrder {
		if requestOrder[index] != want {
			t.Fatalf("DNS.LA request order = %v, want %v", requestOrder, wantOrder)
		}
	}
	if !source.credentialsCleared() {
		t.Fatal("DNS.LA operation retained decrypted credentials")
	}
}

func writeCloudflareDeleteConfirmationRecord(t *testing.T, writer http.ResponseWriter, value string) {
	t.Helper()
	writeTestJSON(t, writer, map[string]any{
		"success": true,
		"result": map[string]any{
			"id": "record-cf-target", "zone_id": "zone-cf", "name": testOwner,
			"type": "TXT", "content": value,
		},
	})
}
