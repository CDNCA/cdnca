package dnsproviderremote

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSLARequiresTTL600ForCreatedAndExistingIdentity(t *testing.T) {
	for _, ttl := range []struct {
		name  string
		set   bool
		value uint32
		valid bool
	}{
		{name: "missing"},
		{name: "zero", set: true},
		{name: "wrong", set: true, value: 300},
		{name: "matching", set: true, value: 600, valid: true},
	} {
		for _, lifecycle := range []string{"present", "observe", "delete"} {
			t.Run(lifecycle+"/"+ttl.name, func(t *testing.T) {
				var domainCalls, createCalls, listCalls, deleteCalls atomic.Int32
				deleted := false
				handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					switch {
					case request.Method == http.MethodGet && request.URL.Path == "/api/domain":
						domainCalls.Add(1)
						writeTestJSON(t, writer, map[string]any{"code": 200, "data": map[string]any{
							"id": "zone-dnsla-ttl", "domain": testZone + ".",
						}})
					case request.Method == http.MethodPost && request.URL.Path == "/api/record":
						createCalls.Add(1)
						writeTestJSON(t, writer, map[string]any{"code": 200, "data": map[string]any{
							"id": "record-dnsla-ttl",
						}})
					case request.Method == http.MethodGet && request.URL.Path == "/api/recordList":
						listCalls.Add(1)
						results := []map[string]any{}
						if !deleted {
							record := map[string]any{
								"id": "record-dnsla-ttl", "domainId": "zone-dnsla-ttl",
								"host": testRelative, "type": 16, "data": testValue,
							}
							if ttl.set {
								record["ttl"] = ttl.value
							}
							results = append(results, record)
						}
						writeTestJSON(t, writer, map[string]any{"code": 200, "data": map[string]any{
							"total": len(results), "results": results,
						}})
					case request.Method == http.MethodDelete && request.URL.Path == "/api/record":
						deleteCalls.Add(1)
						deleted = true
						writeTestJSON(t, writer, map[string]any{"code": 200, "data": nil})
					default:
						t.Errorf("unexpected DNS.LA request %s %s", request.Method, request.URL.String())
						writer.WriteHeader(http.StatusNotFound)
					}
				})
				config := ProviderConfig{
					ProviderType: providerDNSLA, ZoneName: testZone,
					Credentials: map[string]string{"api_id": "dnsla-ttl-id", "api_secret": "dnsla-ttl-secret"},
				}
				adapter, source := newProviderTestAdapter(t, config, handler, time.Second)
				var err error
				switch lifecycle {
				case "present":
					_, err = adapter.PresentTXT(t.Context(), testChallenge())
				case "observe", "delete":
					handle, handleErr := encodeTestHandle(t, testChallenge(), config, recordHandle{
						Provider: providerDNSLA, Zone: testZone, ZoneID: "zone-dnsla-ttl",
						RecordID: "record-dnsla-ttl", Owner: testOwner,
					})
					if handleErr != nil {
						t.Fatal(handleErr)
					}
					challenge := testChallengeWithHandle(handle)
					if lifecycle == "observe" {
						err = adapter.ObserveTXT(t.Context(), challenge)
					} else {
						err = adapter.DeleteTXT(t.Context(), challenge)
					}
				}

				if ttl.valid && err != nil {
					t.Fatalf("%s matching TTL error = %v", lifecycle, err)
				}
				if !ttl.valid && ErrorCodeOf(err) != CodeInvalidResponse {
					t.Fatalf("%s TTL %s error = %v, want %s", lifecycle, ttl.name, err, CodeInvalidResponse)
				}
				wantDomain, wantCreate, wantLists, wantDeletes := int32(0), int32(0), int32(1), int32(0)
				if lifecycle == "present" {
					wantDomain, wantCreate = 1, 1
				}
				if lifecycle == "delete" && ttl.valid {
					wantLists, wantDeletes = 2, 1
				}
				if domainCalls.Load() != wantDomain || createCalls.Load() != wantCreate ||
					listCalls.Load() != wantLists || deleteCalls.Load() != wantDeletes {
					t.Fatalf("%s TTL %s calls domain/create/list/delete=%d/%d/%d/%d, want %d/%d/%d/%d",
						lifecycle, ttl.name, domainCalls.Load(), createCalls.Load(), listCalls.Load(), deleteCalls.Load(),
						wantDomain, wantCreate, wantLists, wantDeletes)
				}
				if !source.credentialsCleared() {
					t.Fatal("operation retained decrypted credentials")
				}
			})
		}
	}
}
