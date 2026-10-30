package dnsproviderremote

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestCloudflareZoneLookupRejectsPaginationIdentityDrift(t *testing.T) {
	const zoneID = "zone-cf-authoritative"
	for _, test := range []struct {
		name        string
		metadata    bool
		partial     bool
		page        int
		perPage     int
		count       int
		totalCount  int
		totalPages  int
		wantSuccess bool
		wantCode    ErrorCode
	}{
		{
			name: "stable unique zone", metadata: true, page: 1, perPage: 2,
			count: 1, totalCount: 1, totalPages: 1, wantSuccess: true,
		},
		{name: "missing metadata uses legacy contract", wantSuccess: true},
		{
			name: "partial metadata", metadata: true, partial: true, page: 1, perPage: 2,
			count: 1, totalCount: 1, totalPages: 1, wantCode: CodeInvalidResponse,
		},
		{
			name: "current page drift", metadata: true, page: 2, perPage: 2,
			count: 1, totalCount: 1, totalPages: 1, wantCode: CodeRecordMismatch,
		},
		{
			name: "page size drift", metadata: true, page: 1, perPage: 1,
			count: 1, totalCount: 1, totalPages: 1, wantCode: CodeRecordMismatch,
		},
		{
			name: "count drift", metadata: true, page: 1, perPage: 2,
			count: 2, totalCount: 1, totalPages: 1, wantCode: CodeRecordMismatch,
		},
		{
			name: "total count reveals another zone", metadata: true, page: 1, perPage: 2,
			count: 1, totalCount: 2, totalPages: 1, wantCode: CodeRecordMismatch,
		},
		{
			name: "total pages reveals another page", metadata: true, page: 1, perPage: 2,
			count: 1, totalCount: 1, totalPages: 2, wantCode: CodeRecordMismatch,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var zoneCalls, mutationCalls atomic.Int32
			handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch {
				case request.Method == http.MethodGet && request.URL.Path == "/zones":
					zoneCalls.Add(1)
					query := request.URL.Query()
					if query.Get("name") != testZone || query.Get("page") != "1" || query.Get("per_page") != "2" {
						t.Errorf("zone query = %q", request.URL.RawQuery)
					}
					response := map[string]any{
						"success": true,
						"result":  []any{map[string]any{"id": zoneID, "name": testZone}},
					}
					if test.metadata {
						resultInfo := map[string]any{
							"page": test.page, "per_page": test.perPage, "count": test.count,
							"total_count": test.totalCount, "total_pages": test.totalPages,
						}
						if test.partial {
							delete(resultInfo, "total_pages")
						}
						response["result_info"] = resultInfo
					}
					writeTestJSON(t, writer, response)
				case request.Method == http.MethodPost && request.URL.Path == "/zones/"+zoneID+"/dns_records":
					mutationCalls.Add(1)
					writeTestJSON(t, writer, map[string]any{
						"success": true,
						"result": map[string]any{
							"id": "record-cf-zone", "zone_id": zoneID, "name": testOwner,
							"type": "TXT", "content": testValue,
						},
					})
				default:
					t.Errorf("unexpected Cloudflare request %s %s", request.Method, request.URL.String())
					writer.WriteHeader(http.StatusNotFound)
				}
			})
			adapter, source := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerCloudflare, ZoneName: testZone,
				Credentials: map[string]string{"api_token": "zone-token"},
			}, handler, time.Second)

			handle, err := adapter.PresentTXT(t.Context(), testChallenge())
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("PresentTXT() error = %v", err)
				}
				requireHandle(t, handle, providerCloudflare, zoneID, "record-cf-zone")
				if mutationCalls.Load() != 1 {
					t.Fatalf("mutations=%d, want 1", mutationCalls.Load())
				}
			} else {
				if ErrorCodeOf(err) != test.wantCode || handle.RecordRef != "" {
					t.Fatalf("PresentTXT() = (%+v,%v), want empty handle and %s", handle, err, test.wantCode)
				}
				if mutationCalls.Load() != 0 {
					t.Fatalf("mutations=%d, want 0", mutationCalls.Load())
				}
			}
			if zoneCalls.Load() != 1 || !source.credentialsCleared() {
				t.Fatalf("zone calls=%d credentials cleared=%t", zoneCalls.Load(), source.credentialsCleared())
			}
		})
	}
}
