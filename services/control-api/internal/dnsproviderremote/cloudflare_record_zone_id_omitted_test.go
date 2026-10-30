package dnsproviderremote

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// Cloudflare's current DNS record responses no longer carry zone_id (observed
// live 2026-10-14 on GET /zones/{id}/dns_records[/{id}] and POST). The record
// is already scoped by the zone in the request path; only a present and
// different zone_id is evidence of a cross-zone answer.
func TestCloudflareRecordResponsesWithoutZoneIDAreAccepted(t *testing.T) {
	const zoneID = "zone-cf-omitted"
	for _, foreign := range []bool{false, true} {
		record := func(id, recordType, content string) map[string]any {
			value := map[string]any{"id": id, "name": strings.TrimSuffix(testOwner, "."), "type": recordType,
				"content": content, "ttl": 300}
			if foreign {
				value["zone_id"] = "another-zone"
			}
			return value
		}
		config := completeTestConfig(reconcileHTTPProviderConfig(providerCloudflare))
		providerAdapter, _ := newProviderTestAdapter(t, config,
			http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch {
				case request.URL.Path == "/zones":
					writeTestJSON(t, writer, map[string]any{"success": true, "result": []any{
						map[string]any{"id": zoneID, "name": testZone},
					}})
				case request.Method == http.MethodPost:
					writeTestJSON(t, writer, map[string]any{"success": true, "result": record("record-txt", "TXT", testValue)})
				case strings.HasSuffix(request.URL.Path, "/dns_records/record-cf"):
					writeTestJSON(t, writer, map[string]any{"success": true, "result": record("record-cf", "A", "192.0.2.10")})
				default:
					writeTestJSON(t, writer, map[string]any{"success": true,
						"result":      []any{record("record-cf", "A", "192.0.2.10")},
						"result_info": map[string]any{"page": 1, "per_page": 100, "count": 1, "total_count": 1, "total_pages": 1}})
				}
			}), time.Second)
		provider := &cloudflareProvider{adapter: providerAdapter}
		direct, directErr := provider.reconcileLookup(t.Context(), config, dnscheck.ProviderOperation{
			Action: dnscheck.ProviderUpdate, RecordID: "record-cf", Name: testOwner, Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300, PreviousValue: "192.0.2.10", PreviousTTL: 300,
		})
		listed, listErr := provider.reconcileLookup(t.Context(), config, dnscheck.ProviderOperation{
			Action: dnscheck.ProviderCreate, Name: testOwner, Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300,
		})
		_, presentErr := provider.present(t.Context(), config, testOwner, "", testValue)
		_, _, getErr := provider.get(t.Context(), config, recordHandle{ZoneID: zoneID, RecordID: "record-cf"}, "")
		if foreign {
			if directErr == nil || listErr == nil || presentErr == nil || getErr == nil {
				t.Fatalf("foreign zone_id accepted: direct=%v list=%v present=%v get=%v", directErr, listErr, presentErr, getErr)
			}
			continue
		}
		if directErr != nil || !direct.TargetComplete || direct.RecordID != "record-cf" {
			t.Fatalf("direct lookup = (%+v,%v)", direct, directErr)
		}
		if listErr != nil || !listed.TargetComplete || listed.RecordID != "record-cf" {
			t.Fatalf("list lookup = (%+v,%v)", listed, listErr)
		}
		if presentErr != nil || getErr != nil {
			t.Fatalf("present()=%v get()=%v", presentErr, getErr)
		}
	}
}
