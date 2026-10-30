package dnsproviderremote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestValidationTXTWriterPublishAdoptAndRemove: Publish creates the exact
// TXT record once, adopts it on a repeat, Remove deletes it and is
// idempotent; a record edited by someone else is not deleted.
func TestValidationTXTWriterPublishAdoptAndRemove(t *testing.T) {
	const token = "cloudflare-validation-token"
	const owner = "_cf-custom-hostname.www.example.test."
	const value = "own-ch-7"
	var record *cloudflareRecord
	creates, deletes := 0, 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("unexpected authentication")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			writeTestJSON(t, w, map[string]any{"success": true, "result": []any{map[string]any{"id": "zone-cf", "name": testZone}}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-cf/dns_records":
			records := []cloudflareRecord{}
			if record != nil {
				records = append(records, *record)
			}
			totalPages := 1
			if len(records) == 0 {
				totalPages = 0
			}
			writeTestJSON(t, w, map[string]any{"success": true, "result": records, "result_info": map[string]any{
				"page": 1, "per_page": 100, "count": len(records), "total_count": len(records), "total_pages": totalPages}})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-cf/dns_records":
			creates++
			var body struct{ Type, Name, Content string }
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Type != "TXT" || body.Name != owner || body.Content != value {
				t.Errorf("create body = %+v", body)
			}
			record = &cloudflareRecord{ID: "rec-1", ZoneID: "zone-cf", Name: owner, Type: "TXT", Content: value}
			writeTestJSON(t, w, map[string]any{"success": true, "result": record})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-cf/dns_records/rec-1":
			if record == nil {
				w.WriteHeader(http.StatusNotFound)
				writeTestJSON(t, w, map[string]any{"success": false, "result": nil, "errors": []map[string]any{{"code": 81044}}})
				return
			}
			writeTestJSON(t, w, map[string]any{"success": true, "result": record})
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-cf/dns_records/rec-1":
			deletes++
			record = nil
			writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{"id": "rec-1"}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	adapter := newAdapter(nil, nil, server.Client().Transport,
		endpointSet{cloudflare: endpoint{baseURL: server.URL, host: "api.cloudflare.com"}}, time.Second, nil, nil)
	writer := &ValidationTXTWriter{adapter: adapter}
	config := completeTestConfig(ProviderConfig{ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": token}})
	ctx := context.Background()

	ref, err := writer.Publish(ctx, config, "_cf-custom-hostname.www.example.test", value)
	if err != nil || ref == "" || creates != 1 {
		t.Fatalf("Publish = %q, %v (creates %d)", ref, err, creates)
	}
	again, err := writer.Publish(ctx, config, owner, value)
	if err != nil || again != ref || creates != 1 {
		t.Fatalf("repeat Publish = %q, %v (creates %d)", again, err, creates)
	}

	record.Content = "edited-by-member"
	if err := writer.Remove(ctx, config, ref, owner, value); !isCode(err, CodeRecordMismatch) || deletes != 0 {
		t.Fatalf("Remove of an edited record = %v (deletes %d)", err, deletes)
	}
	record.Content = value
	if err := writer.Remove(ctx, config, ref, owner, value); err != nil || deletes != 1 {
		t.Fatalf("Remove = %v (deletes %d)", err, deletes)
	}
	if err := writer.Remove(ctx, config, ref, owner, value); err != nil || deletes != 1 {
		t.Fatalf("repeat Remove = %v (deletes %d)", err, deletes)
	}

	for name, bad := range map[string][2]string{
		"apex":         {testZone, value},
		"outside zone": {"_acme-challenge.other.test", value},
		"unsafe value": {owner, `a"b`},
		"spaces":       {owner, "a b"},
	} {
		if _, err := writer.Publish(ctx, config, bad[0], bad[1]); !isCode(err, CodeInvalidInput) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := writer.Remove(ctx, config, "txt1.not-base64!", owner, value); !isCode(err, CodeInvalidInput) {
		t.Errorf("bad ref: err = %v", err)
	}
	if creates != 1 {
		t.Fatalf("invalid input reached the provider: creates %d", creates)
	}
}
