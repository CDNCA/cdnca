package analyticsconnections

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestClickHouseWriterLookupQueryBindsCompleteReceiptIdentity(t *testing.T) {
	receipt, err := ValidateDelivery(validConnectionsDelivery())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	want := map[string]string{
		"param_tenant":                 receipt.TenantID,
		"param_receipt":                receipt.ReceiptID,
		"param_batch":                  receipt.BatchID,
		"param_event":                  receipt.EventID,
		"param_installation":           receipt.InstallationID,
		"param_site":                   receipt.SiteID,
		"param_subscription":           receipt.PackageSubscriptionID,
		"param_stream":                 receipt.Stream,
		"param_durable":                receipt.Durable,
		"param_stream_sequence":        strconv.FormatUint(receipt.StreamSequence, 10),
		"param_consumer_sequence":      strconv.FormatUint(receipt.ConsumerSequence, 10),
		"param_puback_stream":          receipt.PubAck.Stream,
		"param_puback_sequence":        strconv.FormatUint(receipt.PubAck.Sequence, 10),
		"param_puback_duplicate":       "0",
		"param_payload_sha256":         digestHex(receipt.PayloadSHA256),
		"param_canonical_event_sha256": digestHex(receipt.CanonicalEventSHA256),
		"param_evidence_sha256":        digestHex(receipt.EvidenceSHA256),
		"param_clickhouse_token":       receipt.ClickHouseToken,
	}
	var bindingError string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			bindingError = "read query: " + err.Error()
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !strings.HasPrefix(strings.TrimSpace(string(body)), "SELECT ") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		for key, value := range want {
			if got := r.URL.Query().Get(key); got != value {
				bindingError = key + " = " + got + ", want " + value
				break
			}
			placeholder := "{" + strings.TrimPrefix(key, "param_") + ":"
			if !strings.Contains(string(body), placeholder) {
				bindingError = "query does not use " + placeholder
				break
			}
		}
	}))
	defer server.Close()

	writer, err := NewClickHouseWriter(ClickHouseConfig{Endpoint: server.URL, Database: "analytics"}, server.Client())
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	if err := writer.Prepare(context.Background(), receipt); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if bindingError != "" {
		t.Fatal(bindingError)
	}
}

func TestClickHouseWriterLookupBindsCompleteReceipt(t *testing.T) {
	receipt, err := ValidateDelivery(validConnectionsDelivery())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	complete := func(mutate func(map[string]json.RawMessage)) []byte {
		stored := receipt
		stored.State = StateClickHousePrepared
		row, ok := newReceiptInsertRow(stored)
		if !ok {
			t.Fatal("valid prepared row was rejected")
		}
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatalf("marshal row: %v", err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatalf("decode row fields: %v", err)
		}
		delete(fields, "schema_version")
		if mutate != nil {
			mutate(fields)
		}
		fields["request_identity_match"] = json.RawMessage("1")
		encoded, err = json.Marshal(fields)
		if err != nil {
			t.Fatalf("marshal fields: %v", err)
		}
		return append(encoded, '\n')
	}
	setString := func(field, value string) func(map[string]json.RawMessage) {
		return func(fields map[string]json.RawMessage) {
			fields[field] = json.RawMessage(strconvQuote(value))
		}
	}
	setUint := func(field string, value uint64) func(map[string]json.RawMessage) {
		return func(fields map[string]json.RawMessage) {
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("marshal %s: %v", field, err)
			}
			fields[field] = encoded
		}
	}
	duplicateState := strings.TrimSuffix(strings.TrimSpace(string(complete(nil))), "}") + `,"state":"ch_prepared"}` + "\n"

	tests := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{name: "complete replay", body: complete(nil)},
		{name: "duplicate rows", body: append(complete(nil), complete(nil)...), wantErr: true},
		{name: "unknown field", body: complete(func(fields map[string]json.RawMessage) { fields["unexpected"] = json.RawMessage("1") }), wantErr: true},
		{name: "duplicate JSON field", body: []byte(duplicateState), wantErr: true},
		{name: "tenant drift", body: complete(setString("tenant_id", "00000000-0000-0000-0000-000000000099")), wantErr: true},
		{name: "installation drift", body: complete(setString("installation_id", "installation-other")), wantErr: true},
		{name: "site drift", body: complete(setString("site_id", "00000000-0000-0000-0000-000000000099")), wantErr: true},
		{name: "subscription drift", body: complete(setString("package_subscription_id", "00000000-0000-0000-0000-000000000099")), wantErr: true},
		{name: "receipt drift", body: complete(setString("receipt_id", "receipt-other")), wantErr: true},
		{name: "batch drift", body: complete(setString("batch_id", "batch-other")), wantErr: true},
		{name: "event drift", body: complete(setString("event_id", "event-other")), wantErr: true},
		{name: "payload digest drift", body: complete(setString("payload_sha256", strings.Repeat("0", 64))), wantErr: true},
		{name: "canonical digest drift", body: complete(setString("canonical_event_sha256", strings.Repeat("0", 64))), wantErr: true},
		{name: "evidence digest drift", body: complete(setString("evidence_sha256", strings.Repeat("0", 64))), wantErr: true},
		{name: "stream drift", body: complete(setString("nats_stream", "OTHER")), wantErr: true},
		{name: "consumer sequence drift", body: complete(setUint("nats_consumer_sequence", receipt.ConsumerSequence+1)), wantErr: true},
		{name: "state drift", body: complete(setString("state", "unknown")), wantErr: true},
		{name: "missing field", body: complete(func(fields map[string]json.RawMessage) { delete(fields, "evidence_sha256") }), wantErr: true},
		{name: "zero field", body: complete(setUint("connections", 0)), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inserted := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("read request: %v", err)
				}
				if strings.HasPrefix(strings.TrimSpace(string(body)), "SELECT ") {
					_, _ = w.Write(test.body)
					return
				}
				inserted = true
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			writer, err := NewClickHouseWriter(ClickHouseConfig{Endpoint: server.URL, Database: "analytics"}, server.Client())
			if err != nil {
				t.Fatalf("writer: %v", err)
			}
			err = writer.Prepare(context.Background(), receipt)
			if test.wantErr {
				if !errors.Is(err, ErrReceiptConflict) {
					t.Fatalf("error = %v, want receipt conflict", err)
				}
			} else if err != nil {
				t.Fatalf("valid replay: %v", err)
			}
			if inserted {
				t.Fatal("lookup result was treated as not found and inserted")
			}
		})
	}
}

func strconvQuote(value string) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
