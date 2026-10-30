package wafreport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestReportAcceptsCompleteReceipt(t *testing.T) {
	for _, empty := range []bool{false, true} {
		name := "custom_policies"
		if empty {
			name = "empty_policies"
		}
		t.Run(name, func(t *testing.T) {
			snapshot, key := reportContractSnapshot(t, empty)
			receipt := reportContractReceipt(snapshot, key)
			// The observation identifies the sent second; server clock order is not a contract.
			receipt["observed_at"] = snapshot.ObservedAt.In(time.FixedZone("test", 8*60*60))
			receipt["received_at"] = snapshot.ObservedAt.Add(-time.Minute)
			encoded := append(encodeReportReceipt(t, receipt), '\n', '\t')
			client, err := NewClient("https://license.example.test", roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Report(context.Background(), snapshot, key); err != nil {
				t.Fatalf("complete upstream receipt rejected: %v", err)
			}
		})
	}
}

func TestReportRejectsInvalidReceipt(t *testing.T) {
	snapshot, key := reportContractSnapshot(t, false)
	assertRejected := func(t *testing.T, encoded []byte) {
		t.Helper()
		client, err := NewClient("https://license.example.test", roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Report(context.Background(), snapshot, key); err == nil || err.Error() != "invalid WAF report response" {
			t.Fatalf("invalid receipt error = %v", err)
		}
	}
	for _, field := range []string{"schema", "id", "installation_id", "customer_id", "license_id", "sequence", "observed_at", "received_at", "policies", "request_id", "signature", "policies_digest"} {
		for _, invalid := range []string{"missing", "null", "wrong_type"} {
			t.Run(field+"/"+invalid, func(t *testing.T) {
				receipt := reportContractReceipt(snapshot, key)
				switch invalid {
				case "missing":
					delete(receipt, field)
				case "null":
					receipt[field] = nil
				case "wrong_type":
					receipt[field] = true
				}
				assertRejected(t, encodeReportReceipt(t, receipt))
			})
		}
	}
	for _, test := range []struct {
		name  string
		field string
		value any
	}{
		{"wrong_schema", "schema", "cdnca.waf-custom-rule-report/v2"},
		{"zero_id", "id", uuid.Nil},
		{"zero_customer", "customer_id", uuid.Nil},
		{"zero_license", "license_id", uuid.Nil},
		{"wrong_installation", "installation_id", uuid.MustParse("00000000-0000-0000-0000-000000000088")},
		{"wrong_sequence", "sequence", snapshot.Sequence + 1},
		{"negative_sequence", "sequence", -1},
		{"fractional_sequence", "sequence", 7.5},
		{"wrong_request", "request_id", "another-request"},
		{"wrong_observation", "observed_at", snapshot.ObservedAt.Add(time.Second)},
		{"fractional_observation", "observed_at", snapshot.ObservedAt.Add(time.Nanosecond)},
		{"unix_observation", "observed_at", snapshot.ObservedAt.Unix()},
		{"zero_received", "received_at", time.Time{}},
		{"invalid_received", "received_at", "yesterday"},
		{"wrong_digest", "policies_digest", strings.Repeat("0", 64)},
		{"uppercase_digest", "policies_digest", strings.ToUpper(hex.EncodeToString(snapshot.PoliciesDigest[:]))},
		{"wrong_signature", "signature", base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))},
		{"padded_signature", "signature", base64.URLEncoding.EncodeToString(ed25519.Sign(key, proofMessage(snapshot, snapshot.PoliciesDigest)))},
		{"different_policies", "policies", []json.RawMessage{}},
		{"changed_policy", "policies", []json.RawMessage{json.RawMessage(strings.Replace(string(snapshot.Policies[0]), "/x", "/changed", 1))}},
		{"invalid_policy", "policies", []json.RawMessage{json.RawMessage(`{"kind":"cc"}`)}},
		{"unknown_field", "unexpected", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			receipt := reportContractReceipt(snapshot, key)
			receipt[test.field] = test.value
			assertRejected(t, encodeReportReceipt(t, receipt))
		})
	}
	valid := encodeReportReceipt(t, reportContractReceipt(snapshot, key))
	for _, test := range []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"null", "null"},
		{"array", "[]"},
		{"truncated", string(valid[:len(valid)-1])},
		{"second_object", string(valid) + "{}"},
		{"second_null", string(valid) + "null"},
		{"trailing_garbage", string(valid) + "garbage"},
		{"too_large", string(valid) + strings.Repeat(" ", maxResponseBytes+1-len(valid))},
		{"obsolete_four_fields", `{"schema":"cdnca.waf-custom-rule-report/v1","id":"00000000-0000-0000-0000-000000000099","installation_id":"00000000-0000-0000-0000-000000000001","sequence":7}`},
	} {
		t.Run(test.name, func(t *testing.T) { assertRejected(t, []byte(test.body)) })
	}
}

func TestReportEmptyReceiptRequiresPolicyArray(t *testing.T) {
	snapshot, key := reportContractSnapshot(t, true)
	for _, missing := range []bool{false, true} {
		receipt := reportContractReceipt(snapshot, key)
		receipt["policies"] = nil
		if missing {
			delete(receipt, "policies")
		}
		encoded := encodeReportReceipt(t, receipt)
		client, err := NewClient("https://license.example.test", roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Report(context.Background(), snapshot, key); err == nil {
			t.Fatalf("empty receipt without an array accepted (missing=%v)", missing)
		}
	}
}

func TestReportHTTPSRetryKeepsSnapshotIdentity(t *testing.T) {
	for _, empty := range []bool{false, true} {
		name := "custom_policies"
		if empty {
			name = "empty_policies"
		}
		t.Run(name, func(t *testing.T) {
			snapshot, key := reportContractSnapshot(t, empty)
			receipt := encodeReportReceipt(t, reportContractReceipt(snapshot, key))
			type wireRequest struct {
				body    []byte
				headers http.Header
			}
			requests := make(chan wireRequest, 2)
			var attempt atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || r.Method != http.MethodPost || r.URL.Path != "/installation/v1/waf-rule-reports" {
					t.Error("unexpected HTTPS report route")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read report: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				requests <- wireRequest{body: body, headers: r.Header.Clone()}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				if attempt.Add(1) == 1 {
					_, _ = w.Write(receipt[:len(receipt)-1])
					return
				}
				_, _ = w.Write(receipt)
			}))
			defer server.Close()
			client, err := NewClient(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Report(context.Background(), snapshot, key); err == nil {
				t.Fatal("truncated first receipt was accepted")
			}
			if err := client.Report(context.Background(), snapshot, key); err != nil {
				t.Fatalf("exact retry failed: %v", err)
			}
			if len(requests) != 2 {
				t.Fatalf("request count = %d, want 2", len(requests))
			}
			first, second := <-requests, <-requests
			if !bytes.Equal(first.body, second.body) {
				t.Fatal("retry changed the signed report body")
			}
			for _, request := range []wireRequest{first, second} {
				if request.headers.Get("Idempotency-Key") != snapshot.RequestID || request.headers.Get("X-Request-ID") != snapshot.RequestID || request.headers.Get("Content-Type") != "application/json" {
					t.Fatal("retry changed report identity or content type headers")
				}
			}
			var body struct {
				InstallationID uuid.UUID         `json:"installation_id"`
				Sequence       uint64            `json:"sequence"`
				ObservedAt     int64             `json:"observed_at"`
				RequestID      string            `json:"request_id"`
				Policies       []json.RawMessage `json:"policies"`
				Signature      string            `json:"signature"`
			}
			if err := json.Unmarshal(second.body, &body); err != nil {
				t.Fatal(err)
			}
			_, digest, err := CanonicalPolicies(body.Policies)
			if err != nil || digest != snapshot.PoliciesDigest || body.InstallationID != snapshot.InstallationID || body.Sequence != snapshot.Sequence || body.ObservedAt != snapshot.ObservedAt.Unix() || body.RequestID != snapshot.RequestID {
				t.Fatal("wire request differs from persisted snapshot identity/content")
			}
			signature, err := base64.RawURLEncoding.DecodeString(body.Signature)
			if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), proofMessage(snapshot, digest), signature) {
				t.Fatal("wire request proof is invalid")
			}
		})
	}
}

func TestReportRejectsNonCreatedReceipt(t *testing.T) {
	snapshot, key := reportContractSnapshot(t, false)
	receipt := encodeReportReceipt(t, reportContractReceipt(snapshot, key))
	for _, status := range []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent, http.StatusUnauthorized, http.StatusConflict, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client, err := NewClient("https://license.example.test", roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(receipt))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			var statusErr *HTTPError
			if err := client.Report(context.Background(), snapshot, key); !errors.As(err, &statusErr) || statusErr.StatusCode != status {
				t.Fatalf("HTTP %d error = %v", status, err)
			}
		})
	}
}

func reportContractSnapshot(t *testing.T, empty bool) (Snapshot, ed25519.PrivateKey) {
	t.Helper()
	var policies []json.RawMessage
	if !empty {
		policies = []json.RawMessage{json.RawMessage(`{"id":"00000000-0000-0000-0000-000000000002","kind":"waf","rules":[{"id":"00000000-0000-0000-0000-000000000012","name":"r","priority":1,"enabled":true,"conditions":[{"field":"path","operator":"contains","values":["/x"]}],"action":"block","flow":"stop","action_config":{}}]}`)}
	}
	canonical, digest, err := CanonicalPolicies(policies)
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{InstallationID: uuid.MustParse("00000000-0000-0000-0000-000000000001"), Sequence: 7, RequestID: "waf-report-7",
		ObservedAt: time.Unix(1_700_000_000, 0).UTC(), Policies: canonical, PoliciesDigest: digest}, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
}

// Complete license handler DTO at 44f43785, corroborated by upstream field metadata on 2026-09-28.
// IDs, policies and key material in these tests are fixtures, never production data.
func reportContractReceipt(snapshot Snapshot, key ed25519.PrivateKey) map[string]any {
	return map[string]any{
		"schema": Schema, "id": uuid.MustParse("00000000-0000-0000-0000-000000000099"), "installation_id": snapshot.InstallationID,
		"customer_id": uuid.MustParse("00000000-0000-0000-0000-000000000077"), "license_id": uuid.MustParse("00000000-0000-0000-0000-000000000066"),
		"sequence": snapshot.Sequence, "observed_at": snapshot.ObservedAt, "received_at": snapshot.ObservedAt.Add(time.Second),
		"policies": snapshot.Policies, "request_id": snapshot.RequestID,
		"signature":       base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, proofMessage(snapshot, snapshot.PoliciesDigest))),
		"policies_digest": hex.EncodeToString(snapshot.PoliciesDigest[:]),
	}
}

func encodeReportReceipt(t *testing.T, receipt map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
