package wafreport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) Do(request *http.Request) (*http.Response, error) { return fn(request) }

func TestCanonicalPoliciesSortsAndDigests(t *testing.T) {
	first := json.RawMessage(`{"id":"00000000-0000-0000-0000-000000000002","kind":"waf","name":"b","rules":[{"id":"00000000-0000-0000-0000-000000000012","name":"r","priority":1,"enabled":true,"conditions":[{"field":"path","operator":"contains","values":["/b"]}],"action":"block","flow":"stop","action_config":{}}]}`)
	second := json.RawMessage(`{"id":"00000000-0000-0000-0000-000000000001","kind":"waf","name":"a","rules":[{"id":"00000000-0000-0000-0000-000000000011","name":"r","priority":1,"enabled":true,"conditions":[{"field":"path","operator":"contains","values":["/a"]}],"action":"block","flow":"stop","action_config":{}}]}`)
	policies, digest, err := CanonicalPolicies([]json.RawMessage{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(policies[0], []byte(`00000000-0000-0000-0000-000000000001`)) {
		t.Fatalf("policies were not sorted by id: %s", policies[0])
	}
	if want := DigestPolicies(policies); digest != want {
		t.Fatalf("digest mismatch: got %x want %x", digest, want)
	}
}

func TestCanonicalPoliciesRejectProtectedAndInvalid(t *testing.T) {
	tests := []json.RawMessage{
		json.RawMessage(`{"id":"00000000-0000-0000-0000-000000000001","kind":"waf","protected":true}`),
		json.RawMessage(`{"id":"00000000-0000-0000-0000-000000000001","kind":"cc"}`),
	}
	for _, policy := range tests {
		if _, _, err := CanonicalPolicies([]json.RawMessage{policy}); err == nil {
			t.Fatalf("invalid policy accepted: %s", policy)
		}
	}
}

func TestCanonicalPoliciesAllowsEmptySnapshot(t *testing.T) {
	policies, digest, err := CanonicalPolicies(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 0 || digest != DigestPolicies(policies) {
		t.Fatalf("empty snapshot = %#v, %x", policies, digest)
	}
}

func TestReportSignsCanonicalPayloadAndHeaders(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	installationID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	observedAt := time.Unix(1_700_000_000, 0).UTC()
	policies := []json.RawMessage{json.RawMessage(`{"id":"00000000-0000-0000-0000-000000000002","kind":"waf","rules":[{"id":"00000000-0000-0000-0000-000000000012","name":"r","priority":1,"enabled":true,"conditions":[{"field":"path","operator":"contains","values":["/x"]}],"action":"block","flow":"stop","action_config":{}}]}`)}
	canonical, digest, err := CanonicalPolicies(policies)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{InstallationID: installationID, Sequence: 7, RequestID: "waf-report-7", ObservedAt: observedAt, Policies: canonical, PoliciesDigest: digest}
	client, err := NewClient("https://license.example.test/base", roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/base/installation/v1/waf-rule-reports" {
			t.Fatalf("unexpected report request: %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Idempotency-Key") != snapshot.RequestID || request.Header.Get("X-Request-ID") != snapshot.RequestID {
			t.Fatal("request identity headers are missing")
		}
		encoded, _ := io.ReadAll(request.Body)
		var body struct {
			Schema         string            `json:"schema"`
			InstallationID uuid.UUID         `json:"installation_id"`
			Sequence       uint64            `json:"sequence"`
			ObservedAt     int64             `json:"observed_at"`
			Policies       []json.RawMessage `json:"policies"`
			RequestID      string            `json:"request_id"`
			Signature      string            `json:"signature"`
		}
		if json.Unmarshal(encoded, &body) != nil || body.Schema != Schema || body.InstallationID != installationID || body.Sequence != snapshot.Sequence || body.ObservedAt != observedAt.Unix() || body.RequestID != snapshot.RequestID {
			t.Fatalf("invalid request body: %s", encoded)
		}
		proof, decodeErr := base64.RawURLEncoding.DecodeString(body.Signature)
		if decodeErr != nil || !ed25519.Verify(publicKey, proofMessage(snapshot, digest), proof) {
			t.Fatal("signature does not verify against the report proof")
		}
		responseBody := encodeReportReceipt(t, reportContractReceipt(snapshot, privateKey))
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(bytes.NewReader(responseBody)), Header: make(http.Header)}, nil
	}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Report(context.Background(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeHTTPErrorReadsCodeAndRetryAfter(t *testing.T) {
	response := &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader(`{"code":"rate_limited"}`)), Header: http.Header{"Retry-After": []string{"3"}}}
	var reportErr *HTTPError
	if !errors.As(decodeHTTPError(response), &reportErr) {
		t.Fatal("expected HTTPError")
	}
	if reportErr.Code != "rate_limited" || reportErr.RetryAfter != 3*time.Second || !reportErr.Retryable() {
		t.Fatalf("unexpected HTTP error: %#v", reportErr)
	}
}

func TestNewClientRejectsNonHTTPS(t *testing.T) {
	if _, err := NewClient("http://license.example.test", nil); err == nil {
		t.Fatal("non-HTTPS license endpoint was accepted")
	}
}
