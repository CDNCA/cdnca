package originauthcontrol

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestEncodeJSONIsDeterministicWithoutHTMLEscapingOrNewline(t *testing.T) {
	value := map[string]any{"path": "/<\">/", "revision": int64(1)}
	first, err := encodeJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encodeJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("encoding differs: %q != %q", first, second)
	}
	if bytes.Contains(first, []byte(`\u003c`)) || bytes.HasSuffix(first, []byte{'\n'}) {
		t.Fatalf("encoding has HTML escaping or trailing newline: %q", first)
	}

	handler := &Handler{maxResponseBytes: maximumMaxResponseBytes}
	response := httptest.NewRecorder()
	handler.writeJSON(response, httptest.NewRequest(http.MethodGet, "/", nil), http.StatusOK, value)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), first) {
		t.Fatalf("handler response = %d %q, want 200 %q", response.Code, response.Body.Bytes(), first)
	}
}

func TestPublicationCanonicalHashIsDeterministic(t *testing.T) {
	tenantScopeID := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	snapshot := PublicationSnapshot{
		SchemaVersion:       publicationSchema,
		TenantScopeID:       tenantScopeID,
		PublicationRevision: 1,
		Rules: []PublicationRule{{
			RuleID:                       uuid.MustParse("20000000-0000-0000-0000-000000000001"),
			SiteID:                       uuid.MustParse("30000000-0000-0000-0000-000000000001"),
			SourcePosition:               1,
			Provider:                     ProviderS3,
			Algorithm:                    AlgorithmS3,
			Endpoint:                     "https://bucket.s3.us-east-1.amazonaws.com",
			PathPrefix:                   "/<\">/",
			Region:                       "us-east-1",
			Service:                      "s3",
			SignatureTTLSeconds:          3600,
			CurrentCredentialRevisionRef: uuid.MustParse("40000000-0000-0000-0000-000000000001"),
		}},
	}
	first, err := encodeJSON(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encodeJSON(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(first) != sha256.Sum256(second) || !bytes.Equal(first, second) {
		t.Fatal("canonical snapshot encoding or hash is not deterministic")
	}
}

func TestExplicitSmallResponseBudgetStillFailsClosed(t *testing.T) {
	handler := &Handler{maxResponseBytes: 1024}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.writeJSON(response, request, http.StatusOK, map[string]string{"value": string(bytes.Repeat([]byte{'a'}, 1024))})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("writeJSON() status = %d, want 503", response.Code)
	}
}
