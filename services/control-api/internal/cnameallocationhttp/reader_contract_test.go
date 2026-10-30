package cnameallocationhttp

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestReaderContractScopesEveryQueryAndUsesReadonlyDiagnosisSnapshot(t *testing.T) {
	source, err := os.ReadFile("reader.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"pgx.RepeatableRead", "pgx.ReadOnly", "tenant_scope_id=$1", "scope_id=$1",
		"cname_allocations", "cname_hostname_claims", "cname_site_bindings", "dns_zones",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("reader missing contract %q", required)
		}
	}
	for _, forbidden := range []string{"hmac_key_id", "request_digest", "idempotency_key", "encrypted_credentials", "credentials_ciphertext"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("reader includes secret/internal field %q", forbidden)
		}
	}
}

func TestPublicModelsNeverSerializeInternalFacts(t *testing.T) {
	raw, err := json.Marshal(AllocationView{ID: uuid.New(), Mode: "site", OwnerID: uuid.New(), State: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"hmac", "digest", "idempotency", "credential", "secret"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Errorf("public model exposes %q: %s", forbidden, raw)
		}
	}
}
