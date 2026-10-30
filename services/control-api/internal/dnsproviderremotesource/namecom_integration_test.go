//go:build integration

package dnsproviderremotesource

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
)

// nameComVerifier records the credentials the service decrypted for
// verification (no network).
type nameComVerifier struct {
	mu                 sync.Mutex
	providerType       string
	username, apiToken string
}

func (v *nameComVerifier) Verify(context.Context, string, string) error {
	return errors.New("legacy verifier path used")
}

func (v *nameComVerifier) VerifyCredentials(_ context.Context, providerType string, credentials map[string]string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.providerType, v.username, v.apiToken = providerType, credentials["username"], credentials["api_token"]
	return nil
}

// TestNameComProviderServicePersistence: a name.com provider is created,
// rotated and verified through the existing credential encryption; the
// stored ciphertext never holds the token, decodeCredentials reads exactly
// username + api_token back, and audit payloads carry no secret. Test-only
// credentials; no request leaves the process.
func TestNameComProviderServicePersistence(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "namecom-service")
	cipher := mustSourceCipher(t, "namecom-key-v1", 13)
	verifier := &nameComVerifier{}
	service := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStore(pool), cipher, verifier, time.Now)
	actor := dnsacme.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}

	if _, err := service.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{
		Name: "Name.com bad", ProviderType: "namecom",
		Credentials:    map[string]string{"username": "fixture:user", "api_token": "fixture-token-a"},
		IdempotencyKey: "namecom-bad", RequestID: "namecom-bad",
	}); !errors.Is(err, dnsacme.ErrInvalidInput) {
		t.Fatalf("CreateProvider(namecom colon username) error = %v", err)
	}
	provider, err := service.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{
		Name: "Name.com", ProviderType: "namecom",
		Credentials:    map[string]string{"username": "fixture-user", "api_token": "fixture-token-a"},
		IdempotencyKey: "namecom-create", RequestID: "namecom-create",
	})
	if err != nil || provider.ProviderType != "namecom" || provider.Status != dnsacme.ProviderStatusUnverified {
		t.Fatalf("CreateProvider(namecom) = %+v, %v", provider, err)
	}
	provider, err = service.UpdateProvider(t.Context(), actor, dnsacme.UpdateProviderRequest{
		ID: provider.ID, ExpectedRevision: provider.Revision, Name: provider.Name,
		Status:         dnsacme.ProviderStatusUnverified,
		Credentials:    map[string]string{"username": "fixture-user", "api_token": "fixture-token-b"},
		IdempotencyKey: "namecom-update", RequestID: "namecom-update",
	})
	if err != nil {
		t.Fatalf("UpdateProvider(namecom) error = %v", err)
	}
	var keyID string
	var ciphertext []byte
	if err := pool.QueryRow(t.Context(), `SELECT credential_key_id,credential_ciphertext FROM dns_providers WHERE id=$1`,
		provider.ID).Scan(&keyID, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if keyID != "namecom-key-v1" || strings.Contains(string(ciphertext), "fixture-token") {
		t.Fatalf("stored credentials not encrypted: key=%q", keyID)
	}
	// Source.Resolve's decryption: the envelope is bound to tenant, scope and provider.
	plaintext, err := cipher.DecryptCredential(dnsacme.CredentialBinding{
		TenantID: tenant.tenantID, ScopeID: tenant.scopeID, ProviderID: provider.ID}, keyID, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := decodeCredentials("namecom", plaintext)
	if err != nil || len(credentials) != 2 || credentials["username"] != "fixture-user" ||
		credentials["api_token"] != "fixture-token-b" {
		t.Fatalf("decodeCredentials(namecom) = %v, %v", len(credentials), err)
	}
	provider, err = service.VerifyProvider(t.Context(), actor, dnsacme.VerifyProviderRequest{
		ID: provider.ID, ExpectedRevision: provider.Revision,
		IdempotencyKey: "namecom-verify", RequestID: "namecom-verify",
	})
	if err != nil || provider.Status != dnsacme.ProviderStatusVerified || verifier.providerType != "namecom" ||
		verifier.username != "fixture-user" || verifier.apiToken != "fixture-token-b" {
		t.Fatalf("VerifyProvider(namecom) = %+v, %v", provider, err)
	}
	var auditPayload string
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(string_agg(payload::text,''),'') FROM audit_events
		WHERE resource_id=$1`, provider.ID.String()).Scan(&auditPayload); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"fixture-token", "api_token", "credential_ciphertext"} {
		if strings.Contains(auditPayload, forbidden) {
			t.Fatalf("audit payload leaked %q", forbidden)
		}
	}
}

// fp-site DNS-01: renaming a verified account (or changing its remark)
// keeps it verified; new credentials make it unverified again, and
// disabling disables it.
func TestProviderMetadataUpdateKeepsVerification(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "dns01-keep-verified")
	service := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStore(pool), mustSourceCipher(t, "dns01-key-v1", 13), &nameComVerifier{}, time.Now)
	actor := dnsacme.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	provider, err := service.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{
		Name: "Name.com", ProviderType: "namecom",
		Credentials:    map[string]string{"username": "fixture-user", "api_token": "fixture-token-a"},
		IdempotencyKey: "dns01-create", RequestID: "dns01-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider, err = service.VerifyProvider(t.Context(), actor, dnsacme.VerifyProviderRequest{
		ID: provider.ID, ExpectedRevision: provider.Revision, IdempotencyKey: "dns01-verify", RequestID: "dns01-verify",
	}); err != nil || provider.Status != dnsacme.ProviderStatusVerified {
		t.Fatalf("verify = %+v, %v", provider, err)
	}
	remark := "renamed"
	update := func(key string, status string, credentials map[string]string) dnsacme.Provider {
		t.Helper()
		next, err := service.UpdateProvider(t.Context(), actor, dnsacme.UpdateProviderRequest{
			ID: provider.ID, ExpectedRevision: provider.Revision, Name: "Name.com " + key, Remark: &remark,
			Status: status, Credentials: credentials, IdempotencyKey: key, RequestID: key,
		})
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		return next
	}
	if provider = update("dns01-rename", dnsacme.ProviderStatusUnverified, nil); provider.Status != dnsacme.ProviderStatusVerified {
		t.Fatalf("rename status = %s, want verified", provider.Status)
	}
	if provider = update("dns01-rotate", dnsacme.ProviderStatusUnverified,
		map[string]string{"username": "fixture-user", "api_token": "fixture-token-b"}); provider.Status != dnsacme.ProviderStatusUnverified {
		t.Fatalf("rotate status = %s, want unverified", provider.Status)
	}
	if provider = update("dns01-disable", dnsacme.ProviderStatusDisabled, nil); provider.Status != dnsacme.ProviderStatusDisabled {
		t.Fatalf("disable status = %s, want disabled", provider.Status)
	}
}
