//go:build integration

package dnsproviderremotesource

import (
	"context"
	"errors"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
)

// intlDNSVerifier records the credentials the service decrypted for
// verification (no network).
type intlDNSVerifier struct {
	mu           sync.Mutex
	providerType string
	credentials  map[string]string
}

func (v *intlDNSVerifier) Verify(context.Context, string, string) error {
	return errors.New("legacy verifier path used")
}

func (v *intlDNSVerifier) VerifyCredentials(_ context.Context, providerType string, credentials map[string]string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.providerType, v.credentials = providerType, maps.Clone(credentials)
	return nil
}

// TestDNSPodComGoDaddyNamesiloProviderServicePersistence: DNSPod.com, GoDaddy and Namesilo
// providers are created, rotated and verified through the existing
// credential encryption; the ciphertext never holds the secret,
// decodeCredentials reads exactly the provider's fields back, malformed
// credentials are refused before storage, and audit payloads carry no
// secret. Test-only credentials; no request leaves the process.
func TestDNSPodComGoDaddyNamesiloProviderServicePersistence(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "intl-dns-service")
	cipher := mustSourceCipher(t, "intl-dns-key-v1", 17)
	verifier := &intlDNSVerifier{}
	service := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStore(pool), cipher, verifier, time.Now)
	actor := dnsacme.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	for _, test := range []struct {
		providerType      string
		bad, first, final map[string]string
		secretField       string
	}{
		{"dnspod_com", map[string]string{"dp_id": "730060", "dp_key": "a,b"},
			map[string]string{"dp_id": "730060", "dp_key": "fixture-secret-a"},
			map[string]string{"dp_id": "730060", "dp_key": "fixture-secret-b"}, "dp_key"},
		{"godaddy", map[string]string{"api_key": "fixture:key", "api_secret": "fixture-secret-a"},
			map[string]string{"api_key": "fixture-key", "api_secret": "fixture-secret-a"},
			map[string]string{"api_key": "fixture-key", "api_secret": "fixture-secret-b"}, "api_secret"},
		{"namesilo", map[string]string{"key": "fixture secret"},
			map[string]string{"key": "fixture-secret-a"},
			map[string]string{"key": "fixture-secret-b"}, `"key"`},
	} {
		t.Run(test.providerType, func(t *testing.T) {
			key := "intl-dns-" + test.providerType
			if _, err := service.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{
				Name: test.providerType + " bad", ProviderType: test.providerType, Credentials: test.bad,
				IdempotencyKey: key + "-bad", RequestID: key + "-bad",
			}); !errors.Is(err, dnsacme.ErrInvalidInput) {
				t.Fatalf("CreateProvider(bad) error = %v", err)
			}
			provider, err := service.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{
				Name: test.providerType, ProviderType: test.providerType, Credentials: test.first,
				IdempotencyKey: key + "-create", RequestID: key + "-create",
			})
			if err != nil || provider.ProviderType != test.providerType || provider.Status != dnsacme.ProviderStatusUnverified {
				t.Fatalf("CreateProvider = %+v, %v", provider, err)
			}
			provider, err = service.UpdateProvider(t.Context(), actor, dnsacme.UpdateProviderRequest{
				ID: provider.ID, ExpectedRevision: provider.Revision, Name: provider.Name,
				Status: dnsacme.ProviderStatusUnverified, Credentials: test.final,
				IdempotencyKey: key + "-update", RequestID: key + "-update",
			})
			if err != nil {
				t.Fatalf("UpdateProvider error = %v", err)
			}
			var keyID string
			var ciphertext []byte
			if err := pool.QueryRow(t.Context(), `SELECT credential_key_id,credential_ciphertext FROM dns_providers WHERE id=$1`,
				provider.ID).Scan(&keyID, &ciphertext); err != nil {
				t.Fatal(err)
			}
			if keyID != "intl-dns-key-v1" || strings.Contains(string(ciphertext), "fixture-secret") {
				t.Fatalf("stored credentials not encrypted: key=%q", keyID)
			}
			plaintext, err := cipher.DecryptCredential(dnsacme.CredentialBinding{
				TenantID: tenant.tenantID, ScopeID: tenant.scopeID, ProviderID: provider.ID}, keyID, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := decodeCredentials(test.providerType, plaintext)
			if err != nil || !maps.Equal(credentials, test.final) {
				t.Fatalf("decodeCredentials = %d fields, %v", len(credentials), err)
			}
			provider, err = service.VerifyProvider(t.Context(), actor, dnsacme.VerifyProviderRequest{
				ID: provider.ID, ExpectedRevision: provider.Revision,
				IdempotencyKey: key + "-verify", RequestID: key + "-verify",
			})
			if err != nil || provider.Status != dnsacme.ProviderStatusVerified || verifier.providerType != test.providerType ||
				!maps.Equal(verifier.credentials, test.final) {
				t.Fatalf("VerifyProvider = %+v, %v", provider, err)
			}
			var auditPayload string
			if err := pool.QueryRow(t.Context(), `SELECT COALESCE(string_agg(payload::text,''),'') FROM audit_events
				WHERE resource_id=$1`, provider.ID.String()).Scan(&auditPayload); err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"fixture-secret", test.secretField, "credential_ciphertext"} {
				if strings.Contains(auditPayload, forbidden) {
					t.Fatalf("audit payload leaked %q", forbidden)
				}
			}
		})
	}
}
