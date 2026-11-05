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

// credentialRecorder records the credentials the service decrypted for
// verification (no network).
type credentialRecorder struct {
	mu           sync.Mutex
	providerType string
	credentials  map[string]string
}

func (v *credentialRecorder) Verify(context.Context, string, string) error {
	return errors.New("legacy verifier path used")
}

func (v *credentialRecorder) VerifyCredentials(_ context.Context, providerType string, credentials map[string]string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.providerType, v.credentials = providerType, maps.Clone(credentials)
	return nil
}

// TestClouDNSNamecheapJDCloudProviderServicePersistence: ClouDNS, Namecheap and JD Cloud
// providers are created, verified and stored through the existing credential
// encryption; the ciphertext never holds the secret, decodeCredentials reads
// exactly the provider's fields back, invalid shapes are refused, and audit
// payloads carry no secret. Test-only credentials; no request leaves the
// process.
func TestClouDNSNamecheapJDCloudProviderServicePersistence(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		providerType string
		credentials  map[string]string
		secret       string
		invalid      map[string]string
	}{
		{"cloudns", map[string]string{"sub_auth_id": "4321", "auth_password": "fixture-secret-cloudns"}, "fixture-secret-cloudns",
			map[string]string{"sub_auth_id": "user", "auth_password": "x"}},
		{"namecheap", map[string]string{"username": "fixture-user", "api_key": "fixture-secret-namecheap", "source_ip": "192.0.2.44"},
			"fixture-secret-namecheap", map[string]string{"username": "u", "api_key": "k", "source_ip": "2001:db8::1"}},
		{"jdcloud", map[string]string{"access_key_id": "FIXTUREAK", "access_key_secret": "fixture-secret-jdcloud"}, "fixture-secret-jdcloud",
			map[string]string{"access_key_id": "FIXTUREAK"}},
	} {
		t.Run(test.providerType, func(t *testing.T) {
			tenant := seedSourceTenant(t, pool, "more-dns-"+test.providerType)
			cipher := mustSourceCipher(t, "more-dns-key-v1", 17)
			verifier := &credentialRecorder{}
			service := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStore(pool), cipher, verifier, time.Now)
			actor := dnsacme.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
			if _, err := service.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{
				Name: test.providerType + " bad", ProviderType: test.providerType, Credentials: test.invalid,
				IdempotencyKey: test.providerType + "-bad", RequestID: test.providerType + "-bad",
			}); !errors.Is(err, dnsacme.ErrInvalidInput) {
				t.Fatalf("CreateProvider(invalid) error = %v", err)
			}
			provider, err := service.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{
				Name: test.providerType, ProviderType: test.providerType, Credentials: maps.Clone(test.credentials),
				IdempotencyKey: test.providerType + "-create", RequestID: test.providerType + "-create",
			})
			if err != nil || provider.ProviderType != test.providerType || provider.Status != dnsacme.ProviderStatusUnverified {
				t.Fatalf("CreateProvider = %+v, %v", provider, err)
			}
			var keyID string
			var ciphertext []byte
			if err := pool.QueryRow(t.Context(), `SELECT credential_key_id,credential_ciphertext FROM dns_providers WHERE id=$1`,
				provider.ID).Scan(&keyID, &ciphertext); err != nil {
				t.Fatal(err)
			}
			if keyID != "more-dns-key-v1" || strings.Contains(string(ciphertext), test.secret) {
				t.Fatalf("stored credentials not encrypted: key=%q", keyID)
			}
			plaintext, err := cipher.DecryptCredential(dnsacme.CredentialBinding{
				TenantID: tenant.tenantID, ScopeID: tenant.scopeID, ProviderID: provider.ID}, keyID, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := decodeCredentials(test.providerType, plaintext)
			if err != nil || !maps.Equal(credentials, test.credentials) {
				t.Fatalf("decodeCredentials = %d fields, %v", len(credentials), err)
			}
			provider, err = service.VerifyProvider(t.Context(), actor, dnsacme.VerifyProviderRequest{
				ID: provider.ID, ExpectedRevision: provider.Revision,
				IdempotencyKey: test.providerType + "-verify", RequestID: test.providerType + "-verify",
			})
			if err != nil || provider.Status != dnsacme.ProviderStatusVerified || verifier.providerType != test.providerType ||
				!maps.Equal(verifier.credentials, test.credentials) {
				t.Fatalf("VerifyProvider = %+v, %v", provider, err)
			}
			var auditPayload string
			if err := pool.QueryRow(t.Context(), `SELECT COALESCE(string_agg(payload::text,''),'') FROM audit_events
				WHERE resource_id=$1`, provider.ID.String()).Scan(&auditPayload); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(auditPayload, test.secret) || strings.Contains(auditPayload, "credential_ciphertext") {
				t.Fatal("audit payload leaked a secret")
			}
		})
	}
}
