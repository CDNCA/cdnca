package systemusersettings

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// The evidence issuer's server private key is saved in
// the page secrets envelope (673 lets its fingerprint in), never stored,
// logged or returned in plaintext, and handed to the issuer runtime with the
// issuer fields; a key that does not match the page certificate is refused.
func TestPostgresSystemUserSettingsKYCIssuerKey(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	service.WithSecretCipher(xorCipher{})
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	text := func(value string) *string { return &value }
	material := newKYCIssuerTestPEM(t, time.Now())
	value := kycIssuerCompleteSettings(material)

	if _, err := service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: 0, Value: value, RequestID: "issuer-0", IdempotencyKey: "issuer-0",
		Secrets: map[string]*string{SecretKYCIssuerServerPrivateKey: text(material.otherKey)}}); func() bool {
		located, ok := fielderr.As(err)
		return !errors.Is(err, ErrInvalidInput) || !ok || located.Field != SecretKYCIssuerServerPrivateKey
	}() {
		t.Fatalf("mismatched key: %v", err)
	}
	saved, err := service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: 0, Value: value, RequestID: "issuer-1", IdempotencyKey: "issuer-1",
		Secrets: map[string]*string{SecretKYCIssuerServerPrivateKey: text(material.serverKey)}})
	if err != nil || saved.Revision != 1 || !saved.KYCIssuerServerPrivateKeyConfigured || len(saved.KYCIssuerServerPrivateKeyFingerprint) != 16 {
		t.Fatalf("save=(%+v,%v)", saved, err)
	}
	var stored []byte
	var settingsJSON, receipts, payloads string
	if err := pool.QueryRow(t.Context(), `SELECT secrets_ciphertext,settings::text FROM platform_system_user_settings WHERE platform_scope_id=$1`,
		scopeID).Scan(&stored, &settingsJSON); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT string_agg(coalesce(response_body::text,''),'') FROM platform_system_user_settings_write_requests
		WHERE target_scope_id=$1`, scopeID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT coalesce(string_agg(payload::text,''),'') FROM audit_events WHERE request_id LIKE 'issuer-%'`).
		Scan(&payloads); err != nil {
		t.Fatal(err)
	}
	got, err := service.Get(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(got)
	keyBody := strings.Split(material.serverKey, "\n")[1]
	for name, where := range map[string]string{"ciphertext": string(stored), "settings": settingsJSON, "receipts": receipts,
		"audit": payloads, "document": string(encoded)} {
		if strings.Contains(where, keyBody) || strings.Contains(where, "PRIVATE KEY") {
			t.Fatalf("private key in %s", name)
		}
	}
	if got.Value.KYCIssuerServerCertificate != material.serverChain || !strings.Contains(payloads, `"kyc_issuer_server_private_key"`) {
		// the audit records the change of the key (its value redacted by the audit log)
		t.Fatalf("certificate equal=%v audit=%s", got.Value.KYCIssuerServerCertificate == material.serverChain, payloads)
	}
	runtime, err := service.IdentityVerificationRuntime(t.Context())
	defer runtime.Clear()
	if err != nil || !bytes.Equal(runtime.IssuerServerPrivateKey, []byte(material.serverKey)) || !runtime.IssuerEnabled ||
		runtime.IssuerClientCA != material.clientCA || runtime.IssuerListenAddress != value.KYCIssuerListenAddress {
		t.Fatalf("runtime=(%+v,%v)", runtime.IssuerListenAddress, err)
	}
}
