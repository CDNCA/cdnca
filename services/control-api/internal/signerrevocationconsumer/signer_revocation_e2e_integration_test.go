//go:build integration

package signerrevocationconsumer

// Process 2 of tests/signer-revocation-e2e/run.sh: the production consumer
// against the live license-service checkpoint route, with the gate installed
// on the shared trust store exactly as cmd/control-api wires it.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/platformpolicy"
	"github.com/google/uuid"
)

type e2eLicenseDocument struct {
	BaseURL                    string `json:"base_url"`
	CACertificatePEM           string `json:"ca_certificate_pem"`
	InstallationID             string `json:"installation_id"`
	InstallationPrivateKeyFile string `json:"installation_private_key_file"`
	OfflineRootKeyID           string `json:"offline_root_key_id"`
	OfflineRootGeneration      uint64 `json:"offline_root_generation"`
	OfflineRootPublicKey       string `json:"offline_root_public_key"`
	RevokedKeyID               string `json:"revoked_key_id"`
	RevokedKeySeed             string `json:"revoked_key_seed"`
}

type e2eSigner struct {
	id  string
	key ed25519.PrivateKey
}

func (signer e2eSigner) KeyID() string { return signer.id }
func (signer e2eSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, payload), nil
}

func TestSignerRevocationE2EControlAgainstLicense(t *testing.T) {
	dir := os.Getenv("SIGNER_REVOCATION_E2E_DIR")
	if dir == "" {
		t.Skip("SIGNER_REVOCATION_E2E_DIR is not set; run tests/signer-revocation-e2e/run.sh")
	}
	defer func() { _ = os.WriteFile(filepath.Join(dir, "control.done"), []byte("done"), 0o600) }()
	var license e2eLicenseDocument
	encoded, err := os.ReadFile(filepath.Join(dir, "license.json"))
	if err != nil || json.Unmarshal(encoded, &license) != nil {
		t.Fatalf("read license.json: %v", err)
	}
	setMode := func(mode string) {
		if err := os.WriteFile(filepath.Join(dir, "license.mode"), []byte(mode), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	revokedSeed := sha256.Sum256([]byte(license.RevokedKeySeed))
	revoked := e2eSigner{id: license.RevokedKeyID, key: ed25519.NewKeyFromSeed(revokedSeed[:])}
	healthyPublic, healthyPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	healthy := e2eSigner{id: "e2e-healthy-lineage", key: healthyPrivate}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: revoked.id, PublicKey: revoked.key.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.ApplyVerifiedKeys([]entitlementguard.VerificationKey{
		{KeyID: revoked.id, PublicKey: revoked.key.Public().(ed25519.PublicKey)},
		{KeyID: healthy.id, PublicKey: healthyPublic}}); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(license.CACertificatePEM)) {
		t.Fatal("license CA certificate")
	}
	rootKey, err := base64.RawURLEncoding.DecodeString(license.OfflineRootPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Enabled: true, BaseURL: license.BaseURL, InstallationID: uuid.MustParse(license.InstallationID),
		InstallationPrivateKeyFile: license.InstallationPrivateKeyFile, RefreshInterval: time.Hour,
		RequestTimeout: 10 * time.Second, StartupTimeout: 30 * time.Second, ShutdownTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, OfflineRootKeyID: license.OfflineRootKeyID,
		OfflineRootGeneration: license.OfflineRootGeneration, OfflineRootPublicKey: ed25519.PublicKey(rootKey)}
	pool := productionIntegrationPool(t, true, 8)
	dependencies := ProductionDependencies{Pool: pool, EntitlementTrust: trust, Now: time.Now}

	now := time.Now().UTC()
	lease := func(signer e2eSigner) error {
		signed, err := entitlement.Sign(t.Context(), entitlement.Lease{Schema: entitlement.SchemaV1,
			Audience: entitlement.ControlAudience, CustomerID: "c", InstallationID: license.InstallationID,
			LicenseID: "l", Serial: 1, NotBefore: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			GraceUntil: now.Add(2 * time.Hour).Unix(),
			Version:    entitlement.VersionRange{Channel: "stable", Min: "1.0.0", Max: "2.0.0"},
			Features:   []entitlement.Feature{{Code: "sites.manage"}}}, signer)
		if err != nil {
			t.Fatal(err)
		}
		_, err = trust.Verify(signed, entitlement.VerifyOptions{Now: time.Now(),
			ExpectedAudience: entitlement.ControlAudience, ExpectedInstallationID: license.InstallationID})
		return err
	}
	policy := func(signer e2eSigner) error {
		body := &platformpolicy.Policy{Schema: platformpolicy.PolicySchema, MinimumControlVersion: "1.0.0",
			AllowedReleaseChannels: []string{"stable"}}
		policyBytes, err := platformpolicy.CanonicalPolicy(body)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(policyBytes)
		envelope := platformpolicy.Envelope{Domain: platformpolicy.SignatureDomain, TargetRevisionID: uuid.NewString(),
			Action: platformpolicy.ActionApply, Schema: platformpolicy.PolicySchema, ScopeKind: platformpolicy.ScopeGlobal,
			ScopeRevision: 1, SignedAt: now.Add(-2 * time.Minute).Unix(), ValidFrom: now.Add(-time.Minute).Unix(),
			ExpiresAt: now.Add(time.Hour).Unix(), ControlProtocolMin: 1, ControlProtocolMax: 1,
			CanonicalPolicySHA256: base64.RawURLEncoding.EncodeToString(digest[:]), KeyID: signer.id}
		envelopeBytes, err := platformpolicy.CanonicalEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		signed := platformpolicy.SignedPlatformPolicy{Envelope: envelope, Policy: body,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.key, envelopeBytes))}
		if _, err := platformpolicy.Verify(signed, trust, platformpolicy.VerifyOptions{Now: time.Now(),
			InstallationID: config.InstallationID, ControlVersion: "1.0.0", ProtocolVersion: 1,
			DeliveredByResolve: true}); err != nil {
			return err
		}
		// Same post-verification decision the policy syncer applies to candidates.
		return trust.CheckSignerRevocation(entitlementguard.SignerArtifactPolicy, signer.id)
	}
	release := func(signer e2eSigner) error {
		return trust.CheckSignerRevocation(entitlementguard.SignerArtifactRelease, signer.id)
	}
	expectAllowed := func(stage string, signer e2eSigner) {
		t.Helper()
		for name, check := range map[string]func(e2eSigner) error{"lease": lease, "policy": policy, "release": release} {
			if err := check(signer); err != nil {
				t.Fatalf("%s: %s signed by %s rejected: %v", stage, name, signer.id, err)
			}
		}
	}
	expectRevoked := func(stage string) {
		t.Helper()
		for name, check := range map[string]func(e2eSigner) error{"lease": lease, "policy": policy, "release": release} {
			if err := check(revoked); !errors.Is(err, entitlementguard.ErrSignerRevoked) {
				t.Fatalf("%s: %s signed by revoked key = %v, want ErrSignerRevoked", stage, name, err)
			}
		}
		expectAllowed(stage, healthy)
	}

	// 1. Older authorization center (no checkpoint route): startup succeeds, nothing is rejected.
	setMode("legacy")
	runtime, err := OpenProductionRuntime(t.Context(), config, dependencies)
	if err != nil {
		t.Fatalf("open with empty LKG: %v", err)
	}
	trust.SetSignerRevocationGate(runtime.RevocationGate(slog.Default()))
	var retryable *retryableRefreshError
	if err := runtime.coordinator.Refresh(t.Context()); !errors.As(err, &retryable) {
		t.Fatalf("legacy center refresh = %v, want retryable", err)
	}
	expectAllowed("legacy center", revoked)
	t.Log("PASS legacy center: startup ok, revoked key still accepted (no verified list)")

	// 2. Center serves the offline-root checkpoint: revoked key rejected on all three classes.
	setMode("")
	if err := runtime.coordinator.Refresh(t.Context()); err != nil {
		t.Fatalf("checkpoint refresh: %v", err)
	}
	expectRevoked("after checkpoint")
	t.Log("PASS checkpoint applied: lease/policy/release signed by revoked key rejected, healthy key accepted")

	// 3. Center unreachable: LKG retained, still fail-closed for the known revocation only.
	setMode("outage")
	if err := runtime.coordinator.Refresh(t.Context()); !errors.As(err, &retryable) {
		t.Fatalf("outage refresh = %v, want retryable", err)
	}
	expectRevoked("during outage")
	var outages int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM control_signer_checkpoint_audit
		WHERE event_type='outage' AND reason_code=$1`, ReasonServerOutage).Scan(&outages); err != nil || outages < 1 {
		t.Fatalf("outage audit rows = %d, err=%v", outages, err)
	}
	t.Log("PASS outage: LKG retained and audited")

	// 4. Restart while the center is still down: LKG restored from PostgreSQL.
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	trust.SetSignerRevocationGate(nil)
	restarted, err := OpenProductionRuntime(t.Context(), config, dependencies)
	if err != nil {
		t.Fatalf("restart during outage: %v", err)
	}
	defer restarted.Close()
	trust.SetSignerRevocationGate(restarted.RevocationGate(slog.Default()))
	expectRevoked("after restart")
	t.Log("PASS restart during outage: LKG restored from PostgreSQL, revocation still enforced")
}
