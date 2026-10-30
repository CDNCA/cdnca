package entitlementguard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

type gateTestSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer gateTestSigner) KeyID() string { return signer.id }

func (signer gateTestSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

// fakeRevocationGate revokes exact (class, key) pairs.
type fakeRevocationGate struct {
	mu      sync.Mutex
	revoked map[SignerArtifactClass]map[string]bool
	calls   []string
}

func (gate *fakeRevocationGate) CheckSigner(class SignerArtifactClass, keyID string) error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.calls = append(gate.calls, string(class)+":"+keyID)
	if gate.revoked[class][keyID] {
		return &SignerRevokedError{Class: class, KeyID: keyID}
	}
	return nil
}

func gateTestLease(now time.Time) entitlement.Lease {
	return entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		CustomerID: "customer-1", InstallationID: "installation-1", LicenseID: "license-1", Serial: 1,
		NotBefore: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		GraceUntil: now.Add(2 * time.Hour).Unix(),
		Version:    entitlement.VersionRange{Channel: "stable", Min: "1.0.0", Max: "2.0.0"},
		Features:   []entitlement.Feature{{Code: "sites.manage"}},
		Quotas:     []entitlement.Quota{{Code: "nodes.count", Limit: 10}},
	}
}

func gateTestStore(t *testing.T) (*TrustStore, map[string]gateTestSigner) {
	t.Helper()
	signers := map[string]gateTestSigner{}
	var keys []VerificationKey
	for _, id := range []string{"lineage-1", "lineage-2"} {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signers[id] = gateTestSigner{id: id, private: privateKey}
		keys = append(keys, VerificationKey{KeyID: id, PublicKey: publicKey})
	}
	store, err := NewTrustStore(keys)
	if err != nil {
		t.Fatal(err)
	}
	return store, signers
}

func TestTrustStoreVerifyRejectsLeaseFromRevokedSigner(t *testing.T) {
	now := time.Now().UTC()
	store, signers := gateTestStore(t)
	revoked, err := entitlement.Sign(t.Context(), gateTestLease(now), signers["lineage-1"])
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := entitlement.Sign(t.Context(), gateTestLease(now), signers["lineage-2"])
	if err != nil {
		t.Fatal(err)
	}
	options := entitlement.VerifyOptions{Now: now, ExpectedAudience: entitlement.ControlAudience,
		ExpectedInstallationID: "installation-1"}

	// Without a gate (consumer disabled / old license-service) behavior is unchanged.
	if _, err := store.Verify(revoked, options); err != nil {
		t.Fatalf("Verify without gate = %v", err)
	}

	gate := &fakeRevocationGate{revoked: map[SignerArtifactClass]map[string]bool{
		SignerArtifactLease: {"lineage-1": true},
	}}
	store.SetSignerRevocationGate(gate)
	if _, err := store.Verify(revoked, options); !errors.Is(err, ErrSignerRevoked) {
		t.Fatalf("Verify revoked lease = %v, want ErrSignerRevoked", err)
	}
	var detail *SignerRevokedError
	if _, err := store.Verify(revoked, options); !errors.As(err, &detail) ||
		detail.Class != SignerArtifactLease || detail.KeyID != "lineage-1" {
		t.Fatalf("revoked detail = %#v", detail)
	}
	if code := verificationErrorCode(ErrSignerRevoked); code != "signer_revoked" {
		t.Fatalf("verificationErrorCode = %q", code)
	}
	if _, err := store.Verify(healthy, options); err != nil {
		t.Fatalf("Verify healthy lease = %v", err)
	}
}

func TestTrustStoreGateRunsOnlyAfterAuthenticSignature(t *testing.T) {
	now := time.Now().UTC()
	store, signers := gateTestStore(t)
	signed, err := entitlement.Sign(t.Context(), gateTestLease(now), signers["lineage-1"])
	if err != nil {
		t.Fatal(err)
	}
	signed.Lease.Serial++
	gate := &fakeRevocationGate{revoked: map[SignerArtifactClass]map[string]bool{
		SignerArtifactLease: {"lineage-1": true},
	}}
	store.SetSignerRevocationGate(gate)
	_, err = store.Verify(signed, entitlement.VerifyOptions{Now: now,
		ExpectedAudience: entitlement.ControlAudience, ExpectedInstallationID: "installation-1"})
	if !errors.Is(err, entitlement.ErrInvalidSignature) {
		t.Fatalf("tampered lease = %v, want invalid signature", err)
	}
	if len(gate.calls) != 0 {
		t.Fatalf("gate consulted for unauthenticated bytes: %v", gate.calls)
	}
}

func TestTrustStoreRejectsUpgradeBundleFromRevokedReleaseSigner(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer := bundleTrustTestSigner{privateKey: privateKey}
	signed := signedTrustTestBundle(t, now, signer)
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTrustStore([]VerificationKey{{KeyID: signer.KeyID(), PublicKey: privateKey.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	options := entitlement.UpgradePlanArtifactBundleVerifyOptions{
		Now: now.Add(time.Minute), ExpectedAudience: entitlement.UpgradePlanArtifactBundleAudience,
		ExpectedInstallationID: signed.Bundle.InstallationID, ExpectedPlanID: signed.Bundle.PlanID,
		ExpectedInitialPlanRevision: 1,
	}
	// Lease-only revocation must not affect release-class artifacts.
	store.SetSignerRevocationGate(&fakeRevocationGate{revoked: map[SignerArtifactClass]map[string]bool{
		SignerArtifactLease: {signer.KeyID(): true},
	}})
	if _, err := store.VerifyUpgradePlanArtifactBundle(encoded, options); err != nil {
		t.Fatalf("lease-only revocation affected release bundle: %v", err)
	}
	store.SetSignerRevocationGate(&fakeRevocationGate{revoked: map[SignerArtifactClass]map[string]bool{
		SignerArtifactRelease: {signer.KeyID(): true},
	}})
	if _, err := store.VerifyUpgradePlanArtifactBundle(encoded, options); !errors.Is(err, ErrSignerRevoked) {
		t.Fatalf("revoked release bundle = %v, want ErrSignerRevoked", err)
	}
}

func TestTrustStoreCheckSignerRevocationIsClassScoped(t *testing.T) {
	store, _ := gateTestStore(t)
	if err := store.CheckSignerRevocation(SignerArtifactRelease, "lineage-1"); err != nil {
		t.Fatalf("no gate = %v", err)
	}
	store.SetSignerRevocationGate(&fakeRevocationGate{revoked: map[SignerArtifactClass]map[string]bool{
		SignerArtifactPolicy: {"lineage-1": true},
	}})
	if err := store.CheckSignerRevocation(SignerArtifactPolicy, "lineage-1"); !errors.Is(err, ErrSignerRevoked) {
		t.Fatalf("policy class = %v", err)
	}
	if err := store.CheckSignerRevocation(SignerArtifactRelease, "lineage-1"); err != nil {
		t.Fatalf("release class must be unaffected = %v", err)
	}
	var nilStore *TrustStore
	if err := nilStore.CheckSignerRevocation(SignerArtifactLease, "lineage-1"); err != nil {
		t.Fatalf("nil store = %v", err)
	}
}
