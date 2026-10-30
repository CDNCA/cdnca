package entitlement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// Artifacts are signed on another host. A verifier whose clock trails the
// signer by less than VerifierClockSkew must accept them; anything further
// ahead stays rejected. Expiry bounds are not widened.
func TestVerifiersTolerateBoundedSignerClockLead(t *testing.T) {
	offsets := []struct {
		name  string
		lead  time.Duration
		valid bool
	}{
		{"subsecond", 500 * time.Millisecond, true},
		{"one second", time.Second, true},
		{"at bound", VerifierClockSkew, true},
		{"beyond bound", VerifierClockSkew + time.Second, false},
	}

	t.Run("lease", func(t *testing.T) {
		now := time.Unix(1_800_000_000, 0).UTC()
		publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
		signed, err := Sign(context.Background(), validLease(now), testSigner{id: "key-1", private: privateKey})
		if err != nil {
			t.Fatal(err)
		}
		ring := NewKeyRing()
		_ = ring.Add("key-1", publicKey)
		for _, offset := range offsets {
			_, err := ring.Verify(signed, VerifyOptions{Now: now.Add(-offset.lead),
				ExpectedAudience: ControlAudience, ExpectedInstallationID: "installation-1"})
			if offset.valid != (err == nil) || (!offset.valid && !errors.Is(err, ErrNotYetValid)) {
				t.Fatalf("%s: Verify() error = %v, want valid=%v", offset.name, err, offset.valid)
			}
		}
	})

	t.Run("revocation set", func(t *testing.T) {
		publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
		issuedAt := time.Unix(1_900_000_000, 0).UTC()
		body := validRevocationSet(issuedAt)
		verifyUntil := issuedAt.Add(24 * time.Hour)
		window := RevocationKeyWindow{NotBefore: issuedAt.Add(-time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil}
		signed, err := SignRevocationSet(t.Context(), body,
			&revocationTestSigner{id: "lease-key-2026-07", private: privateKey}, window)
		if err != nil {
			t.Fatal(err)
		}
		for _, offset := range offsets {
			_, err := VerifyRevocationSet(signed, publicKey, RevocationVerifyOptions{
				Now: issuedAt.Add(-offset.lead), ExpectedAudience: RevocationSetAudience,
				ExpectedCustomerID: body.CustomerID, ExpectedInstallationID: body.InstallationID,
				ExpectedLicenseID: body.LicenseID, KeyWindow: window})
			if offset.valid != (err == nil) || (!offset.valid && !errors.Is(err, ErrRevocationNotCurrent)) {
				t.Fatalf("%s: VerifyRevocationSet() error = %v, want valid=%v", offset.name, err, offset.valid)
			}
		}
	})

	t.Run("upgrade grant", func(t *testing.T) {
		now := time.Unix(1_800_000_000, 0).UTC()
		publicKey, privateKey := upgradeGrantTestKey(3)
		artifactSignature, _ := SignArtifactManifest(context.Background(), validArtifactManifest(),
			testSigner{id: "release-key-3", private: privateKey})
		grant := validUpgradeGrant(now, artifactSignature)
		signed, err := SignUpgradeGrant(context.Background(), grant, testSigner{id: "release-key-3", private: privateKey})
		if err != nil {
			t.Fatal(err)
		}
		ring := NewKeyRing()
		_ = ring.Add("release-key-3", publicKey)
		for _, offset := range offsets {
			err := ring.VerifyUpgradeGrant(signed, UpgradeGrantVerifyOptions{
				Now: time.Unix(grant.IssuedAt, 0).Add(-offset.lead), ExpectedAudience: UpgradeGrantAudience,
				ExpectedInstallationID: grant.InstallationID})
			if offset.valid != (err == nil) || (!offset.valid && !errors.Is(err, ErrUpgradeGrantNotYetValid)) {
				t.Fatalf("%s: VerifyUpgradeGrant() error = %v, want valid=%v", offset.name, err, offset.valid)
			}
		}
	})
}

func TestVerifierClockSkewDoesNotWidenExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	if notYetValid(now.Unix(), now.Unix()) || notYetValid(now.Add(-VerifierClockSkew).Unix(), now.Unix()) {
		t.Fatal("notYetValid rejected a start within the verifier clock skew")
	}
	if !notYetValid(now.Add(-VerifierClockSkew-time.Second).Unix(), now.Unix()) {
		t.Fatal("notYetValid accepted a start beyond the verifier clock skew")
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	issuedAt := time.Unix(1_900_000_000, 0).UTC()
	body := validRevocationSet(issuedAt)
	verifyUntil := issuedAt.Add(24 * time.Hour)
	window := RevocationKeyWindow{NotBefore: issuedAt.Add(-time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil}
	signed, _ := SignRevocationSet(t.Context(), body, &revocationTestSigner{id: "lease-key-2026-07", private: privateKey}, window)
	if _, err := VerifyRevocationSet(signed, publicKey, RevocationVerifyOptions{
		Now: time.Unix(body.ExpiresAt, 0), ExpectedAudience: RevocationSetAudience,
		ExpectedCustomerID: body.CustomerID, ExpectedInstallationID: body.InstallationID,
		ExpectedLicenseID: body.LicenseID, KeyWindow: window}); !errors.Is(err, ErrRevocationNotCurrent) {
		t.Fatalf("expired revocation set error = %v", err)
	}
}
