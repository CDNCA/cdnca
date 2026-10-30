package entitlement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type testSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer testSigner) KeyID() string { return signer.id }

func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func TestSignVerifyAndOfflineCache(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(context.Background(), validLease(now), testSigner{id: "key-2026-01", private: privateKey})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	signedAgain, err := Sign(context.Background(), validLease(now), testSigner{id: "key-2026-01", private: privateKey})
	if err != nil || signedAgain.Signature != signed.Signature {
		t.Fatalf("deterministic Sign() = (%q, %v), want %q", signedAgain.Signature, err, signed.Signature)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	cached, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	ring := NewKeyRing()
	if err := ring.Add("key-2026-01", publicKey); err != nil {
		t.Fatal(err)
	}
	result, err := ring.Verify(cached, VerifyOptions{
		Now: now.Add(time.Minute), ExpectedAudience: ControlAudience, ExpectedInstallationID: "installation-1",
	})
	if err != nil || result.Status != StatusValid {
		t.Fatalf("Verify() = (%#v, %v), want valid", result, err)
	}
	if !result.Lease.HasFeature("sites.manage") || !result.Lease.AllowsVersion("stable", "5.8.14") {
		t.Fatal("verified lease lost feature or version constraints")
	}
	if limit, ok := result.Lease.Quota("nodes.count"); !ok || limit != 10 {
		t.Fatalf("Quota(nodes.count) = (%d, %v)", limit, ok)
	}
}

func TestVerificationFailuresAndStates(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := Sign(context.Background(), validLease(now), testSigner{id: "key-1", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyRing()
	_ = ring.Add("key-1", publicKey)
	base := VerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: ControlAudience, ExpectedInstallationID: "installation-1"}

	tampered := signed
	tampered.Lease.Quotas = append([]Quota(nil), signed.Lease.Quotas...)
	tampered.Lease.Quotas[0].Limit++
	if _, err := ring.Verify(tampered, base); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered Verify() error = %v", err)
	}
	wrongAudience := base
	wrongAudience.ExpectedAudience = "another-service"
	if _, err := ring.Verify(signed, wrongAudience); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("wrong audience error = %v", err)
	}
	wrongInstallation := base
	wrongInstallation.ExpectedInstallationID = "installation-2"
	if _, err := ring.Verify(signed, wrongInstallation); !errors.Is(err, ErrInstallationMismatch) {
		t.Fatalf("wrong installation error = %v", err)
	}
	unknownRing := NewKeyRing()
	if _, err := unknownRing.Verify(signed, base); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key error = %v", err)
	}
	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	wrongKeyRing := NewKeyRing()
	_ = wrongKeyRing.Add("key-1", wrongPublic)
	if _, err := wrongKeyRing.Verify(signed, base); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong public key error = %v", err)
	}

	cases := []struct {
		name    string
		at      time.Time
		revoked []uint64
		status  Status
		err     error
	}{
		{name: "not before", at: now.Add(-VerifierClockSkew - time.Second), err: ErrNotYetValid},
		{name: "grace", at: now.Add(2 * time.Hour), status: StatusGrace},
		{name: "expired", at: now.Add(26 * time.Hour), status: StatusExpired},
		{name: "revoked", at: now.Add(time.Minute), revoked: []uint64{42}, status: StatusRevoked},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			options := base
			options.Now = test.at
			options.RevokedSerials = test.revoked
			result, err := ring.Verify(signed, options)
			if !errors.Is(err, test.err) || result.Status != test.status {
				t.Fatalf("Verify() = (%q, %v), want (%q, %v)", result.Status, err, test.status, test.err)
			}
		})
	}
}

func TestKeyRotation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	newPublic, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	oldLease, _ := Sign(context.Background(), validLease(now), testSigner{id: "old-key", private: oldPrivate})
	newLease, _ := Sign(context.Background(), validLease(now), testSigner{id: "new-key", private: newPrivate})
	ring := NewKeyRing()
	_ = ring.Add("old-key", oldPublic)
	_ = ring.Add("new-key", newPublic)
	options := VerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: ControlAudience, ExpectedInstallationID: "installation-1"}
	for _, signed := range []SignedLease{oldLease, newLease} {
		if result, err := ring.Verify(signed, options); err != nil || result.Status != StatusValid {
			t.Fatalf("rotation Verify() = (%#v, %v)", result, err)
		}
	}
}

func TestStrictLeaseValidationAndCanonicalEncoding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	cases := []struct {
		name   string
		mutate func(*Lease)
	}{
		{name: "duplicate feature", mutate: func(lease *Lease) { lease.Features = append(lease.Features, Feature{Code: "waf.manage"}) }},
		{name: "unsorted quota", mutate: func(lease *Lease) { lease.Quotas[0], lease.Quotas[1] = lease.Quotas[1], lease.Quotas[0] }},
		{name: "negative quota", mutate: func(lease *Lease) { lease.Quotas[0].Limit = -1 }},
		{name: "unknown quota", mutate: func(lease *Lease) { lease.Quotas[0].Code = "unknown.count" }},
		{name: "unsafe integer quota", mutate: func(lease *Lease) { lease.Quotas[0].Limit = MaxQuotaLimit + 1 }},
		{name: "invalid times", mutate: func(lease *Lease) { lease.ExpiresAt = lease.NotBefore }},
		{name: "invalid version range", mutate: func(lease *Lease) { lease.Version.Min = "6.0.0" }},
		{name: "overlong identifier", mutate: func(lease *Lease) { lease.CustomerID = strings.Repeat("c", 129) }},
		{name: "overlong feature code", mutate: func(lease *Lease) { lease.Features[0].Code = strings.Repeat("s", 97) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			lease := validLease(now)
			test.mutate(&lease)
			if err := lease.Validate(); !errors.Is(err, ErrInvalidLease) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}

	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := Sign(context.Background(), validLease(now), testSigner{id: "key-1", private: privateKey})
	encoded, _ := signed.Encode()
	var object map[string]any
	_ = json.Unmarshal(encoded, &object)
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	if _, err := Decode(unknown); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Decode(unknown field) error = %v", err)
	}
	withWhitespace := append([]byte(" "), encoded...)
	if _, err := Decode(withWhitespace); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Decode(non-canonical) error = %v", err)
	}
	algorithmConfusion := signed
	algorithmConfusion.Algorithm = "HS256"
	if _, err := algorithmConfusion.Encode(); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Encode(algorithm confusion) error = %v", err)
	}
}

func validLease(now time.Time) Lease {
	return Lease{
		Schema: SchemaV1, Audience: ControlAudience,
		CustomerID: "customer-1", InstallationID: "installation-1", LicenseID: "license-1", Serial: 42,
		NotBefore: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), GraceUntil: now.Add(24 * time.Hour).Unix(),
		Version:  VersionRange{Channel: "stable", Min: "5.8.0", Max: "5.9.0"},
		Features: []Feature{{Code: "sites.manage"}, {Code: "waf.manage"}},
		Quotas:   []Quota{{Code: "domains.count", Limit: 100}, {Code: "nodes.count", Limit: 10}},
	}
}
