package entitlement

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type revocationTestSigner struct {
	id      string
	private ed25519.PrivateKey
	err     error
	payload []byte
}

func (signer *revocationTestSigner) KeyID() string { return signer.id }

func (signer *revocationTestSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	signer.payload = append([]byte(nil), payload...)
	if signer.err != nil {
		return nil, signer.err
	}
	return ed25519.Sign(signer.private, payload), nil
}

func TestRevocationSetV2CanonicalSignEncodeVerify(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Unix(1_900_000_000, 0).UTC()
	body := validRevocationSet(issuedAt)
	signer := &revocationTestSigner{id: "lease-key-2026-07", private: privateKey}
	verifyUntil := issuedAt.Add(24 * time.Hour)
	signed, err := SignRevocationSet(t.Context(), body, signer, RevocationKeyWindow{
		NotBefore: issuedAt.Add(-time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil,
	})
	if err != nil {
		t.Fatalf("SignRevocationSet() error = %v", err)
	}
	wantDocument := `{"domain":"cdnca-entitlement-revocation-set-signature/v2","algorithm":"Ed25519","key_id":"lease-key-2026-07","body":{"schema":"cdnca.entitlement.revocation-set/v2","audience":"cdnca-control-plane","customer_id":"aaaaaaaa-1111-4111-8111-111111111111","installation_id":"22222222-2222-4222-8222-222222222222","license_id":"33333333-3333-4333-8333-333333333333","revision":7,"issued_at":1900000000,"expires_at":1900000900,"revoked_serials":[2,9,101]}}`
	if string(signer.payload) != wantDocument {
		t.Fatalf("signing document = %s, want %s", signer.payload, wantDocument)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > RevocationSetMaxBytes || bytes.Contains(encoded, []byte("\n")) {
		t.Fatalf("wire length/newline = %d/%v", len(encoded), bytes.Contains(encoded, []byte("\n")))
	}
	digest := sha256.Sum256(encoded)
	if RevocationSetDigest(encoded) != digest || RevocationSetETag(encoded) != `"sha256-`+base64.RawURLEncoding.EncodeToString(digest[:])+`"` {
		t.Fatalf("digest/ETag mismatch: %x %q", RevocationSetDigest(encoded), RevocationSetETag(encoded))
	}
	decoded, err := DecodeRevocationSet(encoded)
	if err != nil || !reflect.DeepEqual(decoded, signed) {
		t.Fatalf("DecodeRevocationSet() = (%#v, %v), want %#v", decoded, err, signed)
	}
	verified, err := VerifyRevocationSet(decoded, publicKey, RevocationVerifyOptions{
		Now: issuedAt.Add(time.Second), ExpectedAudience: RevocationSetAudience,
		ExpectedCustomerID: body.CustomerID, ExpectedInstallationID: body.InstallationID,
		ExpectedLicenseID: body.LicenseID, KeyWindow: RevocationKeyWindow{
			NotBefore: issuedAt.Add(-time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil,
		},
	})
	if err != nil || !reflect.DeepEqual(verified, body) {
		t.Fatalf("VerifyRevocationSet() = (%#v, %v), want %#v", verified, err, body)
	}
}

func TestRevocationSetV2RejectsNonCanonicalAndInvalidValues(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	issuedAt := time.Unix(1_900_000_000, 0).UTC()
	signer := &revocationTestSigner{id: "revocation-key-1", private: privateKey}
	windowEnd := issuedAt.Add(time.Hour)
	signed, err := SignRevocationSet(t.Context(), validRevocationSet(issuedAt), signer,
		RevocationKeyWindow{NotBefore: issuedAt.Add(-time.Hour), SignUntil: &windowEnd, VerifyUntil: &windowEnd})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := signed.Encode()
	mutations := map[string][]byte{
		"leading whitespace": append([]byte(" "), encoded...),
		"trailing data":      append(append([]byte(nil), encoded...), []byte("{}")...),
		"unknown field":      bytes.Replace(encoded, []byte(`"signature":`), []byte(`"unknown":1,"signature":`), 1),
		"duplicate field":    bytes.Replace(encoded, []byte(`"algorithm":`), []byte(`"algorithm":"Ed25519","algorithm":`), 1),
		"padded signature":   bytes.Replace(encoded, []byte(signed.Signature), []byte(signed.Signature+"="), 1),
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRevocationSet(mutation); !errors.Is(err, ErrInvalidRevocationEnvelope) {
				t.Fatalf("DecodeRevocationSet() error = %v", err)
			}
		})
	}

	invalidBodies := map[string]func(*RevocationSet){
		"schema":            func(value *RevocationSet) { value.Schema = "cdnca.entitlement.revocation-set/v1" },
		"audience":          func(value *RevocationSet) { value.Audience = "other" },
		"customer UUID":     func(value *RevocationSet) { value.CustomerID = strings.ToUpper(value.CustomerID) },
		"installation UUID": func(value *RevocationSet) { value.InstallationID = "22222222-2222-4222-8222-22222222222" },
		"license UUID":      func(value *RevocationSet) { value.LicenseID = "not-a-uuid" },
		"zero revision":     func(value *RevocationSet) { value.Revision = 0 },
		"wrong window":      func(value *RevocationSet) { value.ExpiresAt-- },
		"nil serial set":    func(value *RevocationSet) { value.RevokedSerials = nil },
		"zero serial":       func(value *RevocationSet) { value.RevokedSerials = []uint64{0} },
		"duplicate serial":  func(value *RevocationSet) { value.RevokedSerials = []uint64{2, 2} },
		"unsorted serial":   func(value *RevocationSet) { value.RevokedSerials = []uint64{9, 2} },
		"serial overflow":   func(value *RevocationSet) { value.RevokedSerials = []uint64{1 << 63} },
		"too many serials":  func(value *RevocationSet) { value.RevokedSerials = make([]uint64, RevocationSetMaxSerials+1) },
	}
	for name, mutate := range invalidBodies {
		t.Run(name, func(t *testing.T) {
			value := validRevocationSet(issuedAt)
			mutate(&value)
			if _, err := SignRevocationSet(t.Context(), value, signer,
				RevocationKeyWindow{NotBefore: issuedAt.Add(-time.Hour), SignUntil: &windowEnd, VerifyUntil: &windowEnd}); !errors.Is(err, ErrInvalidRevocationSet) {
				t.Fatalf("SignRevocationSet() error = %v", err)
			}
		})
	}
}

func TestRevocationSetV2KeyWindowSignerFailureAndFetchProof(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	issuedAt := time.Unix(1_900_000_000, 0).UTC()
	body := validRevocationSet(issuedAt)
	signer := &revocationTestSigner{id: "revocation-key-1", private: privateKey}
	tooShort := issuedAt.Add(RevocationSetWindow - time.Second)
	if _, err := SignRevocationSet(t.Context(), body, signer,
		RevocationKeyWindow{NotBefore: issuedAt, SignUntil: &tooShort, VerifyUntil: &tooShort}); !errors.Is(err, ErrRevocationKeyWindow) {
		t.Fatalf("short key window error = %v", err)
	}
	signer.err = errors.New("signer unavailable")
	windowEnd := issuedAt.Add(time.Hour)
	if _, err := SignRevocationSet(t.Context(), body, signer,
		RevocationKeyWindow{NotBefore: issuedAt, SignUntil: &windowEnd, VerifyUntil: &windowEnd}); !errors.Is(err, signer.err) {
		t.Fatalf("signer error = %v", err)
	}

	knownDigest := sha256.Sum256([]byte("known revocation set"))
	knownDigestText := base64.RawURLEncoding.EncodeToString(knownDigest[:])
	proof := RevocationFetchProof{InstallationID: body.InstallationID, RequestID: "request-123",
		RequestedAt: issuedAt.Unix(), KnownRevision: 6, KnownDigest: knownDigestText,
		IfNoneMatch: `"sha256-` + knownDigestText + `"`}
	message, err := RevocationFetchProofMessage(proof)
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	if err := VerifyRevocationFetchProof(proof, publicKey, issuedAt.Add(RevocationFetchClockSkew)); err != nil {
		t.Fatalf("VerifyRevocationFetchProof(boundary) error = %v", err)
	}
	if err := VerifyRevocationFetchProof(proof, publicKey, issuedAt.Add(RevocationFetchClockSkew+time.Second)); !errors.Is(err, ErrRevocationFetchExpired) {
		t.Fatalf("expired proof error = %v", err)
	}
	proof.RequestID = "changed"
	if err := VerifyRevocationFetchProof(proof, publicKey, issuedAt); !errors.Is(err, ErrInvalidRevocationFetchProof) {
		t.Fatalf("tampered proof error = %v", err)
	}
}

func validRevocationSet(issuedAt time.Time) RevocationSet {
	return RevocationSet{
		Schema: RevocationSetSchemaV2, Audience: RevocationSetAudience,
		CustomerID:     "aaaaaaaa-1111-4111-8111-111111111111",
		InstallationID: "22222222-2222-4222-8222-222222222222",
		LicenseID:      "33333333-3333-4333-8333-333333333333", Revision: 7,
		IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(RevocationSetWindow).Unix(),
		RevokedSerials: []uint64{2, 9, 101},
	}
}
