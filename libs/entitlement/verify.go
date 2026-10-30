package entitlement

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"
)

// VerifierClockSkew bounds how far a signer's clock may lead the verifier's
// clock. Artifacts are signed by another host, so an artifact issued "now" can
// arrive before the verifier's clock reaches its start time. Only start bounds
// (issued_at/not_before) are relaxed; expiry bounds stay exact.
const VerifierClockSkew = 30 * time.Second

// notYetValid reports whether start is still in the future after allowing for
// VerifierClockSkew.
func notYetValid(now, start int64) bool {
	return now+int64(VerifierClockSkew/time.Second) < start
}

type Status string

const (
	StatusValid   Status = "valid"
	StatusGrace   Status = "grace"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
)

type Result struct {
	Lease  Lease
	Status Status
}

type VerifyOptions struct {
	Now                    time.Time
	ExpectedAudience       string
	ExpectedInstallationID string
	RevokedSerials         []uint64
}

type KeyRing struct {
	keys map[string]ed25519.PublicKey
}

func NewKeyRing() *KeyRing {
	return &KeyRing{keys: make(map[string]ed25519.PublicKey)}
}

func (ring *KeyRing) Add(keyID string, publicKey ed25519.PublicKey) error {
	if ring == nil || !validID(keyID) || ValidateEd25519PublicKey(publicKey) != nil {
		return ErrInvalidEnvelope
	}
	if current, exists := ring.keys[keyID]; exists && subtle.ConstantTimeCompare(current, publicKey) != 1 {
		return errors.New("signing key ID already has different key material")
	}
	ring.keys[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	return nil
}

func (ring *KeyRing) Verify(signed SignedLease, options VerifyOptions) (Result, error) {
	if ring == nil {
		return Result{}, ErrUnknownKey
	}
	if err := signed.validateEnvelope(); err != nil {
		return Result{}, err
	}
	publicKey, exists := ring.keys[signed.KeyID]
	if !exists {
		return Result{}, ErrUnknownKey
	}
	payload, err := signed.signingBytes()
	if err != nil {
		return Result{}, err
	}
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if !ed25519.Verify(publicKey, payload, signature) {
		return Result{}, ErrInvalidSignature
	}
	if options.ExpectedAudience == "" || signed.Lease.Audience != options.ExpectedAudience {
		return Result{}, ErrAudienceMismatch
	}
	if options.ExpectedInstallationID == "" || signed.Lease.InstallationID != options.ExpectedInstallationID {
		return Result{}, ErrInstallationMismatch
	}
	for _, serial := range options.RevokedSerials {
		if serial == signed.Lease.Serial {
			return Result{Lease: signed.Lease, Status: StatusRevoked}, nil
		}
	}
	now := options.Now.UTC().Unix()
	if options.Now.IsZero() || notYetValid(now, signed.Lease.NotBefore) {
		return Result{}, ErrNotYetValid
	}
	status := StatusValid
	if now >= signed.Lease.GraceUntil {
		status = StatusExpired
	} else if now >= signed.Lease.ExpiresAt {
		status = StatusGrace
	}
	return Result{Lease: signed.Lease, Status: status}, nil
}
