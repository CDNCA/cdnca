package entitlement

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

type signingDocument struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Lease     Lease  `json:"lease"`
}

type SignedLease struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Lease     Lease  `json:"lease"`
	Signature string `json:"signature"`
}

func Sign(ctx context.Context, lease Lease, signer Signer) (SignedLease, error) {
	if signer == nil || !validID(signer.KeyID()) {
		return SignedLease{}, ErrInvalidEnvelope
	}
	if err := lease.Validate(); err != nil {
		return SignedLease{}, err
	}
	document := signingDocument{Algorithm: Algorithm, KeyID: signer.KeyID(), Lease: lease}
	payload, err := json.Marshal(document)
	if err != nil {
		return SignedLease{}, fmt.Errorf("marshal signing document: %w", err)
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return SignedLease{}, fmt.Errorf("sign entitlement lease: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return SignedLease{}, ErrInvalidSignature
	}
	return SignedLease{
		Algorithm: Algorithm,
		KeyID:     signer.KeyID(),
		Lease:     lease,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

func (signed SignedLease) Encode() ([]byte, error) {
	if err := signed.validateEnvelope(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		return nil, fmt.Errorf("encode signed lease: %w", err)
	}
	return encoded, nil
}

func Decode(encoded []byte) (SignedLease, error) {
	if len(encoded) == 0 || len(encoded) > 64*1024 {
		return SignedLease{}, ErrInvalidEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed SignedLease
	if err := decoder.Decode(&signed); err != nil {
		return SignedLease{}, ErrInvalidEnvelope
	}
	if decoder.More() {
		return SignedLease{}, ErrInvalidEnvelope
	}
	if err := signed.validateEnvelope(); err != nil {
		return SignedLease{}, err
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return SignedLease{}, ErrInvalidEnvelope
	}
	return signed, nil
}

func (signed SignedLease) validateEnvelope() error {
	if signed.Algorithm != Algorithm || !validID(signed.KeyID) {
		return ErrInvalidEnvelope
	}
	if err := signed.Lease.Validate(); err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidEnvelope
	}
	return nil
}

func (signed SignedLease) signingBytes() ([]byte, error) {
	return json.Marshal(signingDocument{
		Algorithm: signed.Algorithm,
		KeyID:     signed.KeyID,
		Lease:     signed.Lease,
	})
}
