// Package card is the market-signed binding of a member ID to its keys. A
// controller seals to a peer's box key and verifies a peer's envelopes only
// with keys taken from a verified card, never from keys handed over in transit.
package card

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
)

const Domain = "cdnca.market.member-card/v1\n"

var (
	ErrUnknownKey = errors.New("member card signing key unknown")
	ErrSignature  = errors.New("member card signature rejected")
	ErrInvalid    = errors.New("invalid member card")
)

type Card struct {
	MemberID         uuid.UUID `json:"member_id"`
	SigningPublicKey []byte    `json:"signing_public_key"`
	BoxPublicKey     []byte    `json:"box_public_key"`
	IssuedAt         int64     `json:"issued_at"`
}

type Signed struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func Sign(c Card, keyID string, key ed25519.PrivateKey) (Signed, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return Signed{}, err
	}
	return Signed{
		KeyID:     keyID,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(Domain), payload...))),
	}, nil
}

func Verify(keys map[string]ed25519.PublicKey, s Signed) (Card, error) {
	public, ok := keys[s.KeyID]
	if !ok || len(public) != ed25519.PublicKeySize {
		return Card{}, ErrUnknownKey
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(s.Payload)
	if err != nil {
		return Card{}, ErrInvalid
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(public, append([]byte(Domain), payload...), signature) {
		return Card{}, ErrSignature
	}
	var c Card
	if err := json.Unmarshal(payload, &c); err != nil || c.MemberID == uuid.Nil ||
		len(c.SigningPublicKey) != ed25519.PublicKeySize || len(c.BoxPublicKey) != 32 {
		return Card{}, ErrInvalid
	}
	return c, nil
}
