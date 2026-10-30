// Package envelope implements the relay message format: a plaintext header the
// market can inspect for compliance checks, and a payload only the recipient
// controller can decrypt (docs/marketplace/01-architecture.md §4).
//
// Seal: ephemeral X25519 + HKDF-SHA256 -> XChaCha20-Poly1305 with the header as
// associated data; the sender signs domain||header||ephemeral||nonce||ciphertext
// with its Ed25519 member key so the relay and recipient can authenticate it.
package envelope

import (
	"bytes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	SchemaV1      = "cdnca.market.envelope/v1"
	signingDomain = SchemaV1 + "\n"
	hkdfInfo      = SchemaV1 + " key"

	MaxPayloadBytes = 4 << 20
	maxHeaderBytes  = 16 << 10
	maxDomains      = 256
	maxDomainLength = 253
)

var (
	ErrInvalid   = errors.New("invalid market envelope")
	ErrSignature = errors.New("market envelope signature rejected")
	ErrDecrypt   = errors.New("market envelope cannot be decrypted")

	operationPattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
)

// Header is visible to the relay. It must carry enough to enforce blacklists,
// ICP rules and grant scope without exposing site configuration or keys.
type Header struct {
	Schema          string    `json:"schema"`
	MessageID       uuid.UUID `json:"message_id"`
	IdempotencyKey  string    `json:"idempotency_key"`
	SenderMemberID  uuid.UUID `json:"sender_member_id"`
	RecipientMember uuid.UUID `json:"recipient_member_id"`
	GrantID         uuid.UUID `json:"grant_id"`
	Operation       string    `json:"operation"`
	Domains         []string  `json:"domains"`
	ProtocolVersion int       `json:"protocol_version"`
	CreatedAt       int64     `json:"created_at"`
}

func (h Header) Validate() error {
	if h.Schema != SchemaV1 || h.MessageID == uuid.Nil || h.SenderMemberID == uuid.Nil ||
		h.RecipientMember == uuid.Nil || h.SenderMemberID == h.RecipientMember {
		return ErrInvalid
	}
	if h.IdempotencyKey == "" || len(h.IdempotencyKey) > 128 || !operationPattern.MatchString(h.Operation) {
		return ErrInvalid
	}
	if len(h.Domains) > maxDomains || h.ProtocolVersion < 1 || h.CreatedAt <= 0 {
		return ErrInvalid
	}
	for _, domain := range h.Domains {
		if domain == "" || len(domain) > maxDomainLength {
			return ErrInvalid
		}
	}
	return nil
}

// Sealed is the wire form. HeaderBytes is kept verbatim so signatures and AEAD
// associated data are checked against exactly what the sender produced.
type Sealed struct {
	HeaderBytes []byte `json:"header"`
	Ephemeral   []byte `json:"ephemeral"`
	Nonce       []byte `json:"nonce"`
	Ciphertext  []byte `json:"ciphertext"`
	Signature   []byte `json:"signature"`
}

// Seal encrypts payload to recipientX25519 and signs it with senderKey.
func Seal(header Header, payload []byte, recipientX25519 []byte, senderKey ed25519.PrivateKey) (Sealed, error) {
	return seal(rand.Reader, header, payload, recipientX25519, senderKey)
}

func seal(entropy io.Reader, header Header, payload []byte, recipientX25519 []byte, senderKey ed25519.PrivateKey) (Sealed, error) {
	if err := header.Validate(); err != nil {
		return Sealed{}, err
	}
	if len(payload) > MaxPayloadBytes || len(recipientX25519) != curve25519.PointSize || len(senderKey) != ed25519.PrivateKeySize {
		return Sealed{}, ErrInvalid
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return Sealed{}, fmt.Errorf("encode envelope header: %w", err)
	}
	ephemeralPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(entropy, ephemeralPrivate); err != nil {
		return Sealed{}, fmt.Errorf("envelope entropy: %w", err)
	}
	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return Sealed{}, ErrInvalid
	}
	aead, err := deriveAEAD(ephemeralPrivate, recipientX25519, ephemeralPublic, recipientX25519, hkdfInfo)
	if err != nil {
		return Sealed{}, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(entropy, nonce); err != nil {
		return Sealed{}, fmt.Errorf("envelope entropy: %w", err)
	}
	s := Sealed{HeaderBytes: headerBytes, Ephemeral: ephemeralPublic, Nonce: nonce}
	s.Ciphertext = aead.Seal(nil, nonce, payload, headerBytes)
	s.Signature = ed25519.Sign(senderKey, s.signedMessage())
	return s, nil
}

// KeyLookup returns the registered Ed25519 signing key of a member.
type KeyLookup func(memberID uuid.UUID) (ed25519.PublicKey, error)

// Inspect authenticates the sender and returns the header without decrypting.
// The signing key is looked up from the header's own sender, so a valid result
// always means "signed by SenderMemberID". The relay uses it; it never holds
// recipient private keys.
func Inspect(s Sealed, lookup KeyLookup) (Header, error) {
	if len(s.HeaderBytes) == 0 || len(s.HeaderBytes) > maxHeaderBytes || len(s.Ephemeral) != curve25519.PointSize ||
		len(s.Nonce) != chacha20poly1305.NonceSizeX || len(s.Signature) != ed25519.SignatureSize ||
		len(s.Ciphertext) > MaxPayloadBytes+chacha20poly1305.Overhead || lookup == nil {
		return Header{}, ErrInvalid
	}
	// Unknown header fields from newer senders are ignored (the signature and
	// AEAD cover HeaderBytes verbatim); anything a receiver must understand
	// needs a new Schema, which Validate rejects.
	decoder := json.NewDecoder(bytes.NewReader(s.HeaderBytes))
	var header Header
	if err := decoder.Decode(&header); err != nil || decoder.More() {
		return Header{}, ErrInvalid
	}
	if err := header.Validate(); err != nil {
		return Header{}, err
	}
	senderPublic, err := lookup(header.SenderMemberID)
	if err != nil || len(senderPublic) != ed25519.PublicKeySize {
		return Header{}, ErrSignature
	}
	if !ed25519.Verify(senderPublic, s.signedMessage(), s.Signature) {
		return Header{}, ErrSignature
	}
	return header, nil
}

// Open authenticates, checks the envelope is addressed to self, then decrypts
// with self's X25519 private key.
func Open(s Sealed, lookup KeyLookup, self uuid.UUID, recipientPrivate []byte) (Header, []byte, error) {
	header, err := Inspect(s, lookup)
	if err != nil {
		return Header{}, nil, err
	}
	if header.RecipientMember != self {
		return Header{}, nil, ErrInvalid
	}
	if len(recipientPrivate) != curve25519.ScalarSize {
		return Header{}, nil, ErrInvalid
	}
	recipientPublic, err := curve25519.X25519(recipientPrivate, curve25519.Basepoint)
	if err != nil {
		return Header{}, nil, ErrInvalid
	}
	aead, err := deriveAEAD(recipientPrivate, s.Ephemeral, s.Ephemeral, recipientPublic, hkdfInfo)
	if err != nil {
		return Header{}, nil, err
	}
	payload, err := aead.Open(nil, s.Nonce, s.Ciphertext, s.HeaderBytes)
	if err != nil {
		return Header{}, nil, ErrDecrypt
	}
	return header, payload, nil
}

func deriveAEAD(private, peer, ephemeralPublic, recipientPublic []byte, info string) (cipher.AEAD, error) {
	shared, err := curve25519.X25519(private, peer)
	if err != nil {
		// Rejects low-order peer points (all-zero shared secret).
		return nil, ErrInvalid
	}
	salt := make([]byte, 0, 2*curve25519.PointSize)
	salt = append(salt, ephemeralPublic...)
	salt = append(salt, recipientPublic...)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte(info)), key); err != nil {
		return nil, fmt.Errorf("derive envelope key: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("envelope cipher: %w", err)
	}
	return aead, nil
}

func (s Sealed) signedMessage() []byte {
	message := make([]byte, 0, len(signingDomain)+len(s.HeaderBytes)+len(s.Ephemeral)+len(s.Nonce)+len(s.Ciphertext)+16)
	message = append(message, signingDomain...)
	for _, part := range [][]byte{s.HeaderBytes, s.Ephemeral, s.Nonce, s.Ciphertext} {
		message = appendLength(message, len(part))
		message = append(message, part...)
	}
	return message
}

// appendLength length-prefixes each signed part so boundaries cannot shift.
func appendLength(dst []byte, n int) []byte {
	return append(dst, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
