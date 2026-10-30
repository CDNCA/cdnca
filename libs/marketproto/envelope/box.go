package envelope

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Box is one secret sealed to a member's X25519 key with the same ephemeral
// X25519 + HKDF-SHA256 + XChaCha20-Poly1305 construction as Seal, without a
// header or signature: it travels inside an already signed envelope (the
// origin auth credentials of a siteconf revision, fix-mktsiteconf5), so
// copies of that payload kept by the sender hold ciphertext only. domain
// separates uses (it is the HKDF info and prefixes the associated data);
// aad binds the box to its context.
type Box struct {
	Ephemeral  []byte `json:"ephemeral"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

const maxBoxDomain = 128

// SealBox seals payload to recipientX25519.
func SealBox(domain string, payload, aad, recipientX25519 []byte) (Box, error) {
	return sealBox(rand.Reader, domain, payload, aad, recipientX25519)
}

// SealBoxSeeded is SealBox with the ephemeral key and nonce derived from
// seed (HKDF-SHA256), so equal inputs give equal boxes: a sender that
// recompiles the same revision (preview, then apply) gets the same digest.
// seed must be secret and bound to the payload, recipient and aad.
func SealBoxSeeded(seed [32]byte, domain string, payload, aad, recipientX25519 []byte) (Box, error) {
	return sealBox(hkdf.New(sha256.New, seed[:], nil, []byte(domain+" seed")), domain, payload, aad, recipientX25519)
}

func sealBox(entropy io.Reader, domain string, payload, aad, recipientX25519 []byte) (Box, error) {
	if domain == "" || len(domain) > maxBoxDomain || len(payload) > MaxPayloadBytes ||
		len(recipientX25519) != curve25519.PointSize {
		return Box{}, ErrInvalid
	}
	ephemeralPrivate := make([]byte, curve25519.ScalarSize)
	defer clear(ephemeralPrivate)
	if _, err := io.ReadFull(entropy, ephemeralPrivate); err != nil {
		return Box{}, ErrInvalid
	}
	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return Box{}, ErrInvalid
	}
	aead, err := deriveAEAD(ephemeralPrivate, recipientX25519, ephemeralPublic, recipientX25519, domain+" key")
	if err != nil {
		return Box{}, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(entropy, nonce); err != nil {
		return Box{}, ErrInvalid
	}
	return Box{Ephemeral: ephemeralPublic, Nonce: nonce,
		Ciphertext: aead.Seal(nil, nonce, payload, boxAAD(domain, aad))}, nil
}

// OpenBox decrypts b with the recipient's X25519 private key; another key,
// domain or aad gives ErrDecrypt.
func OpenBox(domain string, b Box, aad, recipientPrivate []byte) ([]byte, error) {
	if domain == "" || len(domain) > maxBoxDomain || len(b.Ephemeral) != curve25519.PointSize ||
		len(b.Nonce) != chacha20poly1305.NonceSizeX || len(b.Ciphertext) < chacha20poly1305.Overhead ||
		len(b.Ciphertext) > MaxPayloadBytes+chacha20poly1305.Overhead || len(recipientPrivate) != curve25519.ScalarSize {
		return nil, ErrInvalid
	}
	recipientPublic, err := curve25519.X25519(recipientPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := deriveAEAD(recipientPrivate, b.Ephemeral, b.Ephemeral, recipientPublic, domain+" key")
	if err != nil {
		return nil, err
	}
	payload, err := aead.Open(nil, b.Nonce, b.Ciphertext, boxAAD(domain, aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return payload, nil
}

func boxAAD(domain string, aad []byte) []byte {
	out := make([]byte, 0, len(domain)+1+len(aad))
	out = append(append(append(out, domain...), 0), aad...)
	return out
}
