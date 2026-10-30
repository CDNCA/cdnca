package openrestysecurity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
)

const (
	secretEnvelopePrefix = "CDNORS\x01"
	secretEnvelopeAAD    = "cdnca.control-api.openresty-security.secret.v1"
)

var (
	ErrInvalidSecretKey      = errors.New("invalid OpenResty security secret key")
	ErrInvalidSecretEnvelope = errors.New("invalid OpenResty security secret envelope")
)

// SecretCipher seals OpenResty security secrets in a versioned AES-256-GCM envelope.
type SecretCipher struct {
	aead cipher.AEAD
}

var _ SecretSealer = (*SecretCipher)(nil)

func NewSecretCipher(key []byte) (*SecretCipher, error) {
	if len(key) != 32 {
		return nil, ErrInvalidSecretKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidSecretKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &SecretCipher{aead: aead}, nil
}

func (secret *SecretCipher) Seal(ctx context.Context, plaintext []byte) ([]byte, error) {
	if secret == nil || secret.aead == nil || ctx == nil || len(plaintext) == 0 {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nonce := make([]byte, secret.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrUnavailable
	}
	prefix := []byte(secretEnvelopePrefix)
	envelope := make([]byte, 0, len(prefix)+len(nonce)+len(plaintext)+secret.aead.Overhead())
	envelope = append(envelope, prefix...)
	envelope = append(envelope, nonce...)
	return secret.aead.Seal(envelope, nonce, plaintext, []byte(secretEnvelopeAAD)), nil
}

func (secret *SecretCipher) Unseal(ctx context.Context, envelope []byte) ([]byte, error) {
	if secret == nil || secret.aead == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prefix := []byte(secretEnvelopePrefix)
	minimumSize := len(prefix) + secret.aead.NonceSize() + secret.aead.Overhead()
	if len(envelope) < minimumSize || subtle.ConstantTimeCompare(envelope[:len(prefix)], prefix) != 1 {
		return nil, ErrInvalidSecretEnvelope
	}
	nonceStart := len(prefix)
	nonceEnd := nonceStart + secret.aead.NonceSize()
	plaintext, err := secret.aead.Open(nil, envelope[nonceStart:nonceEnd], envelope[nonceEnd:], []byte(secretEnvelopeAAD))
	if err != nil {
		return nil, ErrInvalidSecretEnvelope
	}
	return plaintext, nil
}

func (SecretCipher) String() string {
	return "openrestysecurity.SecretCipher([REDACTED])"
}

func (SecretCipher) GoString() string {
	return "openrestysecurity.SecretCipher([REDACTED])"
}
