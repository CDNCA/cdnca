package accountregistrationchallenge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"regexp"
)

var envelopeKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type SealedEnvelope struct {
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

type EnvelopeKeyring struct {
	activeID string
	keys     map[string][]byte
	random   io.Reader
}

func NewEnvelopeKeyring(activeID string, keys map[string][]byte) (*EnvelopeKeyring, error) {
	if !envelopeKeyIDPattern.MatchString(activeID) || len(keys) == 0 {
		return nil, ErrInvalidConfig
	}
	cloned := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if !envelopeKeyIDPattern.MatchString(id) || len(key) != 32 {
			return nil, ErrInvalidConfig
		}
		cloned[id] = append([]byte(nil), key...)
	}
	if _, exists := cloned[activeID]; !exists {
		return nil, ErrInvalidConfig
	}
	return &EnvelopeKeyring{activeID: activeID, keys: cloned, random: rand.Reader}, nil
}

func (keyring *EnvelopeKeyring) Seal(plaintext, aad []byte) (SealedEnvelope, error) {
	if keyring == nil || len(plaintext) == 0 || len(aad) == 0 {
		return SealedEnvelope{}, ErrInvalidConfig
	}
	aead, err := keyring.aead(keyring.activeID)
	if err != nil {
		return SealedEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(keyring.random, nonce); err != nil {
		return SealedEnvelope{}, ErrChallengeUnavailable
	}
	return SealedEnvelope{
		KeyID: keyring.activeID, Nonce: nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, aad),
	}, nil
}

func (keyring *EnvelopeKeyring) Open(envelope SealedEnvelope, aad []byte) ([]byte, error) {
	if keyring == nil || len(aad) == 0 {
		return nil, ErrInvalidConfig
	}
	aead, err := keyring.aead(envelope.KeyID)
	if err != nil || len(envelope.Nonce) != aead.NonceSize() || len(envelope.Ciphertext) < aead.Overhead() {
		return nil, ErrChallengeUnavailable
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrChallengeUnavailable
	}
	return plaintext, nil
}

func (keyring *EnvelopeKeyring) aead(keyID string) (cipher.AEAD, error) {
	key, exists := keyring.keys[keyID]
	if !exists {
		return nil, ErrChallengeUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrChallengeUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrChallengeUnavailable
	}
	return aead, nil
}

func validEnvelopeKeyring(keyring *EnvelopeKeyring) bool {
	if keyring == nil || keyring.random == nil || len(keyring.keys) == 0 {
		return false
	}
	_, err := keyring.aead(keyring.activeID)
	return !errors.Is(err, ErrChallengeUnavailable)
}
