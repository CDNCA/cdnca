package analytics

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"sync"
)

type rotatingIsolationKeyProvider struct {
	mu      sync.RWMutex
	active  string
	keys    map[string][]byte
	retired map[string]bool
}

func newRotatingIsolationKeyProvider() *rotatingIsolationKeyProvider {
	return &rotatingIsolationKeyProvider{
		active: "kek-v1",
		keys: map[string][]byte{
			"kek-v1": bytes.Repeat([]byte{0x11}, 32),
			"kek-v2": bytes.Repeat([]byte{0x22}, 32),
		},
		retired: make(map[string]bool),
	}
}

func (provider *rotatingIsolationKeyProvider) ActiveKeyID(context.Context) (string, error) {
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	if provider.active == "" || provider.retired[provider.active] {
		return "", errors.New("no active isolation KEK")
	}
	return provider.active, nil
}

func (provider *rotatingIsolationKeyProvider) WrapDEK(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	provider.mu.RLock()
	key := append([]byte(nil), provider.keys[keyID]...)
	retired := provider.retired[keyID]
	provider.mu.RUnlock()
	defer clear(key)
	if len(key) != 32 || retired {
		return nil, errors.New("unknown or retired isolation KEK")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, plaintext, []byte(keyID))...), nil
}

func (provider *rotatingIsolationKeyProvider) UnwrapDEK(_ context.Context, keyID string, wrapped []byte) ([]byte, error) {
	provider.mu.RLock()
	key := append([]byte(nil), provider.keys[keyID]...)
	retired := provider.retired[keyID]
	provider.mu.RUnlock()
	defer clear(key)
	if len(key) != 32 || retired {
		return nil, errors.New("unknown or retired isolation KEK")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(wrapped) < aead.NonceSize() {
		return nil, errors.New("invalid wrapped isolation DEK")
	}
	return aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], []byte(keyID))
}

func (provider *rotatingIsolationKeyProvider) rotate(keyID string) {
	provider.mu.Lock()
	provider.active = keyID
	provider.mu.Unlock()
}

func (provider *rotatingIsolationKeyProvider) retire(keyID string) {
	provider.mu.Lock()
	provider.retired[keyID] = true
	provider.mu.Unlock()
}
