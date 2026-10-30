package accountrecovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"regexp"
)

const dispatchDataKeyBytes = 32

var dispatchKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type DispatchKeyring struct {
	activeID string
	keys     map[string]cipher.AEAD
	entropy  io.Reader
}

func NewDispatchKeyring(activeID string, keys map[string][]byte) (*DispatchKeyring, error) {
	return newDispatchKeyring(activeID, keys, rand.Reader)
}

func newDispatchKeyring(activeID string, keys map[string][]byte, entropy io.Reader) (*DispatchKeyring, error) {
	if !dispatchKeyIDPattern.MatchString(activeID) || len(keys) == 0 || entropy == nil {
		return nil, ErrDispatchUnavailable
	}
	ring := &DispatchKeyring{activeID: activeID, keys: make(map[string]cipher.AEAD, len(keys)), entropy: entropy}
	for keyID, key := range keys {
		if !dispatchKeyIDPattern.MatchString(keyID) || len(key) != 32 {
			return nil, ErrDispatchUnavailable
		}
		block, err := aes.NewCipher(append([]byte(nil), key...))
		if err != nil {
			return nil, ErrDispatchUnavailable
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrDispatchUnavailable
		}
		ring.keys[keyID] = aead
	}
	if _, exists := ring.keys[activeID]; !exists {
		return nil, ErrDispatchUnavailable
	}
	return ring, nil
}

func (r *DispatchKeyring) seal(plaintext, aad []byte) (string, []byte, []byte, [32]byte, error) {
	if r == nil || r.entropy == nil {
		return "", nil, nil, [32]byte{}, ErrDispatchUnavailable
	}
	kek, exists := r.keys[r.activeID]
	if !exists {
		return "", nil, nil, [32]byte{}, ErrDispatchUnavailable
	}
	dataKey := make([]byte, dispatchDataKeyBytes)
	if _, err := io.ReadFull(r.entropy, dataKey); err != nil {
		return "", nil, nil, [32]byte{}, ErrDispatchUnavailable
	}
	defer clear(dataKey)
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", nil, nil, [32]byte{}, ErrDispatchUnavailable
	}
	dataAEAD, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, nil, [32]byte{}, ErrDispatchUnavailable
	}
	aadHash := sha256.Sum256(aad)
	wrappedKey, err := sealAEAD(kek, dataKey, wrapAAD(aadHash), r.entropy)
	if err != nil {
		return "", nil, nil, [32]byte{}, ErrDispatchUnavailable
	}
	sealedToken, err := sealAEAD(dataAEAD, plaintext, payloadAAD(aad), r.entropy)
	if err != nil {
		return "", nil, nil, [32]byte{}, ErrDispatchUnavailable
	}
	return r.activeID, wrappedKey, sealedToken, aadHash, nil
}

func (r *DispatchKeyring) open(keyID string, wrappedKey, sealedToken, aad []byte) ([]byte, error) {
	if r == nil {
		return nil, ErrDispatchUnavailable
	}
	kek, exists := r.keys[keyID]
	if !exists {
		return nil, ErrDispatchUnavailable
	}
	aadHash := sha256.Sum256(aad)
	dataKey, err := openAEAD(kek, wrappedKey, wrapAAD(aadHash))
	if err != nil || len(dataKey) != dispatchDataKeyBytes {
		clear(dataKey)
		return nil, ErrDispatchUnavailable
	}
	defer clear(dataKey)
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, ErrDispatchUnavailable
	}
	dataAEAD, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDispatchUnavailable
	}
	plaintext, err := openAEAD(dataAEAD, sealedToken, payloadAAD(aad))
	if err != nil {
		return nil, ErrDispatchUnavailable
	}
	return plaintext, nil
}

func sealAEAD(aead cipher.AEAD, plaintext, aad []byte, entropy io.Reader) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(entropy, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

func openAEAD(aead cipher.AEAD, sealed, aad []byte) ([]byte, error) {
	if len(sealed) <= aead.NonceSize() {
		return nil, ErrDispatchUnavailable
	}
	plaintext, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], aad)
	if err != nil {
		return nil, ErrDispatchUnavailable
	}
	return plaintext, nil
}

func wrapAAD(hash [32]byte) []byte {
	return append([]byte("cdnca/account-recovery/dispatch-key-wrap/v1\x00"), hash[:]...)
}

func payloadAAD(aad []byte) []byte {
	return append([]byte("cdnca/account-recovery/dispatch-payload/v1\x00"), aad...)
}

func validDispatchKeyring(ring *DispatchKeyring) bool {
	if ring == nil || ring.entropy == nil || !dispatchKeyIDPattern.MatchString(ring.activeID) {
		return false
	}
	_, exists := ring.keys[ring.activeID]
	return exists
}
