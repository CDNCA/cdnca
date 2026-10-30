package urlauthpolicy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

const keyDigestDomain = "cdnca-control-url-auth/key-digest/v1\x00"

type BoundSecretCipher interface {
	SecretCipher
	EncryptBound([]byte, []byte) (string, []byte, error)
	DecryptBound(string, []byte, []byte) ([]byte, error)
	SecretDigest([]byte) [32]byte
}

type AESGCMSecretCipher struct {
	keyID  string
	aead   cipher.AEAD
	macKey []byte
}

func NewAESGCMSecretCipher(keyID string, key []byte) (*AESGCMSecretCipher, error) {
	if keyID == "" || len(key) != 32 {
		return nil, ErrEncryptionUnavailable
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, ErrEncryptionUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEncryptionUnavailable
	}
	return &AESGCMSecretCipher{keyID: keyID, aead: aead, macKey: append([]byte(nil), key...)}, nil
}

func (cipher *AESGCMSecretCipher) Encrypt(plaintext []byte) (string, []byte, error) {
	return cipher.EncryptBound(plaintext, nil)
}

func (cipher *AESGCMSecretCipher) EncryptBound(plaintext, associatedData []byte) (string, []byte, error) {
	if cipher == nil || cipher.aead == nil {
		return "", nil, ErrEncryptionUnavailable
	}
	nonce := make([]byte, cipher.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, ErrEncryptionUnavailable
	}
	sealed := cipher.aead.Seal(nil, nonce, plaintext, associatedData)
	return cipher.keyID, append(nonce, sealed...), nil
}

func (cipher *AESGCMSecretCipher) DecryptBound(keyID string, ciphertext, associatedData []byte) ([]byte, error) {
	if cipher == nil || cipher.aead == nil || keyID != cipher.keyID || len(ciphertext) <= cipher.aead.NonceSize() {
		return nil, ErrEncryptionUnavailable
	}
	plaintext, err := cipher.aead.Open(nil, ciphertext[:cipher.aead.NonceSize()], ciphertext[cipher.aead.NonceSize():], associatedData)
	if err != nil {
		return nil, ErrEncryptionUnavailable
	}
	return plaintext, nil
}

func (cipher *AESGCMSecretCipher) IdempotencyDigest(value []byte) [32]byte {
	return cipher.SecretDigest(value)
}

func (cipher *AESGCMSecretCipher) SecretDigest(value []byte) [32]byte {
	if cipher == nil || len(cipher.macKey) == 0 {
		return [32]byte{}
	}
	mac := hmac.New(sha256.New, cipher.macKey)
	_, _ = mac.Write([]byte(keyDigestDomain))
	_, _ = mac.Write(value)
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

var _ BoundSecretCipher = (*AESGCMSecretCipher)(nil)
