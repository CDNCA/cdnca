package acmehttp01

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"slices"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeedge"
)

type Cipher struct {
	keyID  string
	aead   cipher.AEAD
	random io.Reader
}

func NewCipher(keyID string, key []byte) (*Cipher, error) {
	if keyID == "" || len(keyID) > 128 || len(key) != 32 {
		return nil, ErrInvalidConfig
	}
	block, err := aes.NewCipher(slices.Clone(key))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &Cipher{keyID: keyID, aead: aead, random: rand.Reader}, nil
}

func (c *Cipher) Seal(ctx context.Context, request acmeedge.SealRequest) (acmeedge.SealResult, error) {
	if ctx == nil || ctx.Err() != nil || len(request.AAD) == 0 || len(request.Token) == 0 || len(request.ExactValue) == 0 {
		return acmeedge.SealResult{}, acmeedge.ErrEncryptionFailed
	}
	if len(request.Token) > 65535 || len(request.ExactValue) > 65535 {
		return acmeedge.SealResult{}, acmeedge.ErrEncryptionFailed
	}
	plaintext := make([]byte, 4+len(request.Token)+len(request.ExactValue))
	binary.BigEndian.PutUint16(plaintext[:2], uint16(len(request.Token)))
	binary.BigEndian.PutUint16(plaintext[2:4], uint16(len(request.ExactValue)))
	copy(plaintext[4:], request.Token)
	copy(plaintext[4+len(request.Token):], request.ExactValue)
	defer clear(plaintext)
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		clear(nonce)
		return acmeedge.SealResult{}, acmeedge.ErrEncryptionFailed
	}
	ciphertext := c.aead.Seal(nil, nonce, plaintext, request.AAD)
	return acmeedge.SealResult{KeyID: c.keyID, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (c *Cipher) open(token acmeedge.SealedToken, aad []byte) (plaintextToken, plaintextValue []byte, err error) {
	if token.KeyID != c.keyID || len(token.Nonce) != c.aead.NonceSize() || len(token.Ciphertext) <= c.aead.Overhead() {
		return nil, nil, ErrArtifactIntegrity
	}
	plaintext, err := c.aead.Open(nil, token.Nonce, token.Ciphertext, aad)
	if err != nil {
		return nil, nil, ErrArtifactIntegrity
	}
	if len(plaintext) < 4 {
		clear(plaintext)
		return nil, nil, ErrArtifactIntegrity
	}
	tokenLength := int(binary.BigEndian.Uint16(plaintext[:2]))
	valueLength := int(binary.BigEndian.Uint16(plaintext[2:4]))
	if tokenLength == 0 || valueLength == 0 || 4+tokenLength+valueLength != len(plaintext) {
		clear(plaintext)
		return nil, nil, ErrArtifactIntegrity
	}
	plaintextToken = slices.Clone(plaintext[4 : 4+tokenLength])
	plaintextValue = slices.Clone(plaintext[4+tokenLength:])
	clear(plaintext)
	return plaintextToken, plaintextValue, nil
}

func clearBytes(values ...[]byte) {
	for _, value := range values {
		clear(value)
	}
}
