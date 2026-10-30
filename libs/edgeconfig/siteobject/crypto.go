package siteobject

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Every fetched object (scope, bucket, site, file) is sealed once with a key
// derived from the scope's content key and the object's plaintext digest:
//
//	key   = HKDF-SHA256(ikm=content_key, salt=nil,
//	                    info="cdnca-edge-site-object-v1\x00" || scope_id || "\x00" || hex(sha256))
//	wire  = AES-256-GCM(key, nonce=12 zero bytes, plaintext,
//	                    aad="cdnca-edge-site-object-aad-v1\x00" || scope_id || "\x00" || hex(sha256))
//
// Each key seals exactly one plaintext, so the fixed nonce is never reused
// under one key, and an unchanged object keeps its ciphertext across
// publications (it is stored and transferred once). Nodes receive the
// content key in their HPKE key artifact (KeyDocument).

const (
	ContentKeySize = 32

	objectKeyInfo = "cdnca-edge-site-object-v1\x00"
	objectAAD     = "cdnca-edge-site-object-aad-v1\x00"
)

func objectAEAD(contentKey []byte, scopeID, digest string) (cipher.AEAD, []byte, error) {
	if len(contentKey) != ContentKeySize || !uuidPattern.MatchString(scopeID) || !digestPattern.MatchString(digest) {
		return nil, nil, fmt.Errorf("%w: object key input", ErrInvalid)
	}
	context := scopeID + "\x00" + digest
	key, err := hkdf.Key(sha256.New, contentKey, nil, objectKeyInfo+context, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: derive object key", ErrInvalid)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: object cipher", ErrInvalid)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: object cipher", ErrInvalid)
	}
	return aead, []byte(objectAAD + context), nil
}

// Seal returns the object's digest and wire bytes.
func Seal(contentKey []byte, scopeID string, plaintext []byte) (string, []byte, error) {
	if len(plaintext) > MaxObjectBytes {
		return "", nil, fmt.Errorf("%w: object size", ErrInvalid)
	}
	digest := Digest(plaintext)
	aead, aad, err := objectAEAD(contentKey, scopeID, digest)
	if err != nil {
		return "", nil, err
	}
	return digest, aead.Seal(nil, make([]byte, aead.NonceSize()), plaintext, aad), nil
}

// Open decrypts an object fetched by digest and checks the digest.
func Open(contentKey []byte, scopeID, digest string, wire []byte) ([]byte, error) {
	aead, aad, err := objectAEAD(contentKey, scopeID, digest)
	if err != nil {
		return nil, err
	}
	if len(wire) < aead.Overhead() || len(wire) > MaxObjectBytes+aead.Overhead() {
		return nil, fmt.Errorf("%w: object wire size", ErrInvalid)
	}
	plaintext, err := aead.Open(nil, make([]byte, aead.NonceSize()), wire, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: object does not open", ErrInvalid)
	}
	sum := sha256.Sum256(plaintext)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("%w: object digest", ErrInvalid)
	}
	return plaintext, nil
}
