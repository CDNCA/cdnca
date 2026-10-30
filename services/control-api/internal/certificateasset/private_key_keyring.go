package certificateasset

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
)

const maximumPrivateKeyWrappingKeys = 4

type PrivateKeyWrappingKey struct {
	ID       string
	Material []byte
}

type AESGCMPrivateKeyEnvelopeKeyring struct {
	activeID string
	aeads    map[string]cipher.AEAD
	random   io.Reader
}

type privateKeyEnvelopeMetadata struct {
	Schema string          `json:"schema"`
	Kind   string          `json:"kind"`
	Source json.RawMessage `json:"source,omitempty"`
}

func NewAESGCMPrivateKeyEnvelopeKeyring(
	active PrivateKeyWrappingKey,
	previous ...PrivateKeyWrappingKey,
) (*AESGCMPrivateKeyEnvelopeKeyring, error) {
	if len(previous)+1 > maximumPrivateKeyWrappingKeys {
		return nil, ErrEnvelopeUnavailable
	}
	aeads := make(map[string]cipher.AEAD, len(previous)+1)
	for _, key := range append([]PrivateKeyWrappingKey{active}, previous...) {
		if !validPrivateKeyWrappingKey(key) {
			return nil, ErrEnvelopeUnavailable
		}
		if _, duplicate := aeads[key.ID]; duplicate {
			return nil, ErrEnvelopeUnavailable
		}
		material := append([]byte(nil), key.Material...)
		block, err := aes.NewCipher(material)
		clear(material)
		if err != nil {
			return nil, ErrEnvelopeUnavailable
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrEnvelopeUnavailable
		}
		aeads[key.ID] = aead
	}
	return &AESGCMPrivateKeyEnvelopeKeyring{
		activeID: active.ID, aeads: aeads, random: rand.Reader,
	}, nil
}

func (keyring *AESGCMPrivateKeyEnvelopeKeyring) Seal(
	ctx context.Context,
	request PrivateKeySealRequest,
) (PrivateKeyEnvelope, error) {
	if ctx == nil {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	return keyring.seal(request.Context, request.PlaintextPKCS8, privateKeyEnvelopeMetadata{
		Schema: "cdnca.acme-certificate-envelope.v1", Kind: "pkcs8",
	})
}

func (keyring *AESGCMPrivateKeyEnvelopeKeyring) SealOpaque(
	ctx context.Context,
	request OpaquePrivateKeySealRequest,
) (PrivateKeyEnvelope, error) {
	if ctx == nil || !json.Valid(request.Metadata) {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	return keyring.seal(request.Context, request.WrappedKeyMaterial, privateKeyEnvelopeMetadata{
		Schema: "cdnca.acme-certificate-envelope.v1", Kind: "opaque_wrapped",
		Source: append(json.RawMessage(nil), request.Metadata...),
	})
}

func (keyring *AESGCMPrivateKeyEnvelopeKeyring) Unseal(
	ctx context.Context,
	request PrivateKeyUnsealRequest,
) ([]byte, error) {
	if ctx == nil || keyring == nil || len(request.Envelope.Metadata) == 0 ||
		len(request.Envelope.Metadata) > 4096 {
		return nil, ErrEnvelopeUnavailable
	}
	metadata, err := decodePrivateKeyEnvelopeMetadata(request.Envelope.Metadata)
	if err != nil {
		return nil, ErrEnvelopeUnavailable
	}
	aead, found := keyring.aeads[request.Envelope.KeyID]
	if !found || aead == nil || len(request.Envelope.Nonce) != aead.NonceSize() ||
		len(request.Envelope.Ciphertext) < aead.Overhead() {
		return nil, ErrEnvelopeUnavailable
	}
	aad, err := privateKeyEnvelopeAAD(request.Context, request.Envelope.KeyID, request.Envelope.Metadata)
	if err != nil {
		return nil, ErrEnvelopeUnavailable
	}
	plaintext, err := aead.Open(nil, request.Envelope.Nonce, request.Envelope.Ciphertext, aad)
	if err != nil {
		// The metadata column is jsonb: it reads back reordered and spaced,
		// not as the bytes seal hashed. Seal wrote json.Marshal of the
		// decoded struct, so that encoding is the sealed one.
		if canonical, marshalErr := json.Marshal(metadata); marshalErr == nil &&
			!bytes.Equal(canonical, request.Envelope.Metadata) {
			if aad, err = privateKeyEnvelopeAAD(request.Context, request.Envelope.KeyID, canonical); err == nil {
				plaintext, err = aead.Open(nil, request.Envelope.Nonce, request.Envelope.Ciphertext, aad)
			}
		}
	}
	if err != nil || len(plaintext) == 0 ||
		(metadata.Kind != "pkcs8" && metadata.Kind != "opaque_wrapped") {
		clear(plaintext)
		return nil, ErrEnvelopeUnavailable
	}
	return plaintext, nil
}

func (keyring *AESGCMPrivateKeyEnvelopeKeyring) Rewrap(
	ctx context.Context,
	request PrivateKeyRewrapRequest,
) (PrivateKeyEnvelope, error) {
	if ctx == nil || keyring == nil || request.TargetKeyID != keyring.activeID {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	metadata, err := decodePrivateKeyEnvelopeMetadata(request.Envelope.Metadata)
	if err != nil {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	plaintext, err := keyring.Unseal(ctx, PrivateKeyUnsealRequest{
		Context: request.Context, Envelope: request.Envelope,
	})
	if err != nil {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	defer clear(plaintext)
	return keyring.seal(request.Context, plaintext, metadata)
}

func (keyring *AESGCMPrivateKeyEnvelopeKeyring) seal(
	contextValue PrivateKeyEnvelopeContext,
	plaintext []byte,
	metadata privateKeyEnvelopeMetadata,
) (PrivateKeyEnvelope, error) {
	if keyring == nil || keyring.random == nil || len(plaintext) == 0 || len(plaintext) > 128*1024 {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	aead := keyring.aeads[keyring.activeID]
	if aead == nil {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	encodedMetadata, err := json.Marshal(metadata)
	if err != nil || len(encodedMetadata) > 4096 {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	aad, err := privateKeyEnvelopeAAD(contextValue, keyring.activeID, encodedMetadata)
	if err != nil {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(keyring.random, nonce); err != nil {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	return PrivateKeyEnvelope{
		KeyID: keyring.activeID, Nonce: nonce, Metadata: encodedMetadata,
		Ciphertext: aead.Seal(nil, nonce, plaintext, aad),
	}, nil
}

func privateKeyEnvelopeAAD(
	contextValue PrivateKeyEnvelopeContext,
	keyID string,
	metadata json.RawMessage,
) ([]byte, error) {
	canonicalContext, err := contextValue.CanonicalAAD()
	if err != nil || !validPrivateKeyWrappingKeyID(keyID) || !json.Valid(metadata) {
		return nil, ErrEnvelopeUnavailable
	}
	metadataDigest := sha256.Sum256(metadata)
	return json.Marshal(struct {
		Schema         string          `json:"schema"`
		KeyID          string          `json:"key_id"`
		Context        json.RawMessage `json:"context"`
		MetadataSHA256 [32]byte        `json:"metadata_sha256"`
	}{
		Schema: "cdnca.acme-certificate-envelope-aad.v1", KeyID: keyID,
		Context: canonicalContext, MetadataSHA256: metadataDigest,
	})
}

func decodePrivateKeyEnvelopeMetadata(value json.RawMessage) (privateKeyEnvelopeMetadata, error) {
	var metadata privateKeyEnvelopeMetadata
	if err := json.Unmarshal(value, &metadata); err != nil ||
		metadata.Schema != "cdnca.acme-certificate-envelope.v1" ||
		(metadata.Kind != "pkcs8" && metadata.Kind != "opaque_wrapped") ||
		(metadata.Kind == "opaque_wrapped" && !json.Valid(metadata.Source)) {
		return privateKeyEnvelopeMetadata{}, ErrEnvelopeUnavailable
	}
	return metadata, nil
}

func validPrivateKeyWrappingKey(key PrivateKeyWrappingKey) bool {
	return validPrivateKeyWrappingKeyID(key.ID) && len(key.Material) == 32
}

func validPrivateKeyWrappingKeyID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func (*AESGCMPrivateKeyEnvelopeKeyring) String() string {
	return "certificateasset.AESGCMPrivateKeyEnvelopeKeyring{redacted}"
}

func (*AESGCMPrivateKeyEnvelopeKeyring) GoString() string {
	return "certificateasset.AESGCMPrivateKeyEnvelopeKeyring{redacted}"
}

func (*AESGCMPrivateKeyEnvelopeKeyring) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("%w: keyring serialization forbidden", ErrEnvelopeUnavailable)
}

var _ PrivateKeyEnveloper = (*AESGCMPrivateKeyEnvelopeKeyring)(nil)
