package dnsacme

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

const (
	credentialEnvelopeMagic   = "DCEN"
	credentialEnvelopeVersion = byte(1)
	credentialBoundVersion    = byte(2)
	credentialDEKSize         = 32
	credentialEnvelopeDomain  = "cdnca-dns-credential-envelope/v1"
	credentialBoundDomain     = "cdnca-dns-credential-envelope/v2"
	credentialDigestKeyDomain = "cdnca-dns-credential-digest-key/v1"
	maxPreviousCredentialKeys = 1
	maxCredentialKeyIDLength  = 255
)

type CredentialCipher interface {
	Encrypt([]byte) (keyID string, ciphertext []byte, err error)
	Decrypt(keyID string, ciphertext []byte) ([]byte, error)
	IdempotencyDigest([]byte) [32]byte
}

type CredentialBinding struct {
	TenantID   uuid.UUID
	ScopeID    uuid.UUID
	ProviderID uuid.UUID
}

// BoundCredentialCipher is mandatory for DNS provider credential paths. The
// unbound methods remain available for unrelated legacy secret consumers.
type BoundCredentialCipher interface {
	CredentialCipher
	EncryptCredential(CredentialBinding, []byte) (keyID string, ciphertext []byte, err error)
	DecryptCredential(CredentialBinding, string, []byte) ([]byte, error)
	RewrapCredential(CredentialBinding, string, []byte) (keyID string, ciphertext []byte, err error)
}

// CredentialKey is a KEK that can decrypt an envelope. The active key is used
// for new envelopes; keys supplied as previous are verification-only.
type CredentialKey struct {
	ID       string
	Material []byte
}

type AESGCMCredentialCipher struct {
	mu     sync.RWMutex
	keyID  string
	keys   map[string][]byte
	macKey []byte
	closed bool
}

func NewAESGCMCredentialCipher(keyID string, key []byte, previous ...CredentialKey) (*AESGCMCredentialCipher, error) {
	if !validCredentialKeyID(keyID) || len(key) != 32 || len(previous) > maxPreviousCredentialKeys {
		return nil, ErrCredentialUnavailable
	}
	keys := make(map[string][]byte, len(previous)+1)
	keys[keyID] = append([]byte(nil), key...)
	for _, candidate := range previous {
		if !validCredentialKeyID(candidate.ID) || len(candidate.Material) != 32 {
			return nil, ErrCredentialUnavailable
		}
		if _, exists := keys[candidate.ID]; exists {
			return nil, ErrCredentialUnavailable
		}
		keys[candidate.ID] = append([]byte(nil), candidate.Material...)
	}
	digestRoot := key
	if len(previous) > 0 {
		// Rotation callers pass the complete verify-only chain newest-to-oldest.
		// Keeping the oldest root retains idempotency identity across KEK rotation.
		digestRoot = previous[len(previous)-1].Material
	}
	return &AESGCMCredentialCipher{
		keyID: keyID, keys: keys, macKey: deriveCredentialDigestKey(digestRoot),
	}, nil
}

// NewAESGCMCredentialKeyring is the explicit rotation constructor. The first
// key is active and subsequent keys are verify-only.
func NewAESGCMCredentialKeyring(active CredentialKey, previous ...CredentialKey) (*AESGCMCredentialCipher, error) {
	return NewAESGCMCredentialCipher(active.ID, active.Material, previous...)
}

func (c *AESGCMCredentialCipher) IdempotencyDigest(plaintext []byte) [32]byte {
	if c == nil {
		return [32]byte{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || len(c.macKey) == 0 {
		return [32]byte{}
	}
	mac := hmac.New(sha256.New, c.macKey)
	_, _ = mac.Write([]byte("cdnca-dns-credential-idempotency/v1\x00"))
	_, _ = mac.Write(plaintext)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func (c *AESGCMCredentialCipher) Encrypt(plaintext []byte) (string, []byte, error) {
	if c == nil {
		return "", nil, ErrCredentialUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return "", nil, ErrCredentialUnavailable
	}
	kek, err := credentialAEAD(c.keys[c.keyID])
	if err != nil {
		return "", nil, ErrCredentialUnavailable
	}
	dek := make([]byte, credentialDEKSize)
	if _, err := rand.Read(dek); err != nil {
		clear(dek)
		return "", nil, fmt.Errorf("generate credential key: %w", err)
	}
	defer clear(dek)
	payload, err := credentialAEAD(dek)
	if err != nil {
		return "", nil, ErrCredentialUnavailable
	}
	wrapNonce := make([]byte, kek.NonceSize())
	payloadNonce := make([]byte, payload.NonceSize())
	if _, err := rand.Read(wrapNonce); err != nil {
		return "", nil, fmt.Errorf("generate credential nonce: %w", err)
	}
	if _, err := rand.Read(payloadNonce); err != nil {
		return "", nil, fmt.Errorf("generate credential nonce: %w", err)
	}
	header := credentialEnvelopeHeader()
	wrappedDEK := kek.Seal(nil, wrapNonce, dek, credentialEnvelopeAAD(c.keyID, "wrap", header))
	sealed := payload.Seal(nil, payloadNonce, plaintext, credentialEnvelopeAAD(c.keyID, "payload", header))
	envelope := make([]byte, 0, len(header)+len(wrapNonce)+len(wrappedDEK)+len(payloadNonce)+len(sealed))
	envelope = append(envelope, header...)
	envelope = append(envelope, wrapNonce...)
	envelope = append(envelope, wrappedDEK...)
	envelope = append(envelope, payloadNonce...)
	envelope = append(envelope, sealed...)
	return c.keyID, envelope, nil
}

func (c *AESGCMCredentialCipher) EncryptCredential(binding CredentialBinding, plaintext []byte) (string, []byte, error) {
	if c == nil || !validCredentialBinding(binding) {
		return "", nil, ErrCredentialUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return "", nil, ErrCredentialUnavailable
	}
	kek, err := credentialAEAD(c.keys[c.keyID])
	if err != nil {
		return "", nil, ErrCredentialUnavailable
	}
	dek := make([]byte, credentialDEKSize)
	if _, err := rand.Read(dek); err != nil {
		clear(dek)
		return "", nil, fmt.Errorf("generate credential key: %w", err)
	}
	defer clear(dek)
	payload, err := credentialAEAD(dek)
	if err != nil {
		return "", nil, ErrCredentialUnavailable
	}
	wrapNonce := make([]byte, kek.NonceSize())
	payloadNonce := make([]byte, payload.NonceSize())
	if _, err := rand.Read(wrapNonce); err != nil {
		return "", nil, fmt.Errorf("generate credential nonce: %w", err)
	}
	if _, err := rand.Read(payloadNonce); err != nil {
		return "", nil, fmt.Errorf("generate credential nonce: %w", err)
	}
	header := credentialBoundEnvelopeHeader(c.keyID)
	wrappedDEK := kek.Seal(nil, wrapNonce, dek, credentialBoundEnvelopeAAD(c.keyID, "wrap", header, binding))
	sealed := payload.Seal(nil, payloadNonce, plaintext, credentialBoundEnvelopeAAD(c.keyID, "payload", header, binding))
	envelope := make([]byte, 0, len(header)+len(wrapNonce)+len(wrappedDEK)+len(payloadNonce)+len(sealed))
	envelope = append(envelope, header...)
	envelope = append(envelope, wrapNonce...)
	envelope = append(envelope, wrappedDEK...)
	envelope = append(envelope, payloadNonce...)
	envelope = append(envelope, sealed...)
	return c.keyID, envelope, nil
}

func (c *AESGCMCredentialCipher) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrCredentialUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, ErrCredentialUnavailable
	}
	key, ok := c.keys[keyID]
	if !ok {
		return nil, ErrCredentialUnavailable
	}
	kek, err := credentialAEAD(key)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	header := credentialEnvelopeHeader()
	if len(ciphertext) >= len(credentialEnvelopeMagic) &&
		bytes.Equal(ciphertext[:len(credentialEnvelopeMagic)], []byte(credentialEnvelopeMagic)) {
		if len(ciphertext) < len(header) || !bytes.Equal(ciphertext[:len(header)], header) {
			return nil, ErrCredentialUnavailable
		}
		wrapNonceStart := len(header)
		wrappedDEKStart := wrapNonceStart + kek.NonceSize()
		wrappedDEKEnd := wrappedDEKStart + credentialDEKSize + kek.Overhead()
		payloadNonceEnd := wrappedDEKEnd + kek.NonceSize()
		if len(ciphertext) <= payloadNonceEnd+kek.Overhead() {
			return nil, ErrCredentialUnavailable
		}
		dek, err := kek.Open(nil, ciphertext[wrapNonceStart:wrappedDEKStart],
			ciphertext[wrappedDEKStart:wrappedDEKEnd], credentialEnvelopeAAD(keyID, "wrap", header))
		if err != nil || len(dek) != credentialDEKSize {
			clear(dek)
			return nil, ErrCredentialUnavailable
		}
		defer clear(dek)
		payload, err := credentialAEAD(dek)
		if err != nil {
			return nil, ErrCredentialUnavailable
		}
		plaintext, err := payload.Open(nil, ciphertext[wrappedDEKEnd:payloadNonceEnd],
			ciphertext[payloadNonceEnd:], credentialEnvelopeAAD(keyID, "payload", header))
		if err != nil {
			return nil, ErrCredentialUnavailable
		}
		return plaintext, nil
	}
	if len(ciphertext) <= kek.NonceSize() {
		return nil, ErrCredentialUnavailable
	}
	plaintext, err := kek.Open(nil, ciphertext[:kek.NonceSize()], ciphertext[kek.NonceSize():], []byte(keyID))
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	return plaintext, nil
}

func (c *AESGCMCredentialCipher) DecryptCredential(
	binding CredentialBinding,
	keyID string,
	ciphertext []byte,
) ([]byte, error) {
	if c == nil || !validCredentialBinding(binding) {
		return nil, ErrCredentialUnavailable
	}
	header, embeddedKeyID, ok := parseCredentialBoundEnvelopeHeader(ciphertext)
	if !ok || embeddedKeyID != keyID {
		return nil, ErrCredentialUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, ErrCredentialUnavailable
	}
	key, ok := c.keys[keyID]
	if !ok {
		return nil, ErrCredentialUnavailable
	}
	kek, err := credentialAEAD(key)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	wrapNonceStart := len(header)
	wrappedDEKStart := wrapNonceStart + kek.NonceSize()
	wrappedDEKEnd := wrappedDEKStart + credentialDEKSize + kek.Overhead()
	payloadNonceEnd := wrappedDEKEnd + kek.NonceSize()
	if len(ciphertext) <= payloadNonceEnd+kek.Overhead() {
		return nil, ErrCredentialUnavailable
	}
	dek, err := kek.Open(nil, ciphertext[wrapNonceStart:wrappedDEKStart],
		ciphertext[wrappedDEKStart:wrappedDEKEnd], credentialBoundEnvelopeAAD(keyID, "wrap", header, binding))
	if err != nil || len(dek) != credentialDEKSize {
		clear(dek)
		return nil, ErrCredentialUnavailable
	}
	defer clear(dek)
	payload, err := credentialAEAD(dek)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	plaintext, err := payload.Open(nil, ciphertext[wrappedDEKEnd:payloadNonceEnd],
		ciphertext[payloadNonceEnd:], credentialBoundEnvelopeAAD(keyID, "payload", header, binding))
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	return plaintext, nil
}

// RewrapCredential is the only path that accepts an unbound v1 envelope for a
// DNS provider. Callers must persist its returned active-key v2 envelope using
// their existing revision and audit transaction.
func (c *AESGCMCredentialCipher) RewrapCredential(
	binding CredentialBinding,
	keyID string,
	ciphertext []byte,
) (string, []byte, error) {
	if !validCredentialBinding(binding) {
		return "", nil, ErrCredentialUnavailable
	}
	var (
		plaintext []byte
		err       error
	)
	if len(ciphertext) > len(credentialEnvelopeMagic) && ciphertext[len(credentialEnvelopeMagic)] == credentialBoundVersion {
		plaintext, err = c.DecryptCredential(binding, keyID, ciphertext)
	} else {
		plaintext, err = c.Decrypt(keyID, ciphertext)
	}
	if err != nil {
		clear(plaintext)
		return "", nil, ErrCredentialUnavailable
	}
	defer clear(plaintext)
	return c.EncryptCredential(binding, plaintext)
}

func deriveCredentialDigestKey(root []byte) []byte {
	mac := hmac.New(sha256.New, root)
	_, _ = mac.Write([]byte(credentialDigestKeyDomain))
	return mac.Sum(nil)
}

func credentialEnvelopeHeader() []byte {
	return []byte{credentialEnvelopeMagic[0], credentialEnvelopeMagic[1], credentialEnvelopeMagic[2],
		credentialEnvelopeMagic[3], credentialEnvelopeVersion}
}

func credentialEnvelopeAAD(keyID, purpose string, header []byte) []byte {
	aad := make([]byte, 0, len(credentialEnvelopeDomain)+len(purpose)+len(keyID)+len(header)+3)
	aad = append(aad, credentialEnvelopeDomain...)
	aad = append(aad, 0)
	aad = append(aad, purpose...)
	aad = append(aad, 0)
	aad = append(aad, keyID...)
	aad = append(aad, 0)
	return append(aad, header...)
}

func credentialBoundEnvelopeHeader(keyID string) []byte {
	header := make([]byte, len(credentialEnvelopeMagic)+1+2+len(keyID))
	copy(header, credentialEnvelopeMagic)
	header[len(credentialEnvelopeMagic)] = credentialBoundVersion
	binary.BigEndian.PutUint16(header[len(credentialEnvelopeMagic)+1:], uint16(len(keyID)))
	copy(header[len(credentialEnvelopeMagic)+3:], keyID)
	return header
}

func parseCredentialBoundEnvelopeHeader(ciphertext []byte) ([]byte, string, bool) {
	prefixLength := len(credentialEnvelopeMagic) + 3
	if len(ciphertext) < prefixLength || !bytes.Equal(ciphertext[:len(credentialEnvelopeMagic)], []byte(credentialEnvelopeMagic)) ||
		ciphertext[len(credentialEnvelopeMagic)] != credentialBoundVersion {
		return nil, "", false
	}
	keyIDLength := int(binary.BigEndian.Uint16(ciphertext[len(credentialEnvelopeMagic)+1 : prefixLength]))
	headerLength := prefixLength + keyIDLength
	if keyIDLength < 1 || keyIDLength > maxCredentialKeyIDLength || len(ciphertext) < headerLength {
		return nil, "", false
	}
	keyID := string(ciphertext[prefixLength:headerLength])
	if !validCredentialKeyID(keyID) {
		return nil, "", false
	}
	return ciphertext[:headerLength], keyID, true
}

func credentialBoundEnvelopeAAD(keyID, purpose string, header []byte, binding CredentialBinding) []byte {
	aad := make([]byte, 0, len(credentialBoundDomain)+len(purpose)+len(keyID)+len(header)+3+3*len(uuid.UUID{}))
	aad = append(aad, credentialBoundDomain...)
	aad = append(aad, 0)
	aad = append(aad, purpose...)
	aad = append(aad, 0)
	aad = append(aad, keyID...)
	aad = append(aad, 0)
	aad = append(aad, binding.TenantID[:]...)
	aad = append(aad, binding.ScopeID[:]...)
	aad = append(aad, binding.ProviderID[:]...)
	return append(aad, header...)
}

func validCredentialBinding(binding CredentialBinding) bool {
	return binding.TenantID != uuid.Nil && binding.ScopeID != uuid.Nil && binding.ProviderID != uuid.Nil
}

func validCredentialKeyID(keyID string) bool {
	return keyID != "" && len(keyID) <= maxCredentialKeyIDLength
}

// Close releases retained key material. It is safe to call repeatedly.
func (c *AESGCMCredentialCipher) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	for id, key := range c.keys {
		clear(key)
		delete(c.keys, id)
	}
	clear(c.macKey)
	c.keyID = ""
	c.closed = true
	return nil
}

func credentialAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrCredentialUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	return cipher.NewGCM(block)
}
