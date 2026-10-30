package mfacipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"
)

const (
	Version = 1

	algorithmAES256GCM = 1
	fixedHeaderSize    = 8
	maxKeyIDSize       = 128
	envelopeDomain     = "cdnca.control-api.mfa.secret-envelope"
	envelopeMagic      = "MFAE"
)

var (
	ErrInvalidConfig   = errors.New("invalid MFA cipher configuration")
	ErrUnavailable     = errors.New("MFA cipher unavailable")
	ErrInvalidEnvelope = errors.New("invalid MFA cipher envelope")
)

// Key identifies one AES-256-GCM key-encryption key.
type Key struct {
	ID       string
	Material []byte
}

// Cipher encrypts with the active key and decrypts with the active or previous keys.
type Cipher struct {
	mu       sync.RWMutex
	activeID string
	keys     map[string][]byte
	closed   bool
}

// New copies active and previous key material into a new cipher.
func New(active Key, previous ...Key) (*Cipher, error) {
	all := make([]Key, 0, 1+len(previous))
	all = append(all, active)
	all = append(all, previous...)

	seen := make(map[string]struct{}, len(all))
	for _, key := range all {
		if !validKeyID(key.ID) || len(key.Material) != 32 {
			return nil, ErrInvalidConfig
		}
		if _, exists := seen[key.ID]; exists {
			return nil, ErrInvalidConfig
		}
		seen[key.ID] = struct{}{}
	}

	keys := make(map[string][]byte, len(all))
	for _, key := range all {
		keys[key.ID] = append([]byte(nil), key.Material...)
	}
	return &Cipher{activeID: active.ID, keys: keys}, nil
}

// Encrypt returns the active key ID and a versioned AES-256-GCM envelope.
func (c *Cipher) Encrypt(plaintext []byte) (string, []byte, error) {
	if c == nil {
		return "", nil, ErrUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return "", nil, ErrUnavailable
	}

	key := c.keys[c.activeID]
	aead, err := newGCM(key)
	if err != nil {
		return "", nil, ErrUnavailable
	}
	header := makeHeader(c.activeID)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, ErrUnavailable
	}

	envelope := make([]byte, 0, len(header)+len(nonce)+len(plaintext)+aead.Overhead())
	envelope = append(envelope, header...)
	envelope = append(envelope, nonce...)
	envelope = aead.Seal(envelope, nonce, plaintext, associatedData(header))
	return c.activeID, envelope, nil
}

// Decrypt authenticates the envelope context before returning plaintext.
func (c *Cipher) Decrypt(keyID string, envelope []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrUnavailable
	}
	headerSize, embeddedKeyID, ok := parseHeader(envelope)
	if !ok || subtle.ConstantTimeCompare([]byte(keyID), embeddedKeyID) != 1 {
		return nil, ErrInvalidEnvelope
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, ErrUnavailable
	}
	key, exists := c.keys[keyID]
	if !exists {
		return nil, ErrInvalidEnvelope
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(envelope) < headerSize+aead.NonceSize()+aead.Overhead() {
		return nil, ErrInvalidEnvelope
	}

	nonce := envelope[headerSize : headerSize+aead.NonceSize()]
	sealed := envelope[headerSize+aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, associatedData(envelope[:headerSize]))
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	return plaintext, nil
}

// Close zeroes retained key material. It is safe to call more than once.
func (c *Cipher) Close() error {
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
	c.keys = nil
	c.activeID = ""
	c.closed = true
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func makeHeader(keyID string) []byte {
	header := make([]byte, fixedHeaderSize+len(keyID))
	copy(header, envelopeMagic)
	header[4] = Version
	header[5] = algorithmAES256GCM
	binary.BigEndian.PutUint16(header[6:8], uint16(len(keyID)))
	copy(header[fixedHeaderSize:], keyID)
	return header
}

func parseHeader(envelope []byte) (int, []byte, bool) {
	if len(envelope) < fixedHeaderSize ||
		subtle.ConstantTimeCompare(envelope[:4], []byte(envelopeMagic)) != 1 ||
		envelope[4] != Version || envelope[5] != algorithmAES256GCM {
		return 0, nil, false
	}
	keyIDSize := int(binary.BigEndian.Uint16(envelope[6:8]))
	headerSize := fixedHeaderSize + keyIDSize
	if keyIDSize == 0 || headerSize > len(envelope) {
		return 0, nil, false
	}
	return headerSize, envelope[fixedHeaderSize:headerSize], true
}

func validKeyID(value string) bool {
	if len(value) == 0 || len(value) > maxKeyIDSize {
		return false
	}
	for index, current := range []byte(value) {
		alphanumeric := (current >= 'A' && current <= 'Z') || (current >= 'a' && current <= 'z') ||
			(current >= '0' && current <= '9')
		if alphanumeric || (index > 0 && (current == '.' || current == '_' || current == ':' ||
			current == '/' || current == '-')) {
			continue
		}
		return false
	}
	return true
}

func associatedData(header []byte) []byte {
	aad := make([]byte, 0, len(envelopeDomain)+len(header))
	aad = append(aad, envelopeDomain...)
	return append(aad, header...)
}
