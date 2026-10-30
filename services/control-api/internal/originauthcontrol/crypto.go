package originauthcontrol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"regexp"

	"golang.org/x/crypto/hkdf"
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type encryptedSecret struct {
	keyID      string
	ciphertext []byte
}

type Keyring struct {
	activeKeyID string
	keys        map[string][]byte
	random      io.Reader
}

func NewKeyring(activeKeyID string, keys map[string][]byte) (*Keyring, error) {
	return newKeyring(activeKeyID, keys, rand.Reader)
}

func newKeyring(activeKeyID string, keys map[string][]byte, random io.Reader) (*Keyring, error) {
	if !keyIDPattern.MatchString(activeKeyID) || len(keys[activeKeyID]) != 32 || random == nil {
		return nil, ErrEncryptionUnavailable
	}
	copied := make(map[string][]byte, len(keys))
	for keyID, key := range keys {
		if !keyIDPattern.MatchString(keyID) || len(key) != 32 {
			return nil, ErrEncryptionUnavailable
		}
		copied[keyID] = append([]byte(nil), key...)
	}
	return &Keyring{activeKeyID: activeKeyID, keys: copied, random: random}, nil
}

func (keyring *Keyring) configured() bool {
	if keyring == nil || !keyIDPattern.MatchString(keyring.activeKeyID) ||
		len(keyring.keys[keyring.activeKeyID]) != 32 || keyring.random == nil {
		return false
	}
	for keyID, key := range keyring.keys {
		if !keyIDPattern.MatchString(keyID) || len(key) != 32 {
			return false
		}
	}
	return true
}

func (keyring *Keyring) seal(plaintext, associatedData []byte) (encryptedSecret, error) {
	aead, err := keyring.aead(keyring.activeKeyID)
	if err != nil {
		return encryptedSecret{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(keyring.random, nonce); err != nil {
		return encryptedSecret{}, fmt.Errorf("seal origin credential: %w", ErrEncryptionUnavailable)
	}
	aad := envelopeAAD(keyring.activeKeyID, associatedData)
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	clearBytes(aad)
	return encryptedSecret{keyID: keyring.activeKeyID, ciphertext: append(nonce, sealed...)}, nil
}

func (keyring *Keyring) open(keyID string, ciphertext, associatedData []byte) ([]byte, error) {
	aead, err := keyring.aead(keyID)
	if err != nil || len(ciphertext) <= aeadNonceSize(aead) {
		return nil, ErrEncryptionUnavailable
	}
	aad := envelopeAAD(keyID, associatedData)
	plaintext, err := aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], aad)
	clearBytes(aad)
	if err != nil {
		return nil, ErrEncryptionUnavailable
	}
	return plaintext, nil
}

// seed is HMAC-SHA256 of value under a key derived from the active key
// (never the key itself).
func (keyring *Keyring) seed(value []byte) ([32]byte, error) {
	key, found := keyring.keys[keyring.activeKeyID]
	if !found {
		return [32]byte{}, ErrEncryptionUnavailable
	}
	derived := make([]byte, 32)
	defer clearBytes(derived)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, nil, []byte("cdnca.control.originauth.market-seed/v1")), derived); err != nil {
		return [32]byte{}, ErrEncryptionUnavailable
	}
	mac := hmac.New(sha256.New, derived)
	mac.Write(value)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out, nil
}

func (keyring *Keyring) aead(keyID string) (cipher.AEAD, error) {
	key, found := keyring.keys[keyID]
	if !found {
		return nil, ErrEncryptionUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrEncryptionUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEncryptionUnavailable
	}
	return aead, nil
}

func envelopeAAD(keyID string, associatedData []byte) []byte {
	value := make([]byte, 0, len(keyID)+len(associatedData)+40)
	value = append(value, "cdnca.control.originauth.envelope/v1\x00"...)
	value = append(value, keyID...)
	value = append(value, 0)
	return append(value, associatedData...)
}

func aeadNonceSize(aead cipher.AEAD) int {
	if aead == nil {
		return 0
	}
	return aead.NonceSize()
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func clearSecret(secret *CredentialSecret) {
	secret.AccessKeyID = ""
	secret.SecretAccessKey = ""
	secret.SessionToken = ""
}
