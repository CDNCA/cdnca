package pluginwebhookcontrol

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strconv"

	"github.com/google/uuid"
)

type WrappingKey struct {
	ID  string
	Key [32]byte
}

type Keyring interface {
	Active(context.Context) (WrappingKey, error)
	Lookup(context.Context, string) ([32]byte, error)
}

type secretCipher struct {
	keys Keyring
	fill func([]byte) error
}

type encryptedSecret struct {
	WrappingKeyID string
	AADSHA256     []byte
	Nonce         []byte
	Ciphertext    []byte
	SecretSHA256  []byte
}

type encryptedReceipt struct {
	WrappingKeyID string
	AADSHA256     []byte
	Nonce         []byte
	Ciphertext    []byte
}

type secretValue struct{ value [32]byte }

func (secret *secretValue) bytes() []byte {
	result := make([]byte, len(secret.value))
	copy(result, secret.value[:])
	return result
}

func (secret *secretValue) clear() {
	if secret == nil {
		return
	}
	for index := range secret.value {
		secret.value[index] = 0
	}
}

func (secret secretValue) encoded() string {
	return base64.RawURLEncoding.EncodeToString(secret.value[:])
}

func newSecretCipher(keys Keyring, fill func([]byte) error) (*secretCipher, error) {
	if keys == nil {
		return nil, ErrInvalidConfig
	}
	if fill == nil {
		fill = func(target []byte) error { _, err := io.ReadFull(rand.Reader, target); return err }
	}
	return &secretCipher{keys: keys, fill: fill}, nil
}

func (cipherSuite *secretCipher) encryptSecret(ctx context.Context, target, subscription, secretID uuid.UUID, version uint64) (encryptedSecret, secretValue, error) {
	var plaintext secretValue
	if cipherSuite == nil || target == uuid.Nil || subscription == uuid.Nil || secretID == uuid.Nil || version == 0 {
		return encryptedSecret{}, plaintext, ErrInvalidInput
	}
	key, err := cipherSuite.keys.Active(ctx)
	if err != nil || key.ID == "" || key.Key == ([32]byte{}) {
		return encryptedSecret{}, plaintext, ErrSecretUnavailable
	}
	if err := cipherSuite.fill(plaintext.value[:]); err != nil {
		plaintext.clear()
		return encryptedSecret{}, plaintext, ErrSecretUnavailable
	}
	aad := secretAAD(target, subscription, secretID, version, key.ID)
	record, err := cipherSuite.seal(key, plaintext.value[:], aad)
	if err != nil {
		plaintext.clear()
		return encryptedSecret{}, plaintext, err
	}
	digest := sha256.Sum256(plaintext.value[:])
	record.SecretSHA256 = append([]byte(nil), digest[:]...)
	return record, plaintext, nil
}

func (cipherSuite *secretCipher) decryptSecret(ctx context.Context, record encryptedSecret, target, subscription, secretID uuid.UUID, version uint64) (secretValue, error) {
	var result secretValue
	key, err := cipherSuite.keys.Lookup(ctx, record.WrappingKeyID)
	if err != nil || key == ([32]byte{}) {
		return result, ErrSecretUnavailable
	}
	aad := secretAAD(target, subscription, secretID, version, record.WrappingKeyID)
	plaintext, err := openAESGCM(key, record.Nonce, record.Ciphertext, aad)
	if err != nil || len(plaintext) != len(result.value) {
		clearBytes(plaintext)
		return result, ErrSecretUnavailable
	}
	copy(result.value[:], plaintext)
	clearBytes(plaintext)
	return result, nil
}

func (cipherSuite *secretCipher) seal(key WrappingKey, plaintext, aad []byte) (encryptedSecret, error) {
	block, err := aes.NewCipher(key.Key[:])
	if err != nil {
		return encryptedSecret{}, ErrSecretUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return encryptedSecret{}, ErrSecretUnavailable
	}
	nonce := make([]byte, gcm.NonceSize())
	if err := cipherSuite.fill(nonce); err != nil {
		return encryptedSecret{}, ErrSecretUnavailable
	}
	digest := sha256.Sum256(aad)
	return encryptedSecret{WrappingKeyID: key.ID, AADSHA256: append([]byte(nil), digest[:]...), Nonce: nonce, Ciphertext: gcm.Seal(nil, nonce, plaintext, aad)}, nil
}

func (cipherSuite *secretCipher) encryptReceipt(ctx context.Context, plaintext []byte, target, actorScope, actorUser uuid.UUID, idempotencyKey, operation string, resource uuid.UUID) (encryptedReceipt, error) {
	key, err := cipherSuite.keys.Active(ctx)
	if err != nil || key.ID == "" || key.Key == ([32]byte{}) {
		return encryptedReceipt{}, ErrSecretUnavailable
	}
	aad := receiptAAD(target, actorScope, actorUser, idempotencyKey, operation, resource)
	record, err := cipherSuite.seal(key, plaintext, aad)
	if err != nil {
		return encryptedReceipt{}, err
	}
	return encryptedReceipt{WrappingKeyID: record.WrappingKeyID, AADSHA256: record.AADSHA256, Nonce: record.Nonce, Ciphertext: record.Ciphertext}, nil
}

func (cipherSuite *secretCipher) decryptReceipt(ctx context.Context, record encryptedReceipt, target, actorScope, actorUser uuid.UUID, idempotencyKey, operation string, resource uuid.UUID) ([]byte, error) {
	key, err := cipherSuite.keys.Lookup(ctx, record.WrappingKeyID)
	if err != nil || key == ([32]byte{}) {
		return nil, ErrSecretUnavailable
	}
	aad := receiptAAD(target, actorScope, actorUser, idempotencyKey, operation, resource)
	plaintext, err := openAESGCM(key, record.Nonce, record.Ciphertext, aad)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	return plaintext, nil
}

func openAESGCM(key [32]byte, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrSecretUnavailable
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func secretAAD(target, subscription, secretID uuid.UUID, version uint64, keyID string) []byte {
	return joinAAD("cdnca.plugin-webhook.secret/v1", target.String(), subscription.String(), secretID.String(), strconv.FormatUint(version, 10), keyID)
}

func receiptAAD(target, actorScope, actorUser uuid.UUID, key, operation string, resource uuid.UUID) []byte {
	return joinAAD("cdnca.plugin-webhook.receipt/v1", target.String(), actorScope.String(), actorUser.String(), key, operation, resource.String())
}

func joinAAD(parts ...string) []byte {
	length := len(parts) - 1
	for _, part := range parts {
		length += len(part)
	}
	result := make([]byte, 0, length)
	for index, part := range parts {
		if index > 0 {
			result = append(result, 0)
		}
		result = append(result, part...)
	}
	return result
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
