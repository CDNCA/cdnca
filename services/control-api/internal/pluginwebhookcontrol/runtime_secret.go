package pluginwebhookcontrol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RuntimeSecretProvider struct {
	pool   *pgxpool.Pool
	cipher *secretCipher
}

type runtimeSecretRecord struct {
	Status        string
	Fresh         bool
	Version       uint64
	WrappingKeyID string
	AADSHA256     []byte
	Nonce         []byte
	Ciphertext    []byte
	SecretSHA256  []byte
}

func NewRuntimeSecretProvider(pool *pgxpool.Pool, keys Keyring) (*RuntimeSecretProvider, error) {
	if pool == nil || keys == nil {
		return nil, ErrInvalidConfig
	}
	cipherSuite, err := newSecretCipher(keys, nil)
	if err != nil {
		return nil, err
	}
	return &RuntimeSecretProvider{pool: pool, cipher: cipherSuite}, nil
}

func (provider *RuntimeSecretProvider) Secret(ctx context.Context, targetScopeID, subscriptionID, secretVersionID uuid.UUID) ([]byte, error) {
	if provider == nil || provider.pool == nil || provider.cipher == nil || ctx == nil ||
		targetScopeID == uuid.Nil || subscriptionID == uuid.Nil || secretVersionID == uuid.Nil {
		return nil, ErrSecretUnavailable
	}
	tx, err := provider.pool.Begin(ctx)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	defer tx.Rollback(ctx)
	secret, err := provider.SecretTx(ctx, tx, targetScopeID, subscriptionID, secretVersionID)
	if err != nil {
		clearBytes(secret)
		return nil, ErrSecretUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		clearBytes(secret)
		return nil, ErrSecretUnavailable
	}
	return secret, nil
}

func (provider *RuntimeSecretProvider) SecretTx(ctx context.Context, tx pgx.Tx, targetScopeID, subscriptionID, secretVersionID uuid.UUID) ([]byte, error) {
	if provider == nil || provider.cipher == nil || ctx == nil || tx == nil ||
		targetScopeID == uuid.Nil || subscriptionID == uuid.Nil || secretVersionID == uuid.Nil {
		return nil, ErrSecretUnavailable
	}
	var subscriptionStatus string
	var activeSecretID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT status,active_secret_version_id FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND id=$2 FOR SHARE`, targetScopeID, subscriptionID).Scan(&subscriptionStatus, &activeSecretID); err != nil || subscriptionStatus != "active" || activeSecretID != secretVersionID {
		return nil, ErrSecretUnavailable
	}

	var record runtimeSecretRecord
	var versionText string
	err := tx.QueryRow(ctx, `SELECT status,(expires_at IS NULL OR clock_timestamp()<expires_at),version::text,wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256 FROM plugin_webhook_secret_versions WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 FOR SHARE`, targetScopeID, subscriptionID, secretVersionID).Scan(
		&record.Status, &record.Fresh, &versionText, &record.WrappingKeyID, &record.AADSHA256,
		&record.Nonce, &record.Ciphertext, &record.SecretSHA256,
	)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	record.Version, err = parseU64(versionText)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	secret, err := provider.decryptRecord(ctx, targetScopeID, subscriptionID, secretVersionID, record)
	if err != nil {
		clearBytes(secret)
		return nil, ErrSecretUnavailable
	}
	return secret, nil
}

func (provider *RuntimeSecretProvider) decryptRecord(ctx context.Context, targetScopeID, subscriptionID, secretVersionID uuid.UUID, record runtimeSecretRecord) ([]byte, error) {
	if provider == nil || provider.cipher == nil || ctx == nil || targetScopeID == uuid.Nil ||
		subscriptionID == uuid.Nil || secretVersionID == uuid.Nil || record.Status != "active" ||
		!record.Fresh || record.Version == 0 || record.WrappingKeyID == "" || len(record.AADSHA256) != sha256.Size ||
		len(record.Nonce) != 12 || len(record.Ciphertext) != 48 || len(record.SecretSHA256) != sha256.Size {
		return nil, ErrSecretUnavailable
	}
	expectedAAD := sha256.Sum256(secretAAD(targetScopeID, subscriptionID, secretVersionID, record.Version, record.WrappingKeyID))
	if subtle.ConstantTimeCompare(expectedAAD[:], record.AADSHA256) != 1 {
		return nil, ErrSecretUnavailable
	}
	decrypted, err := provider.cipher.decryptSecret(ctx, encryptedSecret{
		WrappingKeyID: record.WrappingKeyID,
		AADSHA256:     record.AADSHA256,
		Nonce:         record.Nonce,
		Ciphertext:    record.Ciphertext,
		SecretSHA256:  record.SecretSHA256,
	}, targetScopeID, subscriptionID, secretVersionID, record.Version)
	if err != nil {
		decrypted.clear()
		return nil, ErrSecretUnavailable
	}
	defer decrypted.clear()
	digest := sha256.Sum256(decrypted.value[:])
	if subtle.ConstantTimeCompare(digest[:], record.SecretSHA256) != 1 {
		return nil, ErrSecretUnavailable
	}
	return decrypted.bytes(), nil
}
