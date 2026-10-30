package entitlementsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNoLocalKeyset = errors.New("no local signing keyset")

type PostgresKeysetStore struct {
	pool *pgxpool.Pool
}

func NewPostgresKeysetStore(pool *pgxpool.Pool) *PostgresKeysetStore {
	return &PostgresKeysetStore{pool: pool}
}

func (store *PostgresKeysetStore) Restore(ctx context.Context, pins []entitlementguard.VerificationKey,
	now time.Time) (*VerifiedKeyset, string, error) {
	if store == nil || store.pool == nil || len(pins) == 0 || now.IsZero() {
		return nil, "", ErrInvalidConfiguration
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("restore signing keyset: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockKeysetState(ctx, tx); err != nil {
		return nil, "", fmt.Errorf("restore signing keyset: %w", err)
	}
	var etag string
	var payload, digest []byte
	var acceptedAt time.Time
	err = tx.QueryRow(ctx, `SELECT etag,payload,payload_sha256,accepted_at
		FROM entitlement_signing_keyset_lkg WHERE singleton=true FOR UPDATE`).Scan(
		&etag, &payload, &digest, &acceptedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", clearKeysetProjectionAndCommit(ctx, tx, ErrNoLocalKeyset)
	}
	if err != nil {
		return nil, "", fmt.Errorf("restore signing keyset: %w", err)
	}
	expected := sha256.Sum256(payload)
	if !bytes.Equal(digest, expected[:]) || !validKeysetETag(etag, payload) {
		return nil, "", clearKeysetProjectionAndCommit(ctx, tx, ErrInvalidKeyset)
	}
	verified, err := VerifyPublicKeyset(payload, pins, nil, now)
	if err != nil {
		return nil, "", clearKeysetProjectionAndCommit(ctx, tx,
			fmt.Errorf("verify restored signing keyset: %w", err))
	}
	if err := replaceKeysetProjection(ctx, tx, verified, digest, acceptedAt); err != nil {
		return nil, "", fmt.Errorf("restore signing keyset projection: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", fmt.Errorf("commit restored signing keyset: %w", err)
	}
	return verified, etag, nil
}

func (store *PostgresKeysetStore) Accept(ctx context.Context, payload []byte, etag string,
	pins []entitlementguard.VerificationKey, now time.Time) (*VerifiedKeyset, error) {
	if store == nil || store.pool == nil || len(pins) == 0 || now.IsZero() || !validKeysetETag(etag, payload) {
		return nil, ErrInvalidConfiguration
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept signing keyset: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockKeysetState(ctx, tx); err != nil {
		return nil, fmt.Errorf("accept signing keyset: %w", err)
	}
	var previous *VerifiedKeyset
	var storedETag string
	var storedPayload, storedDigest []byte
	var storedAcceptedAt time.Time
	err = tx.QueryRow(ctx, `SELECT etag,payload,payload_sha256,accepted_at
		FROM entitlement_signing_keyset_lkg WHERE singleton=true FOR UPDATE`).Scan(
		&storedETag, &storedPayload, &storedDigest, &storedAcceptedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("accept signing keyset: %w", err)
	}
	if err == nil {
		expected := sha256.Sum256(storedPayload)
		if !bytes.Equal(storedDigest, expected[:]) || !validKeysetETag(storedETag, storedPayload) {
			return nil, fmt.Errorf("accept signing keyset: %w",
				clearKeysetProjectionAndCommit(ctx, tx, ErrInvalidKeyset))
		}
		previous, err = VerifyPublicKeyset(storedPayload, pins, nil, now)
		if err != nil {
			return nil, fmt.Errorf("accept signing keyset: %w",
				clearKeysetProjectionAndCommit(ctx, tx, err))
		}
	}

	var candidate *VerifiedKeyset
	digest := sha256.Sum256(payload)
	acceptedAt := now.UTC()
	if previous != nil && storedETag == etag {
		if !bytes.Equal(storedPayload, payload) {
			return nil, fmt.Errorf("accept signing keyset: %w", ErrInvalidKeyset)
		}
		candidate, err = VerifyPublicKeyset(payload, pins, previous, now)
		acceptedAt = storedAcceptedAt.UTC()
	} else {
		candidate, err = VerifyPublicKeyset(payload, pins, previous, now)
	}
	if err != nil {
		return nil, fmt.Errorf("accept signing keyset: %w", err)
	}
	if previous == nil || storedETag != etag {
		_, err = tx.Exec(ctx, `INSERT INTO entitlement_signing_keyset_lkg(
			singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at)
			VALUES(true,$1,$2,$3,$4,$5,$6,$7,$7)
			ON CONFLICT(singleton) DO UPDATE SET schema_version=EXCLUDED.schema_version,etag=EXCLUDED.etag,
			active_key_id=EXCLUDED.active_key_id,chain_depth=EXCLUDED.chain_depth,payload=EXCLUDED.payload,
			payload_sha256=EXCLUDED.payload_sha256,accepted_at=EXCLUDED.accepted_at,updated_at=EXCLUDED.updated_at`,
			candidate.Schema, etag, candidate.ActiveKeyID, len(candidate.Chain), payload, digest[:], acceptedAt)
		if err != nil {
			return nil, fmt.Errorf("accept signing keyset: %w", err)
		}
	}
	if err := replaceKeysetProjection(ctx, tx, candidate, digest[:], acceptedAt); err != nil {
		return nil, fmt.Errorf("accept signing keyset: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("accept signing keyset: %w", err)
	}
	return candidate, nil
}

func lockKeysetState(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `LOCK TABLE entitlement_signing_keyset_lkg IN SHARE ROW EXCLUSIVE MODE`)
	return err
}

func replaceKeysetProjection(ctx context.Context, tx pgx.Tx, verified *VerifiedKeyset, digest []byte,
	acceptedAt time.Time) error {
	if verified == nil || len(verified.KeyStates) == 0 || len(digest) != sha256.Size || acceptedAt.IsZero() {
		return ErrInvalidKeyset
	}
	if _, err := tx.Exec(ctx, `DELETE FROM entitlement_signing_keyset_current_keys`); err != nil {
		return err
	}
	for _, state := range verified.KeyStates {
		if _, err := tx.Exec(ctx, `INSERT INTO entitlement_signing_keyset_current_keys(
			key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, state.Key.KeyID, []byte(state.Key.PublicKey), state.Status,
			state.Key.NotBefore, state.Key.SignUntil, state.Key.VerifyUntil, digest, acceptedAt.UTC()); err != nil {
			return err
		}
	}
	return nil
}

func clearKeysetProjectionAndCommit(ctx context.Context, tx pgx.Tx, cause error) error {
	if _, err := tx.Exec(ctx, `DELETE FROM entitlement_signing_keyset_current_keys`); err != nil {
		return errors.Join(cause, fmt.Errorf("clear signing keyset projection: %w", err))
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(cause, fmt.Errorf("commit cleared signing keyset projection: %w", err))
	}
	return cause
}

type KeysetManager struct {
	mu      sync.Mutex
	client  *Client
	store   *PostgresKeysetStore
	trust   *entitlementguard.TrustStore
	pins    []entitlementguard.VerificationKey
	now     func() time.Time
	current *VerifiedKeyset
	etag    string
}

func NewKeysetManager(ctx context.Context, client *Client, store *PostgresKeysetStore,
	trust *entitlementguard.TrustStore, now func() time.Time) (*KeysetManager, error) {
	if client == nil || store == nil || trust == nil {
		return nil, ErrInvalidConfiguration
	}
	if now == nil {
		now = time.Now
	}
	manager := &KeysetManager{client: client, store: store, trust: trust,
		pins: trust.PinnedKeys(), now: now}
	restored, etag, err := store.Restore(ctx, manager.pins, now().UTC())
	if err != nil && !errors.Is(err, ErrNoLocalKeyset) {
		return nil, err
	}
	if restored != nil {
		if err := trust.ApplyVerifiedKeys(restored.Keys); err != nil {
			return nil, err
		}
		manager.current, manager.etag = restored, etag
	}
	return manager, nil
}

func (manager *KeysetManager) Refresh(ctx context.Context) error {
	if manager == nil {
		return ErrInvalidConfiguration
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	fetched, err := manager.client.fetchKeyset(ctx, manager.etag)
	if err != nil {
		return err
	}
	if fetched.NotModified {
		if manager.current == nil || manager.etag == "" {
			return ErrInvalidConfiguration
		}
		accepted, err := manager.store.Accept(ctx, manager.current.Payload, manager.etag,
			manager.pins, manager.now().UTC())
		if err != nil {
			return err
		}
		if err := manager.trust.ApplyVerifiedKeys(accepted.Keys); err != nil {
			return err
		}
		manager.current = accepted
		return nil
	}
	accepted, err := manager.store.Accept(ctx, fetched.Body, fetched.ETag, manager.pins, manager.now().UTC())
	if err != nil {
		return err
	}
	if err := manager.trust.ApplyVerifiedKeys(accepted.Keys); err != nil {
		return err
	}
	manager.current, manager.etag = accepted, fetched.ETag
	return nil
}
