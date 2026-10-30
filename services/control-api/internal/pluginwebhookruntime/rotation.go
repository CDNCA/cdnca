package pluginwebhookruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Operator rotation of the publication attestation key (docs/runbooks/
// plugin-webhook-key.md). Migration 084 keeps exactly one active key and only
// lets the head advance to generation+1 after its key is retired, all in one
// transaction. The overlap lives in the runtime instead: it is started with the
// current key and the staged next key and signs with whichever the head names,
// so the head can advance without a restart. Publications already recorded keep
// pointing at the retired generation.

// AttestationKeyRotateAction is the audit action of a rotation.
const AttestationKeyRotateAction = "plugin.webhook_attestation_key.rotate"

var (
	ErrAttestationHeadMissing = errors.New("plugin webhook attestation head is not installed yet; start the runtime once first")
	ErrAttestationNextMissing = errors.New("PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID and _NEXT_PRIVATE_KEY_FILE are required to rotate")
	ErrAttestationHeadUnknown = errors.New("plugin webhook attestation head names neither the configured current nor next key")
)

// AttestationKeyPair is one configured key.
type AttestationKeyPair struct {
	ID  string
	Key ed25519.PrivateKey
}

func (pair AttestationKeyPair) matches(keyID string, publicKey []byte) bool {
	return pair.Key != nil && pair.ID == keyID && bytes.Equal(publicKey, pair.Key.Public().(ed25519.PublicKey))
}

// AttestationHeadStatus is the database head and how it relates to the
// configured keys.
type AttestationHeadStatus struct {
	Installed  bool
	Generation uint64
	KeyID      string
	NotBefore  time.Time
	ExpiresAt  time.Time
	// Matches is "current", "next" or "" (neither configured key).
	Matches string
}

// ReadAttestationHead reports the head without changing anything.
func ReadAttestationHead(ctx context.Context, pool *pgxpool.Pool, current, next AttestationKeyPair) (AttestationHeadStatus, error) {
	var status AttestationHeadStatus
	var generation string
	var publicKey []byte
	err := pool.QueryRow(ctx, `SELECT key_generation::text,key_id,public_key,not_before,expires_at
		FROM plugin_webhook_runtime_attestation_head WHERE singleton=true`).
		Scan(&generation, &status.KeyID, &publicKey, &status.NotBefore, &status.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AttestationHeadStatus{}, nil
	}
	if err != nil {
		return AttestationHeadStatus{}, err
	}
	if status.Generation, err = parseUint(generation); err != nil {
		return AttestationHeadStatus{}, err
	}
	status.Installed = true
	switch {
	case current.matches(status.KeyID, publicKey):
		status.Matches = "current"
	case next.matches(status.KeyID, publicKey):
		status.Matches = "next"
	}
	return status, nil
}

// AttestationRotation is the result of RotateAttestationKey.
type AttestationRotation struct {
	FromGeneration, ToGeneration uint64
	FromKeyID, ToKeyID           string
	ExpiresAt                    time.Time
	// AlreadyRotated: the head already named next; nothing was written.
	AlreadyRotated bool
}

// RotateAttestationKey retires the head key (which must be current), installs
// next as generation+1, advances the head and appends the audit event in the
// same transaction. It needs the schema owner's privileges, like the first
// head install. Running it again after success is a no-op.
func RotateAttestationKey(ctx context.Context, pool *pgxpool.Pool, current, next AttestationKeyPair,
	actorRef string,
) (AttestationRotation, error) {
	if !validAttestationKey(current.ID, current.Key) {
		return AttestationRotation{}, errors.New("current plugin webhook attestation key is invalid")
	}
	if next.ID == "" && next.Key == nil {
		return AttestationRotation{}, ErrAttestationNextMissing
	}
	if !validNextAttestationKey(Config{AttestationKeyID: current.ID, AttestationKey: current.Key,
		NextAttestationKeyID: next.ID, NextAttestationKey: next.Key}) {
		return AttestationRotation{}, errors.New("next plugin webhook attestation key is invalid or equals the current key")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return AttestationRotation{}, err
	}
	defer tx.Rollback(ctx)
	// FOR UPDATE waits for publications holding the head FOR SHARE.
	var generationText, keyID string
	var publicKey []byte
	err = tx.QueryRow(ctx, `SELECT key_generation::text,key_id,public_key
		FROM plugin_webhook_runtime_attestation_head WHERE singleton=true FOR UPDATE`).
		Scan(&generationText, &keyID, &publicKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return AttestationRotation{}, ErrAttestationHeadMissing
	}
	if err != nil {
		return AttestationRotation{}, err
	}
	generation, err := parseUint(generationText)
	if err != nil {
		return AttestationRotation{}, err
	}
	if next.matches(keyID, publicKey) {
		return AttestationRotation{FromGeneration: generation, ToGeneration: generation, FromKeyID: keyID,
			ToKeyID: keyID, AlreadyRotated: true}, nil
	}
	if !current.matches(keyID, publicKey) {
		return AttestationRotation{}, ErrAttestationHeadUnknown
	}
	if _, err := tx.Exec(ctx, `UPDATE plugin_webhook_runtime_attestation_keys SET status='retired'
		WHERE key_generation=$1 AND status='active'`, generationText); err != nil {
		return AttestationRotation{}, fmt.Errorf("retire plugin webhook attestation key: %w", err)
	}
	var notBefore, expiresAt time.Time
	if err := tx.QueryRow(ctx, `SELECT date_trunc('second',clock_timestamp())-interval '1 minute',
		date_trunc('second',clock_timestamp())+$1::interval`, attestationKeyLifetime.String()).
		Scan(&notBefore, &expiresAt); err != nil {
		return AttestationRotation{}, err
	}
	nextPublic := []byte(next.Key.Public().(ed25519.PublicKey))
	if _, err := tx.Exec(ctx, `INSERT INTO plugin_webhook_runtime_attestation_keys(
			key_generation,key_id,public_key,status,not_before,expires_at)
		VALUES($1::numeric+1,$2,$3,'active',$4,$5)`, generationText, next.ID, nextPublic, notBefore, expiresAt); err != nil {
		return AttestationRotation{}, fmt.Errorf("install plugin webhook attestation key: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE plugin_webhook_runtime_attestation_head
		SET key_generation=key_generation+1,key_id=$1,public_key=$2,not_before=$3,expires_at=$4
		WHERE singleton=true`, next.ID, nextPublic, notBefore, expiresAt); err != nil {
		return AttestationRotation{}, fmt.Errorf("advance plugin webhook attestation head: %w", err)
	}
	var platformScope uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).
		Scan(&platformScope); err != nil {
		return AttestationRotation{}, fmt.Errorf("read platform scope for the audit event: %w", err)
	}
	if _, err := audit.AppendTx(ctx, tx, audit.Event{
		ScopeID: platformScope, Action: AttestationKeyRotateAction,
		ResourceType: "plugin_webhook_attestation_key", ResourceID: next.ID, Result: "success",
		RequestID: "plugin-webhook-attestation-key/" + uuid.NewString(),
		ActorKind: audit.ActorSystem, ActorRef: actorRef,
		Payload: map[string]any{"expires_at": expiresAt.UTC().Format(time.RFC3339)},
		Changes: []audit.Change{
			{Field: "key_id", Before: keyID, After: next.ID},
			{Field: "generation", Before: generation, After: generation + 1},
		},
	}); err != nil {
		return AttestationRotation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AttestationRotation{}, err
	}
	return AttestationRotation{FromGeneration: generation, ToGeneration: generation + 1, FromKeyID: keyID,
		ToKeyID: next.ID, ExpiresAt: expiresAt}, nil
}
