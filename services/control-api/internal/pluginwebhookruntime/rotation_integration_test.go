//go:build integration

package pluginwebhookruntime

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

func TestRotateAttestationKeyAdvancesHeadWithOverlapAndAudit(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	current := AttestationKeyPair{ID: "plugin-webhook-attestation-v1",
		Key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))}
	next := AttestationKeyPair{ID: "plugin-webhook-attestation-v2",
		Key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))}
	runtimeWith := func(keys ...AttestationKeyPair) *Runtime {
		config := Config{JetStream: DefaultJetStreamConfig(), AttestationKeyID: keys[0].ID, AttestationKey: keys[0].Key}
		if len(keys) > 1 {
			config.NextAttestationKeyID, config.NextAttestationKey = keys[1].ID, keys[1].Key
		}
		return &Runtime{pool: pool, config: config}
	}

	if _, err := RotateAttestationKey(ctx, pool, current, next, "test"); !errors.Is(err, ErrAttestationHeadMissing) {
		t.Fatalf("rotate before the first head install: %v", err)
	}
	if err := runtimeWith(current).ensureAttestationHead(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateAttestationKey(ctx, pool, current, AttestationKeyPair{}, "test"); !errors.Is(err, ErrAttestationNextMissing) {
		t.Fatalf("rotate without a staged key: %v", err)
	}
	if _, err := RotateAttestationKey(ctx, pool, current, current, "test"); err == nil {
		t.Fatal("rotate to the same key accepted")
	}
	stranger := AttestationKeyPair{ID: "plugin-webhook-attestation-x",
		Key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))}
	if _, err := RotateAttestationKey(ctx, pool, stranger, next, "test"); !errors.Is(err, ErrAttestationHeadUnknown) {
		t.Fatalf("rotate from a key the head does not name: %v", err)
	}

	// Overlap: a runtime holding both keys signs with current before the advance.
	overlap := runtimeWith(current, next)
	lockedKey := func(runtime *Runtime) (ed25519.PrivateKey, uint64, error) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		head, err := runtime.lockAttestationHead(ctx, tx)
		return head.key, head.generation, err
	}
	if key, generation, err := lockedKey(overlap); err != nil || !bytes.Equal(key, current.Key) || generation != 1 {
		t.Fatalf("before rotation: generation=%d err=%v", generation, err)
	}

	rotation, err := RotateAttestationKey(ctx, pool, current, next, "cli:test")
	if err != nil {
		t.Fatal(err)
	}
	if rotation.AlreadyRotated || rotation.FromGeneration != 1 || rotation.ToGeneration != 2 ||
		rotation.FromKeyID != current.ID || rotation.ToKeyID != next.ID {
		t.Fatalf("rotation = %#v", rotation)
	}
	// The same running runtime now signs with next; a runtime with only the old key fails closed.
	if key, generation, err := lockedKey(overlap); err != nil || !bytes.Equal(key, next.Key) || generation != 2 {
		t.Fatalf("after rotation: generation=%d err=%v", generation, err)
	}
	if _, _, err := lockedKey(runtimeWith(current)); !errors.Is(err, errAttestationKey) {
		t.Fatalf("old-key runtime after rotation: %v", err)
	}
	if _, _, err := lockedKey(runtimeWith(next)); err != nil {
		t.Fatalf("runtime restarted with next as current: %v", err)
	}

	var history string
	if err := pool.QueryRow(ctx, `SELECT string_agg(key_generation::text||':'||key_id||':'||status, ',' ORDER BY key_generation)
		FROM plugin_webhook_runtime_attestation_keys`).Scan(&history); err != nil {
		t.Fatal(err)
	}
	if history != "1:plugin-webhook-attestation-v1:retired,2:plugin-webhook-attestation-v2:active" {
		t.Fatalf("key history = %s", history)
	}
	status, err := ReadAttestationHead(ctx, pool, next, AttestationKeyPair{})
	if err != nil || !status.Installed || status.Generation != 2 || status.KeyID != next.ID || status.Matches != "current" {
		t.Fatalf("status = %#v err=%v", status, err)
	}

	var count int
	var actorKind, actorRef, resourceID, result string
	var changes []byte
	if err := pool.QueryRow(ctx, `SELECT count(*) OVER (),actor_kind,actor_ref,resource_id,result,changes
		FROM audit_events WHERE action=$1`, AttestationKeyRotateAction).
		Scan(&count, &actorKind, &actorRef, &resourceID, &result, &changes); err != nil {
		t.Fatal(err)
	}
	var changeList []map[string]any
	if err := json.Unmarshal(changes, &changeList); err != nil {
		t.Fatal(err)
	}
	if count != 1 || actorKind != "system" || actorRef != "cli:test" || resourceID != next.ID || result != "success" ||
		len(changeList) != 2 || changeList[0]["before"] != current.ID || changeList[0]["after"] != next.ID {
		t.Fatalf("audit event: count=%d actor=%s/%s resource=%s result=%s changes=%s",
			count, actorKind, actorRef, resourceID, result, changes)
	}

	again, err := RotateAttestationKey(ctx, pool, current, next, "cli:test")
	if err != nil || !again.AlreadyRotated || again.ToGeneration != 2 {
		t.Fatalf("repeat rotation = %#v err=%v", again, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1`,
		AttestationKeyRotateAction).Scan(&count); err != nil || count != 1 {
		t.Fatalf("repeat rotation audited again: count=%d err=%v", count, err)
	}
}
