//go:build integration

package platformpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPlatformPolicyMigrationRoundTrip(t *testing.T) {
	pool := openPlatformPolicyTestDatabase(t)
	ctx := context.Background()
	applyPlatformPolicyMigration(t, pool, "up")
	assertPlatformPolicyTables(t, pool, true)
	applyPlatformPolicyMigration(t, pool, "down")
	assertPlatformPolicyTables(t, pool, false)
	applyPlatformPolicyMigration(t, pool, "up")
	assertPlatformPolicyTables(t, pool, true)

	installationID := uuid.New()
	_, privateKey := testPolicyKey()
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	signed := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
	store, err := NewPostgresStore(pool, installationID)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(signed)
	if _, err := store.RecordFetched(ctx, wire, signed, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE platform_policy_deliveries SET fetched_at=fetched_at
		WHERE target_revision_id=$1`, signed.Envelope.TargetRevisionID); !isPlatformPolicyImmutableError(err) {
		t.Fatalf("delivery UPDATE error = %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM platform_policy_ack_events
		WHERE target_revision_id=$1`, signed.Envelope.TargetRevisionID); !isPlatformPolicyImmutableError(err) {
		t.Fatalf("ack DELETE error = %v", err)
	}
	for _, table := range []string{
		"platform_policy_deliveries",
		"platform_policy_ack_events",
		"platform_policy_application_events",
	} {
		t.Run("truncate "+table, func(t *testing.T) {
			_, err := pool.Exec(ctx, "TRUNCATE "+pgx.Identifier{table}.Sanitize()+" CASCADE")
			if !isPlatformPolicyImmutableError(err) {
				t.Fatalf("%s TRUNCATE error = %v", table, err)
			}
		})
	}
}

func TestPostgresStoreScopePrecedenceWithdrawAndConcurrentAck(t *testing.T) {
	pool := openPlatformPolicyTestDatabase(t)
	applyPlatformPolicyMigration(t, pool, "up")
	ctx := context.Background()
	now := databaseClock(t, pool)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	trust := testPolicyTrust(t, publicKey)
	store, err := NewPostgresStore(pool, installationID)
	if err != nil {
		t.Fatal(err)
	}

	global := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
	applyStoredPolicy(t, store, trust, installationID, global, nil, now)
	installation := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	applyStoredPolicy(t, store, trust, installationID, installation, nil, now.Add(time.Second))
	local, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if local.GlobalActive == nil || local.InstallationActive == nil ||
		local.InstallationActive.Signed.Envelope.TargetRevisionID != installation.Envelope.TargetRevisionID {
		t.Fatalf("active scopes after installation apply = %#v", local)
	}

	withdraw := testSignedPolicy(t, now, installationID, ScopeInstallation, 2,
		installation.Envelope.TargetRevisionID, ActionWithdraw, privateKey)
	applyStoredPolicy(t, store, trust, installationID, withdraw, local.InstallationHead, now.Add(2*time.Second))
	local, err = store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if local.InstallationActive != nil || local.GlobalActive == nil ||
		local.GlobalActive.Signed.Envelope.TargetRevisionID != global.Envelope.TargetRevisionID {
		t.Fatalf("installation withdraw did not fall back to global: %#v", local)
	}
	var effectiveID *string
	if err := pool.QueryRow(ctx, `SELECT effective_target_id FROM platform_policy_application_events
		ORDER BY sequence DESC LIMIT 1`).Scan(&effectiveID); err != nil {
		t.Fatal(err)
	}
	if effectiveID == nil || *effectiveID != global.Envelope.TargetRevisionID {
		t.Fatalf("withdraw effective target = %v, want %s", effectiveID, global.Envelope.TargetRevisionID)
	}
	var rolledBack int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_events
		WHERE target_revision_id=$1 AND status='rolled_back'`, installation.Envelope.TargetRevisionID).Scan(&rolledBack); err != nil {
		t.Fatal(err)
	}
	if rolledBack != 1 {
		t.Fatalf("rolled_back acknowledgement count = %d", rolledBack)
	}

	rejected := testSignedPolicy(t, now, installationID, ScopeGlobal, 2,
		global.Envelope.TargetRevisionID, ActionApply, privateKey)
	wire, _ := json.Marshal(rejected)
	if _, err := store.RecordFetched(ctx, wire, rejected, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	const writers = 8
	var group sync.WaitGroup
	errorsByWriter := make(chan error, writers)
	for range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsByWriter <- store.RecordRejected(ctx, rejected.Envelope.TargetRevisionID,
				"local_validation_failed", now.Add(4*time.Second))
		}()
	}
	group.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Errorf("concurrent RecordRejected() error = %v", err)
		}
	}
	var rejectedCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_events
		WHERE target_revision_id=$1 AND status='rejected'`, rejected.Envelope.TargetRevisionID).Scan(&rejectedCount); err != nil {
		t.Fatal(err)
	}
	if rejectedCount != 1 {
		t.Fatalf("concurrent rejected acknowledgement count = %d", rejectedCount)
	}
}

func TestPostgresStoreFutureCandidateAndRestartRecovery(t *testing.T) {
	pool := openPlatformPolicyTestDatabase(t)
	applyPlatformPolicyMigration(t, pool, "up")
	ctx := context.Background()
	baseTime := databaseClock(t, pool)
	clock := baseTime
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	trust := testPolicyTrust(t, publicKey)
	store, err := NewPostgresStore(pool, installationID)
	if err != nil {
		t.Fatal(err)
	}
	active := testSignedPolicy(t, baseTime, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	applyStoredPolicy(t, store, trust, installationID, active, nil, baseTime)

	future := testSignedPolicy(t, baseTime, installationID, ScopeInstallation, 2,
		active.Envelope.TargetRevisionID, ActionApply, privateKey)
	future.Envelope.ValidFrom = baseTime.Add(time.Hour).Unix()
	future.Envelope.ExpiresAt = baseTime.Add(2 * time.Hour).Unix()
	resignTestPolicy(t, &future, privateKey)
	futureWire, _ := json.Marshal(future)
	if _, err := store.RecordFetched(ctx, futureWire, future, baseTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if candidates, err := store.PendingCandidates(ctx, clock, 64); err != nil || len(candidates) != 0 {
		t.Fatalf("future pending candidates = (%d, %v)", len(candidates), err)
	}
	state := NewState(func() time.Time { return clock })
	syncer, err := NewSyncer(ctx, SyncerConfig{
		Client: &memoryPolicyClient{resolveErr: errors.New("publisher offline")}, Store: store,
		Trust: trust, State: state, InstallationID: installationID, PrivateKey: privateKey,
		ControlVersion: "1.4.0", ProtocolVersion: 1, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(ctx); err == nil {
		t.Fatal("SyncOnce() succeeded while publisher was offline")
	}
	if snapshot, _ := state.Snapshot(); snapshot.TargetRevisionID != active.Envelope.TargetRevisionID {
		t.Fatalf("future target replaced active before valid_from: %#v", snapshot)
	}

	clock = baseTime.Add(time.Hour + time.Second)
	if err := syncer.SyncOnce(ctx); err == nil {
		t.Fatal("SyncOnce() succeeded while publisher remained offline")
	}
	if snapshot, stale := state.Snapshot(); stale || snapshot.TargetRevisionID != future.Envelope.TargetRevisionID {
		t.Fatalf("durable future candidate was not applied: (%#v, %t)", snapshot, stale)
	}
	if candidates, err := store.PendingCandidates(ctx, clock, 64); err != nil || len(candidates) != 0 {
		t.Fatalf("applied pending candidates = (%d, %v)", len(candidates), err)
	}

	rejected := testSignedPolicy(t, clock, installationID, ScopeInstallation, 3,
		future.Envelope.TargetRevisionID, ActionApply, privateKey)
	rejectedWire, _ := json.Marshal(rejected)
	if _, err := store.RecordFetched(ctx, rejectedWire, rejected, clock); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordRejected(ctx, rejected.Envelope.TargetRevisionID, "local_validation_failed", clock); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE platform_policy_scope_state
		SET highwater_revision=3,head_target_revision_id=$1,updated_at=$2
		WHERE scope_key=$3`, rejected.Envelope.TargetRevisionID, clock,
		scopeKey(ScopeInstallation, installationID)); err != nil {
		t.Fatal(err)
	}
	restartedState := NewState(func() time.Time { return clock })
	if _, err := NewSyncer(ctx, SyncerConfig{
		Client: &memoryPolicyClient{}, Store: store, Trust: trust, State: restartedState,
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return clock },
	}); err != nil {
		t.Fatalf("restart behind rejected head error = %v", err)
	}
	if snapshot, _ := restartedState.Snapshot(); snapshot.TargetRevisionID != future.Envelope.TargetRevisionID {
		t.Fatalf("restart did not restore LKG behind rejected head: %#v", snapshot)
	}

	clock = baseTime.Add(3 * time.Hour)
	staleState := NewState(func() time.Time { return clock })
	if _, err := NewSyncer(ctx, SyncerConfig{
		Client: &memoryPolicyClient{}, Store: store, Trust: trust, State: staleState,
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return clock },
	}); err != nil {
		t.Fatalf("stale restart error = %v", err)
	}
	if snapshot, stale := staleState.Snapshot(); !stale || snapshot.TargetRevisionID != future.Envelope.TargetRevisionID {
		t.Fatalf("stale restart = (%#v, %t)", snapshot, stale)
	}
}

func TestPostgresStoreApplyBindsVerifiedPolicyToPersistedDelivery(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*VerifiedPolicy)
	}{
		{name: "canonical policy", mutate: func(value *VerifiedPolicy) {
			value.CanonicalPolicy = append([]byte(nil), value.CanonicalPolicy...)
			value.CanonicalPolicy[0] ^= 1
		}},
		{name: "canonical envelope", mutate: func(value *VerifiedPolicy) {
			value.CanonicalEnvelope = append([]byte(nil), value.CanonicalEnvelope...)
			value.CanonicalEnvelope[0] ^= 1
		}},
		{name: "policy digest", mutate: func(value *VerifiedPolicy) { value.Digest[0] ^= 1 }},
		{name: "signature", mutate: func(value *VerifiedPolicy) {
			value.Signature = append([]byte(nil), value.Signature...)
			value.Signature[0] ^= 1
		}},
	} {
		t.Run("forged "+test.name, func(t *testing.T) {
			pool := openPlatformPolicyTestDatabase(t)
			applyPlatformPolicyMigration(t, pool, "up")
			ctx := context.Background()
			now := databaseClock(t, pool)
			installationID := uuid.New()
			publicKey, privateKey := testPolicyKey()
			store, err := NewPostgresStore(pool, installationID)
			if err != nil {
				t.Fatal(err)
			}
			signed := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
			verified := recordAndVerifyPolicy(t, store, testPolicyTrust(t, publicKey), installationID, signed, now)
			test.mutate(&verified)

			if err := store.Apply(ctx, verified, now); !errors.Is(err, ErrDeliveryConflict) {
				t.Fatalf("Apply() error = %v, want %v", err, ErrDeliveryConflict)
			}
			assertApplyLeftOnlyFetched(t, pool, signed.Envelope.TargetRevisionID)
		})
	}

	t.Run("same target id different signed policy", func(t *testing.T) {
		pool := openPlatformPolicyTestDatabase(t)
		applyPlatformPolicyMigration(t, pool, "up")
		ctx := context.Background()
		now := databaseClock(t, pool)
		installationID := uuid.New()
		publicKey, privateKey := testPolicyKey()
		trust := testPolicyTrust(t, publicKey)
		store, err := NewPostgresStore(pool, installationID)
		if err != nil {
			t.Fatal(err)
		}
		stored := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
		_ = recordAndVerifyPolicy(t, store, trust, installationID, stored, now)
		forged := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
		forged.Envelope.TargetRevisionID = stored.Envelope.TargetRevisionID
		forged.Policy.AllowedReleaseChannels = []string{"stable"}
		canonical, err := CanonicalPolicy(forged.Policy)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(canonical)
		forged.Envelope.CanonicalPolicySHA256 = base64.RawURLEncoding.EncodeToString(digest[:])
		resignTestPolicy(t, &forged, privateKey)
		verified, err := Verify(forged, trust, VerifyOptions{
			Now: now, InstallationID: installationID, ControlVersion: "1.4.0",
			ProtocolVersion: 1, DeliveredByResolve: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		if err := store.Apply(ctx, verified, now); !errors.Is(err, ErrDeliveryConflict) {
			t.Fatalf("Apply() error = %v, want %v", err, ErrDeliveryConflict)
		}
		assertApplyLeftOnlyFetched(t, pool, stored.Envelope.TargetRevisionID)
	})
}

func TestPostgresStoreApplyBindsEveryPersistedEnvelopeField(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*SignedPlatformPolicy, uuid.UUID)
	}{
		{name: "scope and installation", mutate: func(value *SignedPlatformPolicy, installationID uuid.UUID) {
			value.Envelope.ScopeKind = ScopeInstallation
			encoded := installationID.String()
			value.Envelope.InstallationID = &encoded
		}},
		{name: "revision and supersedes", mutate: func(value *SignedPlatformPolicy, _ uuid.UUID) {
			value.Envelope.ScopeRevision = 2
			encoded := uuid.NewString()
			value.Envelope.Supersedes = &encoded
		}},
		{name: "action", mutate: func(value *SignedPlatformPolicy, _ uuid.UUID) {
			value.Envelope.Action = ActionWithdraw
			value.Policy = nil
		}},
		{name: "key id", mutate: func(value *SignedPlatformPolicy, _ uuid.UUID) {
			value.Envelope.KeyID = "another-valid-key"
		}},
		{name: "signed validity", mutate: func(value *SignedPlatformPolicy, _ uuid.UUID) {
			value.Envelope.SignedAt--
			value.Envelope.ValidFrom--
			value.Envelope.ExpiresAt++
		}},
		{name: "protocol bounds", mutate: func(value *SignedPlatformPolicy, _ uuid.UUID) {
			value.Envelope.ControlProtocolMax++
		}},
		{name: "rollback target", mutate: func(value *SignedPlatformPolicy, _ uuid.UUID) {
			encoded := uuid.NewString()
			value.Envelope.RollbackOf = &encoded
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := openPlatformPolicyTestDatabase(t)
			applyPlatformPolicyMigration(t, pool, "up")
			ctx := context.Background()
			now := databaseClock(t, pool)
			installationID := uuid.New()
			_, privateKey := testPolicyKey()
			store, err := NewPostgresStore(pool, installationID)
			if err != nil {
				t.Fatal(err)
			}
			stored := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
			wire, err := json.Marshal(stored)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.RecordFetched(ctx, wire, stored, now); err != nil {
				t.Fatal(err)
			}
			forged := cloneSigned(stored)
			test.mutate(&forged, installationID)
			verified := forgedVerifiedPolicy(t, &forged, privateKey)

			if err := store.Apply(ctx, verified, now); !errors.Is(err, ErrDeliveryConflict) {
				t.Fatalf("Apply() error = %v, want %v", err, ErrDeliveryConflict)
			}
			assertApplyLeftOnlyFetched(t, pool, stored.Envelope.TargetRevisionID)
		})
	}
}

func TestPostgresStoreApplyRejectsInconsistentPersistedDelivery(t *testing.T) {
	for _, test := range []struct {
		name   string
		column string
		value  []byte
	}{
		{name: "signed target digest", column: "signed_target_sha256", value: bytes.Repeat([]byte{0x31}, sha256.Size)},
		{name: "signature", column: "signature", value: bytes.Repeat([]byte{0x32}, 64)},
		{name: "canonical policy", column: "canonical_policy", value: []byte("null")},
		{name: "canonical envelope", column: "canonical_envelope", value: []byte("{}")},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := openPlatformPolicyTestDatabase(t)
			applyPlatformPolicyMigration(t, pool, "up")
			ctx := context.Background()
			now := databaseClock(t, pool)
			installationID := uuid.New()
			publicKey, privateKey := testPolicyKey()
			store, err := NewPostgresStore(pool, installationID)
			if err != nil {
				t.Fatal(err)
			}
			signed := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
			verified := recordAndVerifyPolicy(t, store, testPolicyTrust(t, publicKey), installationID, signed, now)
			setPersistedDeliveryColumn(t, pool, signed.Envelope.TargetRevisionID, test.column, test.value)

			if err := store.Apply(ctx, verified, now); !errors.Is(err, ErrDeliveryConflict) {
				t.Fatalf("Apply() error = %v, want %v", err, ErrDeliveryConflict)
			}
			assertApplyLeftOnlyFetched(t, pool, signed.Envelope.TargetRevisionID)
		})
	}
}

func TestPostgresStoreApplyLocksDeliveryBeforeBindingAndRollsBack(t *testing.T) {
	pool := openPlatformPolicyTestDatabase(t)
	applyPlatformPolicyMigration(t, pool, "up")
	ctx := context.Background()
	now := databaseClock(t, pool)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	store, err := NewPostgresStore(pool, installationID)
	if err != nil {
		t.Fatal(err)
	}
	signed := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
	verified := recordAndVerifyPolicy(t, store, testPolicyTrust(t, publicKey), installationID, signed, now)
	setDeliveryMutationTrigger(t, pool, false)
	defer setDeliveryMutationTrigger(t, pool, true)

	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var blockerPID int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE platform_policy_deliveries SET signature=$2 WHERE target_revision_id=$1`,
		signed.Envelope.TargetRevisionID, bytes.Repeat([]byte{0x42}, 64)); err != nil {
		t.Fatal(err)
	}

	applyResult := make(chan error, 1)
	go func() { applyResult <- store.Apply(ctx, verified, now) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity activity
			WHERE $1 = ANY(pg_blocking_pids(activity.pid))
		)`, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Apply() did not block behind the delivery mutation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-applyResult; !errors.Is(err, ErrDeliveryConflict) {
		t.Fatalf("Apply() error = %v, want %v", err, ErrDeliveryConflict)
	}
	assertApplyLeftOnlyFetched(t, pool, signed.Envelope.TargetRevisionID)
}

func TestPostgresStoreApplyRollbackAndReplay(t *testing.T) {
	pool := openPlatformPolicyTestDatabase(t)
	applyPlatformPolicyMigration(t, pool, "up")
	ctx := context.Background()
	now := databaseClock(t, pool)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	store, err := NewPostgresStore(pool, installationID)
	if err != nil {
		t.Fatal(err)
	}
	signed := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
	verified := recordAndVerifyPolicy(t, store, testPolicyTrust(t, publicKey), installationID, signed, now)
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_test_policy_application() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected application failure'; END; $$;
		CREATE TRIGGER reject_test_policy_application BEFORE INSERT ON platform_policy_application_events
		FOR EACH ROW EXECUTE FUNCTION reject_test_policy_application()`); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(ctx, verified, now); err == nil || !strings.Contains(err.Error(), "injected application failure") {
		t.Fatalf("Apply() error = %v, want injected failure", err)
	}
	assertApplyLeftOnlyFetched(t, pool, signed.Envelope.TargetRevisionID)
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_test_policy_application ON platform_policy_application_events;
		DROP FUNCTION reject_test_policy_application()`); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(ctx, verified, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(ctx, verified, now.Add(time.Second)); err != nil {
		t.Fatalf("replayed Apply() error = %v", err)
	}
	var applications, applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_application_events`).Scan(&applications); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_events
		WHERE target_revision_id=$1 AND status='applied'`, signed.Envelope.TargetRevisionID).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applications != 1 || applied != 1 {
		t.Fatalf("replay facts = applications %d, applied %d", applications, applied)
	}
}

func TestPostgresStoreApplyUsesServerClockAfterLocks(t *testing.T) {
	t.Run("first activation expires while waiting for delivery lock", func(t *testing.T) {
		pool := openPlatformPolicyTestDatabase(t)
		applyPlatformPolicyMigration(t, pool, "up")
		ctx := context.Background()
		now := databaseClock(t, pool)
		installationID := uuid.New()
		publicKey, privateKey := testPolicyKey()
		store, err := NewPostgresStore(pool, installationID)
		if err != nil {
			t.Fatal(err)
		}
		signed := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
		expiresAt := now.Truncate(time.Second).Add(2 * time.Second)
		signed.Envelope.ExpiresAt = expiresAt.Unix()
		resignTestPolicy(t, &signed, privateKey)
		verified := recordAndVerifyPolicy(t, store, testPolicyTrust(t, publicKey), installationID, signed, now)

		blocker, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Release()
		tx, err := blocker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var blockerPID int
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT target_revision_id FROM platform_policy_deliveries
			WHERE target_revision_id=$1 FOR UPDATE`, signed.Envelope.TargetRevisionID).Scan(new(uuid.UUID)); err != nil {
			t.Fatal(err)
		}

		applyResult := make(chan error, 1)
		go func() { applyResult <- store.Apply(ctx, verified, now) }()
		waitForPostgresBlock(t, pool, blockerPID, "delivery lock")
		waitForDatabaseClock(t, pool, expiresAt)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-applyResult; !errors.Is(err, ErrExpired) {
			t.Fatalf("Apply() error = %v, want %v", err, ErrExpired)
		}
		assertApplyLeftOnlyFetched(t, pool, signed.Envelope.TargetRevisionID)
	})

	t.Run("first activation expires while waiting for advisory lock", func(t *testing.T) {
		pool := openPlatformPolicyTestDatabase(t)
		applyPlatformPolicyMigration(t, pool, "up")
		ctx := context.Background()
		now := databaseClock(t, pool)
		installationID := uuid.New()
		publicKey, privateKey := testPolicyKey()
		store, err := NewPostgresStore(pool, installationID)
		if err != nil {
			t.Fatal(err)
		}
		signed := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
		expiresAt := now.Truncate(time.Second).Add(2 * time.Second)
		signed.Envelope.ExpiresAt = expiresAt.Unix()
		resignTestPolicy(t, &signed, privateKey)
		verified := recordAndVerifyPolicy(t, store, testPolicyTrust(t, publicKey), installationID, signed, now)

		blocker, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Release()
		tx, err := blocker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var blockerPID int
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(
			hashtext('cdnca.platform_policy.apply'),hashtext($1))`, installationID.String()); err != nil {
			t.Fatal(err)
		}

		applyResult := make(chan error, 1)
		go func() { applyResult <- store.Apply(ctx, verified, now) }()
		waitForPostgresBlock(t, pool, blockerPID, "apply advisory lock")
		waitForDatabaseClock(t, pool, expiresAt)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-applyResult; !errors.Is(err, ErrExpired) {
			t.Fatalf("Apply() error = %v, want %v", err, ErrExpired)
		}
		assertApplyLeftOnlyFetched(t, pool, signed.Envelope.TargetRevisionID)
	})

	t.Run("next activation expires while waiting for scope state lock", func(t *testing.T) {
		pool := openPlatformPolicyTestDatabase(t)
		applyPlatformPolicyMigration(t, pool, "up")
		ctx := context.Background()
		now := databaseClock(t, pool)
		installationID := uuid.New()
		publicKey, privateKey := testPolicyKey()
		trust := testPolicyTrust(t, publicKey)
		store, err := NewPostgresStore(pool, installationID)
		if err != nil {
			t.Fatal(err)
		}
		head := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
		applyStoredPolicy(t, store, trust, installationID, head, nil, now)
		candidate := testSignedPolicy(t, now, installationID, ScopeGlobal, 2,
			head.Envelope.TargetRevisionID, ActionApply, privateKey)
		expiresAt := now.Truncate(time.Second).Add(2 * time.Second)
		candidate.Envelope.ExpiresAt = expiresAt.Unix()
		resignTestPolicy(t, &candidate, privateKey)
		verified := recordAndVerifyPolicy(t, store, trust, installationID, candidate, now.Add(time.Second))

		blocker, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Release()
		tx, err := blocker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var blockerPID int
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT scope_key FROM platform_policy_scope_state
			WHERE scope_key=$1 FOR UPDATE`, scopeKey(ScopeGlobal, installationID)).Scan(new(string)); err != nil {
			t.Fatal(err)
		}

		applyResult := make(chan error, 1)
		go func() { applyResult <- store.Apply(ctx, verified, now.Add(time.Second)) }()
		waitForPostgresBlock(t, pool, blockerPID, "scope state lock")
		waitForDatabaseClock(t, pool, expiresAt)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-applyResult; !errors.Is(err, ErrExpired) {
			t.Fatalf("Apply() error = %v, want %v", err, ErrExpired)
		}

		var highwater int64
		var currentHead, lkg, active string
		if err := pool.QueryRow(ctx, `SELECT highwater_revision,head_target_revision_id,
			lkg_target_revision_id,active_target_revision_id FROM platform_policy_scope_state
			WHERE scope_key=$1`, scopeKey(ScopeGlobal, installationID)).Scan(
			&highwater, &currentHead, &lkg, &active); err != nil {
			t.Fatal(err)
		}
		var applications, candidateAcks, candidateOutbox int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_application_events`).Scan(&applications); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_events
			WHERE target_revision_id=$1`, candidate.Envelope.TargetRevisionID).Scan(&candidateAcks); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_outbox outbox
			JOIN platform_policy_ack_events event ON event.id=outbox.ack_event_id
			WHERE event.target_revision_id=$1`, candidate.Envelope.TargetRevisionID).Scan(&candidateOutbox); err != nil {
			t.Fatal(err)
		}
		if highwater != 1 || currentHead != head.Envelope.TargetRevisionID ||
			lkg != head.Envelope.TargetRevisionID || active != head.Envelope.TargetRevisionID ||
			applications != 1 || candidateAcks != 1 || candidateOutbox != 1 {
			t.Fatalf("expired scope-lock Apply() mutated facts: highwater=%d head=%s lkg=%s active=%s applications=%d acknowledgements=%d outbox=%d",
				highwater, currentHead, lkg, active, applications, candidateAcks, candidateOutbox)
		}
	})

	t.Run("exact applied replay remains idempotent after expiry", func(t *testing.T) {
		pool := openPlatformPolicyTestDatabase(t)
		applyPlatformPolicyMigration(t, pool, "up")
		now := databaseClock(t, pool)
		installationID := uuid.New()
		publicKey, privateKey := testPolicyKey()
		store, err := NewPostgresStore(pool, installationID)
		if err != nil {
			t.Fatal(err)
		}
		signed := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
		expiresAt := now.Truncate(time.Second).Add(2 * time.Second)
		signed.Envelope.ExpiresAt = expiresAt.Unix()
		resignTestPolicy(t, &signed, privateKey)
		verified := recordAndVerifyPolicy(t, store, testPolicyTrust(t, publicKey), installationID, signed, now)
		if err := store.Apply(context.Background(), verified, now); err != nil {
			t.Fatal(err)
		}
		waitForDatabaseClock(t, pool, expiresAt)
		if err := store.Apply(context.Background(), verified, now); err != nil {
			t.Fatalf("expired exact replay error = %v", err)
		}
		var applications, applied int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM platform_policy_application_events`).Scan(&applications); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM platform_policy_ack_events
			WHERE target_revision_id=$1 AND status='applied'`, signed.Envelope.TargetRevisionID).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if applications != 1 || applied != 1 {
			t.Fatalf("expired replay facts = applications %d, applied %d", applications, applied)
		}
	})
}

func TestPostgresStoreApplyRequiresExactRollbackLineage(t *testing.T) {
	t.Run("unrelated rollback target is rejected without mutation", func(t *testing.T) {
		pool := openPlatformPolicyTestDatabase(t)
		applyPlatformPolicyMigration(t, pool, "up")
		ctx := context.Background()
		now := databaseClock(t, pool)
		installationID := uuid.New()
		publicKey, privateKey := testPolicyKey()
		trust := testPolicyTrust(t, publicKey)
		store, err := NewPostgresStore(pool, installationID)
		if err != nil {
			t.Fatal(err)
		}
		head := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
		applyStoredPolicy(t, store, trust, installationID, head, nil, now)
		rollback := testSignedPolicy(t, now, installationID, ScopeGlobal, 2,
			head.Envelope.TargetRevisionID, ActionApply, privateKey)
		unrelated := uuid.NewString()
		rollback.Envelope.RollbackOf = &unrelated
		resignTestPolicy(t, &rollback, privateKey)
		verified := recordAndVerifyPolicy(t, store, trust, installationID, rollback, now.Add(time.Second))

		if err := store.Apply(ctx, verified, now.Add(time.Second)); !errors.Is(err, ErrSupersedesMismatch) {
			t.Fatalf("Apply() error = %v, want %v", err, ErrSupersedesMismatch)
		}
		var highwater int64
		var currentHead string
		if err := pool.QueryRow(ctx, `SELECT highwater_revision,head_target_revision_id
			FROM platform_policy_scope_state WHERE scope_key=$1`, scopeKey(ScopeGlobal, installationID)).Scan(
			&highwater, &currentHead); err != nil {
			t.Fatal(err)
		}
		var applications, acknowledgements int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_application_events`).Scan(&applications); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_events
			WHERE target_revision_id=$1`, rollback.Envelope.TargetRevisionID).Scan(&acknowledgements); err != nil {
			t.Fatal(err)
		}
		if highwater != 1 || currentHead != head.Envelope.TargetRevisionID || applications != 1 || acknowledgements != 1 {
			t.Fatalf("rejected rollback mutated facts: highwater=%d head=%s applications=%d acknowledgements=%d",
				highwater, currentHead, applications, acknowledgements)
		}
	})

	t.Run("withdrawn head is acknowledged once after atomic concurrent rollback", func(t *testing.T) {
		pool := openPlatformPolicyTestDatabase(t)
		applyPlatformPolicyMigration(t, pool, "up")
		ctx := context.Background()
		now := databaseClock(t, pool)
		installationID := uuid.New()
		publicKey, privateKey := testPolicyKey()
		trust := testPolicyTrust(t, publicKey)
		store, err := NewPostgresStore(pool, installationID)
		if err != nil {
			t.Fatal(err)
		}
		head := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
		applyStoredPolicy(t, store, trust, installationID, head, nil, now)
		loaded, err := store.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		withdraw := testSignedPolicy(t, now, installationID, ScopeGlobal, 2,
			head.Envelope.TargetRevisionID, ActionWithdraw, privateKey)
		applyStoredPolicy(t, store, trust, installationID, withdraw, loaded.GlobalHead, now.Add(time.Second))
		rollback := testSignedPolicy(t, now, installationID, ScopeGlobal, 3,
			withdraw.Envelope.TargetRevisionID, ActionApply, privateKey)
		rollbackOf := withdraw.Envelope.TargetRevisionID
		rollback.Envelope.RollbackOf = &rollbackOf
		resignTestPolicy(t, &rollback, privateKey)
		verified := recordAndVerifyPolicy(t, store, trust, installationID, rollback, now.Add(2*time.Second))

		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_test_policy_rollback_application() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'injected rollback application failure'; END; $$;
			CREATE TRIGGER reject_test_policy_rollback_application BEFORE INSERT ON platform_policy_application_events
			FOR EACH ROW EXECUTE FUNCTION reject_test_policy_rollback_application()`); err != nil {
			t.Fatal(err)
		}
		if err := store.Apply(ctx, verified, now.Add(2*time.Second)); err == nil ||
			!strings.Contains(err.Error(), "injected rollback application failure") {
			t.Fatalf("Apply() error = %v, want injected rollback failure", err)
		}
		var currentHead string
		if err := pool.QueryRow(ctx, `SELECT head_target_revision_id FROM platform_policy_scope_state
			WHERE scope_key=$1`, scopeKey(ScopeGlobal, installationID)).Scan(&currentHead); err != nil {
			t.Fatal(err)
		}
		var rollbackAcks int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_events
			WHERE target_revision_id=$1`, rollback.Envelope.TargetRevisionID).Scan(&rollbackAcks); err != nil {
			t.Fatal(err)
		}
		if currentHead != withdraw.Envelope.TargetRevisionID || rollbackAcks != 1 {
			t.Fatalf("failed rollback facts: head=%s acknowledgements=%d", currentHead, rollbackAcks)
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_test_policy_rollback_application ON platform_policy_application_events;
			DROP FUNCTION reject_test_policy_rollback_application()`); err != nil {
			t.Fatal(err)
		}

		const writers = 8
		results := make(chan error, writers)
		var group sync.WaitGroup
		for range writers {
			group.Add(1)
			go func() {
				defer group.Done()
				results <- store.Apply(ctx, verified, now.Add(3*time.Second))
			}()
		}
		group.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Errorf("concurrent rollback Apply() error = %v", err)
			}
		}
		if err := store.Apply(ctx, verified, now.Add(4*time.Second)); err != nil {
			t.Fatalf("rollback replay error = %v", err)
		}

		var applications, applied, rolledBack int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_application_events
			WHERE target_revision_id=$1`, rollback.Envelope.TargetRevisionID).Scan(&applications); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_events
			WHERE target_revision_id=$1 AND status='applied'`, rollback.Envelope.TargetRevisionID).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_events
			WHERE target_revision_id=$1 AND status='rolled_back'`, withdraw.Envelope.TargetRevisionID).Scan(&rolledBack); err != nil {
			t.Fatal(err)
		}
		if applications != 1 || applied != 1 || rolledBack != 1 {
			t.Fatalf("rollback facts = applications %d, applied %d, withdrawn rolled_back %d",
				applications, applied, rolledBack)
		}
	})

	t.Run("stale rollback loses to a locked head advance without mutation", func(t *testing.T) {
		pool := openPlatformPolicyTestDatabase(t)
		applyPlatformPolicyMigration(t, pool, "up")
		ctx := context.Background()
		now := databaseClock(t, pool)
		installationID := uuid.New()
		publicKey, privateKey := testPolicyKey()
		trust := testPolicyTrust(t, publicKey)
		store, err := NewPostgresStore(pool, installationID)
		if err != nil {
			t.Fatal(err)
		}
		head := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
		applyStoredPolicy(t, store, trust, installationID, head, nil, now)
		advance := testSignedPolicy(t, now, installationID, ScopeGlobal, 2,
			head.Envelope.TargetRevisionID, ActionApply, privateKey)
		_ = recordAndVerifyPolicy(t, store, trust, installationID, advance, now.Add(time.Second))
		rollback := testSignedPolicy(t, now, installationID, ScopeGlobal, 3,
			advance.Envelope.TargetRevisionID, ActionApply, privateKey)
		rollbackOf := head.Envelope.TargetRevisionID
		rollback.Envelope.RollbackOf = &rollbackOf
		resignTestPolicy(t, &rollback, privateKey)
		verified := recordAndVerifyPolicy(t, store, trust, installationID, rollback, now.Add(2*time.Second))

		blocker, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Release()
		tx, err := blocker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var blockerPID int
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT scope_key FROM platform_policy_scope_state
			WHERE scope_key=$1 FOR UPDATE`, scopeKey(ScopeGlobal, installationID)).Scan(new(string)); err != nil {
			t.Fatal(err)
		}
		advanceID := uuid.MustParse(advance.Envelope.TargetRevisionID)
		headID := uuid.MustParse(head.Envelope.TargetRevisionID)
		if err := appendAck(ctx, tx, installationID, advanceID, AckValidated, nil, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE platform_policy_scope_state SET
			highwater_revision=2,head_target_revision_id=$1,lkg_target_revision_id=$1,
			active_target_revision_id=$1,updated_at=$2 WHERE scope_key=$3`,
			advanceID, now.Add(time.Second), scopeKey(ScopeGlobal, installationID)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_policy_application_events(
			id,target_revision_id,previous_effective_target_id,effective_target_id,action,occurred_at)
			VALUES($1,$2,$3,$2,$4,$5)`, uuid.Must(uuid.NewV7()), advanceID, headID,
			ActionApply, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := appendAck(ctx, tx, installationID, advanceID, AckApplied, nil, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}

		applyResult := make(chan error, 1)
		go func() { applyResult <- store.Apply(ctx, verified, now.Add(2*time.Second)) }()
		waitForPostgresBlock(t, pool, blockerPID, "scope state head advance")
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-applyResult; !errors.Is(err, ErrSupersedesMismatch) {
			t.Fatalf("stale rollback Apply() error = %v, want %v", err, ErrSupersedesMismatch)
		}

		var highwater int64
		var currentHead, lkg, active string
		if err := pool.QueryRow(ctx, `SELECT highwater_revision,head_target_revision_id,
			lkg_target_revision_id,active_target_revision_id FROM platform_policy_scope_state
			WHERE scope_key=$1`, scopeKey(ScopeGlobal, installationID)).Scan(
			&highwater, &currentHead, &lkg, &active); err != nil {
			t.Fatal(err)
		}
		var applications, rollbackApplications, rollbackAcks, rollbackOutbox int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_application_events`).Scan(&applications); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_application_events
			WHERE target_revision_id=$1`, rollback.Envelope.TargetRevisionID).Scan(&rollbackApplications); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_events
			WHERE target_revision_id=$1`, rollback.Envelope.TargetRevisionID).Scan(&rollbackAcks); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_outbox outbox
			JOIN platform_policy_ack_events event ON event.id=outbox.ack_event_id
			WHERE event.target_revision_id=$1`, rollback.Envelope.TargetRevisionID).Scan(&rollbackOutbox); err != nil {
			t.Fatal(err)
		}
		if highwater != 2 || currentHead != advance.Envelope.TargetRevisionID ||
			lkg != advance.Envelope.TargetRevisionID || active != advance.Envelope.TargetRevisionID ||
			applications != 2 || rollbackApplications != 0 || rollbackAcks != 1 || rollbackOutbox != 1 {
			t.Fatalf("stale rollback mutated facts: highwater=%d head=%s lkg=%s active=%s applications=%d rollback_applications=%d acknowledgements=%d outbox=%d",
				highwater, currentHead, lkg, active, applications, rollbackApplications, rollbackAcks, rollbackOutbox)
		}
	})
}

func applyStoredPolicy(t *testing.T, store *PostgresStore, trust DetachedVerifier, installationID uuid.UUID,
	signed SignedPlatformPolicy, head *ScopeHead, observedAt time.Time) {
	t.Helper()
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordFetched(context.Background(), wire, signed, observedAt); err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(signed, trust, VerifyOptions{
		Now: observedAt, InstallationID: installationID, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Head: head, DeliveredByResolve: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(context.Background(), verified, observedAt); err != nil {
		t.Fatal(err)
	}
}

func recordAndVerifyPolicy(t *testing.T, store *PostgresStore, trust DetachedVerifier, installationID uuid.UUID,
	signed SignedPlatformPolicy, observedAt time.Time) VerifiedPolicy {
	t.Helper()
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordFetched(context.Background(), wire, signed, observedAt); err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(signed, trust, VerifyOptions{
		Now: observedAt, InstallationID: installationID, ControlVersion: "1.4.0",
		ProtocolVersion: 1, DeliveredByResolve: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func forgedVerifiedPolicy(t *testing.T, signed *SignedPlatformPolicy, privateKey ed25519.PrivateKey) VerifiedPolicy {
	t.Helper()
	canonicalPolicy, err := CanonicalPolicy(signed.Policy)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonicalPolicy)
	signed.Envelope.CanonicalPolicySHA256 = base64.RawURLEncoding.EncodeToString(digest[:])
	resignTestPolicy(t, signed, privateKey)
	canonicalEnvelope, err := CanonicalEnvelope(signed.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	return VerifiedPolicy{Signed: cloneSigned(*signed), CanonicalPolicy: canonicalPolicy,
		CanonicalEnvelope: canonicalEnvelope, Digest: digest, Signature: signature}
}

func setPersistedDeliveryColumn(t *testing.T, pool *pgxpool.Pool, targetID, column string, value []byte) {
	t.Helper()
	setDeliveryMutationTrigger(t, pool, false)
	defer setDeliveryMutationTrigger(t, pool, true)
	identifier := pgx.Identifier{column}.Sanitize()
	if _, err := pool.Exec(context.Background(), `UPDATE platform_policy_deliveries SET `+identifier+`=$2
		WHERE target_revision_id=$1`, targetID, value); err != nil {
		t.Fatal(err)
	}
}

func setDeliveryMutationTrigger(t *testing.T, pool *pgxpool.Pool, enabled bool) {
	t.Helper()
	action := "DISABLE"
	if enabled {
		action = "ENABLE"
	}
	if _, err := pool.Exec(context.Background(), `ALTER TABLE platform_policy_deliveries `+action+
		` TRIGGER platform_policy_deliveries_immutable`); err != nil {
		t.Fatal(err)
	}
}

func assertApplyLeftOnlyFetched(t *testing.T, pool *pgxpool.Pool, targetID string) {
	t.Helper()
	ctx := context.Background()
	var scopeStates, applications, acknowledgements, outbox int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_scope_state`).Scan(&scopeStates); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_application_events`).Scan(&applications); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_events
		WHERE target_revision_id=$1`, targetID).Scan(&acknowledgements); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform_policy_ack_outbox`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if scopeStates != 0 || applications != 0 || acknowledgements != 1 || outbox != 1 {
		t.Fatalf("failed Apply() facts = scope %d, applications %d, acknowledgements %d, outbox %d",
			scopeStates, applications, acknowledgements, outbox)
	}
}

func databaseClock(t *testing.T, pool *pgxpool.Pool) time.Time {
	t.Helper()
	var now time.Time
	if err := pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now.UTC()
}

func waitForDatabaseClock(t *testing.T, pool *pgxpool.Pool, target time.Time) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for databaseClock(t, pool).Before(target) {
		if time.Now().After(deadline) {
			t.Fatalf("database clock did not reach %s", target)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForPostgresBlock(t *testing.T, pool *pgxpool.Pool, blockerPID int, boundary string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var blocked bool
		if err := pool.QueryRow(context.Background(), `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity activity
			WHERE $1 = ANY(pg_blocking_pids(activity.pid))
		)`, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Apply() did not block behind %s", boundary)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openPlatformPolicyTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "platform_policy_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^platform_policy_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func applyPlatformPolicyMigration(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	name := fmt.Sprintf("022_platform_policy_consumer.%s.sql", direction)
	script, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), string(script))
		return err
	}); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
}

func assertPlatformPolicyTables(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass('platform_policy_deliveries') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != want {
		t.Fatalf("platform_policy_deliveries exists = %t, want %t", exists, want)
	}
}

func isPlatformPolicyImmutableError(err error) bool {
	var databaseError *pgconn.PgError
	return errors.As(err, &databaseError) && strings.Contains(databaseError.Message, "append-only")
}
