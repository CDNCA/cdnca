package entitlementsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresKeysetLastKnownGoodRestartRollbackAndUnavailableService(t *testing.T) {
	pool := isolatedKeysetPool(t)
	now := time.Unix(1_850_300_000, 0).UTC()
	root := makeKeysetFixture(t, now, "root", "middle")
	store := NewPostgresKeysetStore(pool)
	rootETag := keysetETag(root.body)
	accepted, err := store.Accept(context.Background(), root.body, rootETag, root.pins, now)
	if err != nil || accepted.ActiveKeyID != "middle" {
		t.Fatalf("accept initial keyset = (%#v, %v)", accepted, err)
	}

	unavailableClient, err := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errTransportUnknown
	})})
	if err != nil {
		t.Fatal(err)
	}
	restartedTrust, err := entitlementguard.NewTrustStore(root.pins)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewKeysetManager(context.Background(), unavailableClient, store, restartedTrust,
		func() time.Time { return now })
	if err != nil {
		t.Fatalf("restore last-known-good: %v", err)
	}
	if key, found := restartedTrust.PublicKey("middle"); !found || len(key) == 0 {
		t.Fatal("restart did not restore the rotated verification key")
	}
	if err := manager.Refresh(context.Background()); err == nil {
		t.Fatal("unavailable license service unexpectedly refreshed")
	}
	if _, found := restartedTrust.PublicKey("middle"); !found {
		t.Fatal("refresh failure discarded last-known-good trust")
	}

	newer := extendKeysetFixture(t, now, root, "leaf")
	newerETag := keysetETag(newer.body)
	accepted, err = store.Accept(context.Background(), newer.body, newerETag, newer.pins, now.Add(time.Minute))
	if err != nil || accepted.ActiveKeyID != "leaf" || len(accepted.Chain) != 3 {
		t.Fatalf("accept extended keyset = (%#v, %v)", accepted, err)
	}
	if _, err := store.Accept(context.Background(), root.body, rootETag, root.pins, now.Add(2*time.Minute)); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("ancestor replay error = %v", err)
	}
	var activeKeyID, storedETag string
	if err := pool.QueryRow(context.Background(), `SELECT active_key_id,etag FROM entitlement_signing_keyset_lkg
		WHERE singleton=true`).Scan(&activeKeyID, &storedETag); err != nil {
		t.Fatal(err)
	}
	if activeKeyID != "leaf" || storedETag != newerETag {
		t.Fatalf("rollback changed LKG active=%q etag=%q", activeKeyID, storedETag)
	}

	var tampered publicKeysetWire
	if err := jsonUnmarshal(newer.body, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Rotations[len(tampered.Rotations)-1].AuthorizationSignature = strings.Repeat("A", 86)
	tamperedBody := mustMarshalKeyset(t, tampered)
	if _, err := store.Accept(context.Background(), tamperedBody, keysetETag(tamperedBody), newer.pins,
		now.Add(3*time.Minute)); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("tampered keyset error = %v", err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT active_key_id FROM entitlement_signing_keyset_lkg
		WHERE singleton=true`).Scan(&activeKeyID); err != nil || activeKeyID != "leaf" {
		t.Fatalf("tampered update changed LKG active=%q err=%v", activeKeyID, err)
	}

	if _, err := pool.Exec(context.Background(), `UPDATE entitlement_signing_keyset_lkg
		SET payload=set_byte(payload,0,get_byte(payload,0)#1) WHERE singleton=true`); err != nil {
		t.Fatal(err)
	}
	corruptTrust, _ := entitlementguard.NewTrustStore(root.pins)
	if _, err := NewKeysetManager(context.Background(), unavailableClient, store, corruptTrust,
		func() time.Time { return now }); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("corrupt LKG restart error = %v", err)
	}
	if _, found := corruptTrust.PublicKey("leaf"); found {
		t.Fatal("corrupt LKG established trust on restart")
	}
}

func TestSigningKeysetMigrationRoundTrip(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682): round-trip 016
	// with only 1..016 loaded, then roll forward to the release head.
	pool := isolatedKeysetSchema(t, false)
	ctx := context.Background()
	if err := databasetest.MigrateThrough(ctx, pool, "up", 16); err != nil {
		t.Fatal(err)
	}
	var version int64
	for {
		if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		if version <= 16 {
			break
		}
		if err := databasetest.MigrateThrough(ctx, pool, "down", 16); err != nil {
			t.Fatal(err)
		}
	}
	if version != 16 {
		t.Fatalf("migration 016 is not applied, current version=%d", version)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "down", 16); err != nil {
		t.Fatal(err)
	}
	var tableName *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('entitlement_signing_keyset_lkg')::text`).Scan(&tableName); err != nil {
		t.Fatal(err)
	}
	if tableName != nil {
		t.Fatalf("migration 016 down retained table %q", *tableName)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT to_regclass('entitlement_signing_keyset_lkg')::text`).Scan(&tableName); err != nil {
		t.Fatal(err)
	}
	if tableName == nil || *tableName != "entitlement_signing_keyset_lkg" {
		t.Fatalf("migration 016 up table = %v", tableName)
	}
}

func TestPostgresKeysetProjectionReplacementRepairAndFailClosedRestore(t *testing.T) {
	pool := isolatedKeysetPool(t)
	now := time.Unix(1_850_400_000, 0).UTC()
	initial := makeKeysetFixture(t, now, "root", "middle")
	var initialWire publicKeysetWire
	if err := jsonUnmarshal(initial.body, &initialWire); err != nil {
		t.Fatal(err)
	}
	initialWire.Keys[0].Status = "retired"
	initial.body = mustMarshalKeyset(t, initialWire)
	extraPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pins := append([]entitlementguard.VerificationKey(nil), initial.pins...)
	pins = append(pins, entitlementguard.VerificationKey{KeyID: "bootstrap-extra", PublicKey: extraPublic})
	store := NewPostgresKeysetStore(pool)
	initialETag := keysetETag(initial.body)
	accepted, err := store.Accept(context.Background(), initial.body, initialETag, pins, now)
	if err != nil {
		t.Fatal(err)
	}
	initialAcceptedAt := keysetAcceptedAt(t, pool)
	assertProjectionMatches(t, pool, accepted, sha256.Sum256(initial.body), initialAcceptedAt)

	if _, err := pool.Exec(context.Background(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at)
		VALUES('stale-key',$1,'retired',$2,NULL,NULL,$3,$2)`, extraPublic, now, bytes.Repeat([]byte{9}, sha256.Size)); err != nil {
		t.Fatal(err)
	}
	rotated := extendKeysetFixture(t, now, initial, "leaf")
	var rotatedWire publicKeysetWire
	if err := jsonUnmarshal(rotated.body, &rotatedWire); err != nil {
		t.Fatal(err)
	}
	rotatedWire.Keys[0].Status = "retired"
	rotated.body = mustMarshalKeyset(t, rotatedWire)
	rotatedETag := keysetETag(rotated.body)
	accepted, err = store.Accept(context.Background(), rotated.body, rotatedETag, pins, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rotatedAcceptedAt := keysetAcceptedAt(t, pool)
	assertProjectionMatches(t, pool, accepted, sha256.Sum256(rotated.body), rotatedAcceptedAt)

	if _, err := pool.Exec(context.Background(), `DELETE FROM entitlement_signing_keyset_current_keys WHERE key_id='leaf'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE entitlement_signing_keyset_current_keys
		SET status='active',keyset_payload_sha256=$1 WHERE key_id='root'`,
		bytes.Repeat([]byte{7}, sha256.Size)); err != nil {
		t.Fatal(err)
	}
	repaired, err := store.Accept(context.Background(), rotated.body, rotatedETag, pins, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := keysetAcceptedAt(t, pool); !got.Equal(rotatedAcceptedAt) {
		t.Fatalf("same ETag accepted_at = %s, want %s", got, rotatedAcceptedAt)
	}
	assertProjectionMatches(t, pool, repaired, sha256.Sum256(rotated.body), rotatedAcceptedAt)

	if _, err := pool.Exec(context.Background(), `UPDATE entitlement_signing_keyset_current_keys
		SET status='active',keyset_payload_sha256=$1`, bytes.Repeat([]byte{5}, sha256.Size)); err != nil {
		t.Fatal(err)
	}
	restored, etag, err := store.Restore(context.Background(), pins, now.Add(3*time.Minute))
	if err != nil || etag != rotatedETag {
		t.Fatalf("Restore() = (%#v, %q, %v)", restored, etag, err)
	}
	assertProjectionMatches(t, pool, restored, sha256.Sum256(rotated.body), rotatedAcceptedAt)

	if _, err := pool.Exec(context.Background(), `UPDATE entitlement_signing_keyset_lkg
		SET payload_sha256=$1 WHERE singleton=true`, bytes.Repeat([]byte{3}, sha256.Size)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Restore(context.Background(), pins, now.Add(4*time.Minute)); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("damaged Restore() error = %v", err)
	}
	assertProjectionCount(t, pool, 0)
}

func TestPostgresKeysetProjectionWriteFailureRollsBackLKGAndProjection(t *testing.T) {
	pool := isolatedKeysetPool(t)
	now := time.Unix(1_850_500_000, 0).UTC()
	initial := makeKeysetFixture(t, now, "root")
	store := NewPostgresKeysetStore(pool)
	accepted, err := store.Accept(context.Background(), initial.body, keysetETag(initial.body), initial.pins, now)
	if err != nil {
		t.Fatal(err)
	}
	acceptedAt := keysetAcceptedAt(t, pool)
	initialDigest := sha256.Sum256(initial.body)
	assertProjectionMatches(t, pool, accepted, initialDigest, acceptedAt)
	if _, err := pool.Exec(context.Background(), `CREATE FUNCTION reject_leaf_projection() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN IF NEW.key_id='leaf' THEN RAISE EXCEPTION 'projection rejected'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_leaf_projection BEFORE INSERT ON entitlement_signing_keyset_current_keys
		FOR EACH ROW EXECUTE FUNCTION reject_leaf_projection()`); err != nil {
		t.Fatal(err)
	}
	rotated := extendKeysetFixture(t, now, initial, "leaf")
	if _, err := store.Accept(context.Background(), rotated.body, keysetETag(rotated.body), initial.pins,
		now.Add(time.Minute)); err == nil {
		t.Fatal("projection write failure accepted candidate")
	}
	var activeKeyID string
	if err := pool.QueryRow(context.Background(), `SELECT active_key_id FROM entitlement_signing_keyset_lkg
		WHERE singleton=true`).Scan(&activeKeyID); err != nil || activeKeyID != "root" {
		t.Fatalf("failed projection changed LKG active=%q err=%v", activeKeyID, err)
	}
	assertProjectionMatches(t, pool, accepted, initialDigest, acceptedAt)
}

func TestPostgresKeysetRestoreClearsOrphanProjectionWithoutLKG(t *testing.T) {
	pool := isolatedKeysetPool(t)
	now := time.Unix(1_850_600_000, 0).UTC()
	fixture := makeKeysetFixture(t, now, "root")
	digest := sha256.Sum256(fixture.body)
	if _, err := pool.Exec(context.Background(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at)
		VALUES('orphan',$1,'active',$2,NULL,NULL,$3,$2)`, fixture.pins[0].PublicKey, now, digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewPostgresKeysetStore(pool).Restore(context.Background(), fixture.pins, now); !errors.Is(err, ErrNoLocalKeyset) {
		t.Fatalf("Restore() error = %v", err)
	}
	assertProjectionCount(t, pool, 0)
}

func TestKeysetManagerNotModifiedRepairsProjection(t *testing.T) {
	pool := isolatedKeysetPool(t)
	now := time.Unix(1_850_700_000, 0).UTC()
	fixture := makeKeysetFixture(t, now, "root", "next")
	etag := keysetETag(fixture.body)
	store := NewPostgresKeysetStore(pool)
	if _, err := store.Accept(context.Background(), fixture.body, etag, fixture.pins, now); err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore(fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("If-None-Match") != etag {
			t.Fatalf("If-None-Match = %q", request.Header.Get("If-None-Match"))
		}
		return keysetHTTPResponse(http.StatusNotModified, nil, etag), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewKeysetManager(context.Background(), client, store, trust, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `DELETE FROM entitlement_signing_keyset_current_keys WHERE key_id='next'`); err != nil {
		t.Fatal(err)
	}
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertProjectionMatches(t, pool, manager.current, sha256.Sum256(fixture.body), keysetAcceptedAt(t, pool))
}

func TestPostgresKeysetConcurrentInitialBranchesAcceptExactlyOne(t *testing.T) {
	pool := isolatedKeysetPool(t)
	now := time.Unix(1_850_800_000, 0).UTC()
	root := makeKeysetFixture(t, now, "root")
	branches := []keysetFixture{
		extendKeysetFixture(t, now, root, "left"),
		extendKeysetFixture(t, now, root, "right"),
	}
	store := NewPostgresKeysetStore(pool)
	start := make(chan struct{})
	results := make(chan error, len(branches))
	var wait sync.WaitGroup
	for index := range branches {
		wait.Add(1)
		go func(fixture keysetFixture) {
			defer wait.Done()
			<-start
			_, err := store.Accept(context.Background(), fixture.body, keysetETag(fixture.body), root.pins, now)
			results <- err
		}(branches[index])
	}
	close(start)
	wait.Wait()
	close(results)
	successes, rollbacks := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrKeysetRollback):
			rollbacks++
		default:
			t.Fatalf("concurrent Accept() error = %v", err)
		}
	}
	if successes != 1 || rollbacks != 1 {
		t.Fatalf("concurrent Accept() successes=%d rollbacks=%d", successes, rollbacks)
	}
	restored, _, err := store.Restore(context.Background(), root.pins, now)
	if err != nil || (restored.ActiveKeyID != "left" && restored.ActiveKeyID != "right") {
		t.Fatalf("concurrent winner = (%#v, %v)", restored, err)
	}
	assertProjectionMatches(t, pool, restored, sha256.Sum256(restored.Payload), keysetAcceptedAt(t, pool))
}

func TestKeysetManagerProjectionFailureDoesNotApplyTrust(t *testing.T) {
	pool := isolatedKeysetPool(t)
	now := time.Unix(1_850_900_000, 0).UTC()
	initial := makeKeysetFixture(t, now, "root")
	rotated := extendKeysetFixture(t, now, initial, "leaf")
	store := NewPostgresKeysetStore(pool)
	initialETag := keysetETag(initial.body)
	if _, err := store.Accept(context.Background(), initial.body, initialETag, initial.pins, now); err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore(initial.pins)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return keysetHTTPResponse(http.StatusOK, rotated.body, keysetETag(rotated.body)), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewKeysetManager(context.Background(), client, store, trust, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `CREATE FUNCTION reject_manager_leaf_projection() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN IF NEW.key_id='leaf' THEN RAISE EXCEPTION 'projection rejected'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_manager_leaf_projection BEFORE INSERT ON entitlement_signing_keyset_current_keys
		FOR EACH ROW EXECUTE FUNCTION reject_manager_leaf_projection()`); err != nil {
		t.Fatal(err)
	}
	if err := manager.Refresh(context.Background()); err == nil {
		t.Fatal("projection failure refreshed manager")
	}
	if _, found := trust.PublicKey("leaf"); found {
		t.Fatal("projection failure applied leaf to memory trust")
	}
	if _, found := trust.PublicKey("root"); !found || manager.current.ActiveKeyID != "root" || manager.etag != initialETag {
		t.Fatal("projection failure changed existing manager trust")
	}
	var activeKeyID string
	if err := pool.QueryRow(context.Background(), `SELECT active_key_id FROM entitlement_signing_keyset_lkg
		WHERE singleton=true`).Scan(&activeKeyID); err != nil || activeKeyID != "root" {
		t.Fatalf("projection failure changed LKG active=%q err=%v", activeKeyID, err)
	}
}

func TestKeysetManagerBootstrapPinCollisionLeavesStateRecoverable(t *testing.T) {
	pool := isolatedKeysetPool(t)
	now := time.Unix(1_851_000_000, 0).UTC()
	initial := makeKeysetFixture(t, now, "root")
	candidate := extendKeysetFixture(t, now, initial, "leaf")
	pinnedLeaf, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pins := append([]entitlementguard.VerificationKey(nil), initial.pins...)
	pins = append(pins, entitlementguard.VerificationKey{KeyID: "leaf", PublicKey: pinnedLeaf})
	store := NewPostgresKeysetStore(pool)
	trust, err := entitlementguard.NewTrustStore(pins)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return keysetHTTPResponse(http.StatusOK, candidate.body, keysetETag(candidate.body)), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewKeysetManager(context.Background(), client, store, trust, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Refresh(context.Background()); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("bootstrap pin collision refresh error = %v", err)
	}
	if manager.current != nil || manager.etag != "" {
		t.Fatalf("collision changed manager current=%#v etag=%q", manager.current, manager.etag)
	}
	if key, found := trust.PublicKey("leaf"); !found || !bytes.Equal(key, pinnedLeaf) {
		t.Fatalf("collision changed pinned in-memory key: found=%v key=%x", found, key)
	}
	var lkgCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM entitlement_signing_keyset_lkg
		WHERE singleton=true`).Scan(&lkgCount); err != nil || lkgCount != 0 {
		t.Fatalf("collision persisted LKG rows=%d err=%v", lkgCount, err)
	}
	assertProjectionCount(t, pool, 0)

	restartedTrust, err := entitlementguard.NewTrustStore(pins)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewKeysetManager(context.Background(), client, store, restartedTrust, func() time.Time { return now })
	if err != nil {
		t.Fatalf("restart after rejected collision: %v", err)
	}
	if restarted.current != nil || restarted.etag != "" {
		t.Fatalf("restart restored current=%#v etag=%q", restarted.current, restarted.etag)
	}
	if key, found := restartedTrust.PublicKey("leaf"); !found || !bytes.Equal(key, pinnedLeaf) {
		t.Fatalf("restart changed pinned key: found=%v key=%x", found, key)
	}
}

func TestPostgresKeysetRetiredStatusReplayRollsBackLKGAndProjection(t *testing.T) {
	pool := isolatedKeysetPool(t)
	now := time.Unix(1_851_100_000, 0).UTC()
	active := makeKeysetFixture(t, now, "root")
	verifyOnly := extendKeysetFixture(t, now, active, "leaf")
	store := NewPostgresKeysetStore(pool)
	if _, err := store.Accept(context.Background(), active.body, keysetETag(active.body), active.pins, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Accept(context.Background(), verifyOnly.body, keysetETag(verifyOnly.body), active.pins,
		now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var retiredWire publicKeysetWire
	if err := jsonUnmarshal(verifyOnly.body, &retiredWire); err != nil {
		t.Fatal(err)
	}
	retiredWire.Keys[0].Status = "retired"
	retiredBody := mustMarshalKeyset(t, retiredWire)
	retiredETag := keysetETag(retiredBody)
	retired, err := store.Accept(context.Background(), retiredBody, retiredETag, active.pins, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	retiredAcceptedAt := keysetAcceptedAt(t, pool)
	retiredDigest := sha256.Sum256(retiredBody)
	assertProjectionMatches(t, pool, retired, retiredDigest, retiredAcceptedAt)

	if _, err := store.Accept(context.Background(), verifyOnly.body, keysetETag(verifyOnly.body), active.pins,
		now.Add(3*time.Minute)); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("retired status replay error = %v", err)
	}
	var storedETag string
	if err := pool.QueryRow(context.Background(), `SELECT etag FROM entitlement_signing_keyset_lkg
		WHERE singleton=true`).Scan(&storedETag); err != nil || storedETag != retiredETag {
		t.Fatalf("retired replay changed LKG etag=%q err=%v", storedETag, err)
	}
	assertProjectionMatches(t, pool, retired, retiredDigest, retiredAcceptedAt)
	restored, restoredETag, err := store.Restore(context.Background(), active.pins, now.Add(4*time.Minute))
	if err != nil || restoredETag != retiredETag {
		t.Fatalf("restore after retired replay = (%#v, %q, %v)", restored, restoredETag, err)
	}
	assertProjectionMatches(t, pool, restored, retiredDigest, retiredAcceptedAt)
}

// isolatedKeysetPool returns a schema at the release head (a clone of
// TEST_DATABASE_TEMPLATE when it is set).
func isolatedKeysetPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		ensureKeysetProjectionContract(t, pool)
		return pool
	}
	return isolatedKeysetSchema(t, true)
}

func isolatedKeysetSchema(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	// A full migration from scratch takes minutes on a loaded machine.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "control_keyset_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^control_keyset_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if migrate {
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			pool.Close()
			t.Fatal(err)
		}
		ensureKeysetProjectionContract(t, pool)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupContext, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupContext, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	return pool
}

func ensureKeysetProjectionContract(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass('entitlement_signing_keyset_current_keys') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		return
	}
	t.Fatal("migration 084 projection table is absent")
}

func keysetAcceptedAt(t *testing.T, pool *pgxpool.Pool) time.Time {
	t.Helper()
	var acceptedAt time.Time
	if err := pool.QueryRow(context.Background(), `SELECT accepted_at FROM entitlement_signing_keyset_lkg
		WHERE singleton=true`).Scan(&acceptedAt); err != nil {
		t.Fatal(err)
	}
	return acceptedAt.UTC()
}

func assertProjectionMatches(t *testing.T, pool *pgxpool.Pool, verified *VerifiedKeyset,
	digest [sha256.Size]byte, acceptedAt time.Time) {
	t.Helper()
	expected := make(map[string]VerifiedKeyState, len(verified.KeyStates))
	for _, state := range verified.KeyStates {
		expected[state.Key.KeyID] = state
	}
	rows, err := pool.Query(context.Background(), `SELECT key_id,public_key,status,not_before,sign_until,verify_until,
		keyset_payload_sha256,accepted_at FROM entitlement_signing_keyset_current_keys`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var keyID, status string
		var publicKey, rowDigest []byte
		var notBefore, rowAcceptedAt time.Time
		var signUntil, verifyUntil *time.Time
		if err := rows.Scan(&keyID, &publicKey, &status, &notBefore, &signUntil, &verifyUntil,
			&rowDigest, &rowAcceptedAt); err != nil {
			t.Fatal(err)
		}
		state, found := expected[keyID]
		if !found || !bytes.Equal(publicKey, state.Key.PublicKey) || status != state.Status ||
			!notBefore.Equal(state.Key.NotBefore) || !equalTimePointer(signUntil, state.Key.SignUntil) ||
			!equalTimePointer(verifyUntil, state.Key.VerifyUntil) || !bytes.Equal(rowDigest, digest[:]) ||
			!rowAcceptedAt.Equal(acceptedAt) {
			t.Fatalf("projection row %q = key=%x status=%q windows=%s/%v/%v digest=%x accepted=%s, want %#v digest=%x accepted=%s",
				keyID, publicKey, status, notBefore, signUntil, verifyUntil, rowDigest, rowAcceptedAt,
				state, digest, acceptedAt)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != len(expected) {
		t.Fatalf("projection rows = %d, want %d", seen, len(expected))
	}
}

func assertProjectionCount(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM entitlement_signing_keyset_current_keys`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("projection count = %d, want %d", count, want)
	}
}

func keysetETag(body []byte) string {
	digest := sha256.Sum256(body)
	return `"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`
}

func jsonUnmarshal(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	return decoder.Decode(target)
}
