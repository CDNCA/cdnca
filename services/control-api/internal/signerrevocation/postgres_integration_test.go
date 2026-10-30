package signerrevocation

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresLKGAtomicRestartConcurrencyAndOutage(t *testing.T) {
	pool := signerRevocationPool(t)
	// The fixture is at the release head; 064 (signer revocation LKG) must be applied.
	var applied bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=64)`).Scan(&applied); err != nil || !applied {
		t.Fatalf("migration 064 applied = %t, err=%v", applied, err)
	}
	initial := makeTrustFixture(t, "root", "current")
	extended := makeTrustFixture(t, "root", "current", "next")
	storeNow := fixedNow.Add(5 * time.Minute)
	store := NewStore(pool, initial, func() time.Time { return storeNow })

	bootstrap, err := store.Accept(t.Context(), Candidate{OperationID: uuid.New(), KeysetPayload: initial.body,
		KeysetETag: strongETag(initial.body), ObservedAt: fixedNow})
	if err != nil || bootstrap.Revision != 1 || bootstrap.RevocationHead.Sequence != 0 {
		t.Fatalf("bootstrap snapshot = (%#v, %v)", bootstrap, err)
	}
	genesis := testManifest(1, nil, nil, "root", 1)
	genesisEncoded := signManifest(t, genesis, AuthorityRef{Kind: AuthorityLineage, KeyID: "current", Generation: 2},
		initial.privateKeys["current"])
	first, err := store.Accept(t.Context(), Candidate{OperationID: uuid.New(), RevocationPayload: genesisEncoded,
		RevocationETag: strongETag(genesisEncoded), ObservedAt: fixedNow.Add(time.Minute)})
	if err != nil || first.Revision != 2 || first.RevocationHead.Sequence != 1 || len(first.Revocations) != 1 {
		t.Fatalf("genesis LKG = (%#v, %v)", first, err)
	}
	if _, err := store.Accept(t.Context(), Candidate{OperationID: uuid.New(), RevocationPayload: genesisEncoded,
		RevocationETag: strongETag([]byte("different payload")), ObservedAt: fixedNow.Add(time.Minute)}); !errors.Is(err, ErrInvalidETag) {
		t.Fatalf("ETag tamper error = %v", err)
	}
	assertLKGCounts(t, pool, 2, 1)

	previous := uint64(1)
	previousDigest := first.RevocationHead.ManifestSHA256
	successor := testManifest(2, &previous, &previousDigest, "root", 1)
	successor.IssuedAt = canonicalTime(fixedNow.Add(2 * time.Minute))
	successor.ExpiresAt = canonicalTime(fixedNow.Add(time.Hour))
	successor.EffectiveNotBefore = canonicalTime(fixedNow.Add(2 * time.Minute))
	validSuccessor := signManifest(t, successor,
		AuthorityRef{Kind: AuthorityLineage, KeyID: "current", Generation: 2}, initial.privateKeys["current"])
	tampered, _ := Decode(validSuccessor)
	signature, _ := base64.RawURLEncoding.DecodeString(tampered.Signature)
	signature[0] ^= 0xff
	tampered.Signature = base64.RawURLEncoding.EncodeToString(signature)
	invalidSuccessor, _ := Encode(tampered)
	_, err = store.Accept(t.Context(), Candidate{OperationID: uuid.New(), KeysetPayload: extended.body,
		KeysetETag: strongETag(extended.body), RevocationPayload: invalidSuccessor,
		RevocationETag: strongETag(invalidSuccessor), ObservedAt: fixedNow.Add(2 * time.Minute)})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("atomic invalid candidate error = %v", err)
	}
	var signatureRejections int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM control_signer_revocation_events
		WHERE stage='reject' AND reason_code=$1`, ReasonInvalidSignature).Scan(&signatureRejections); err != nil ||
		signatureRejections != 1 {
		t.Fatalf("signature rejection events = %d, err=%v", signatureRejections, err)
	}
	assertLKGCounts(t, pool, 2, 1)
	retained, err := store.Restore(t.Context())
	if err != nil || retained.Keyset.ActiveKeyID != "current" || retained.RevocationHead.Sequence != 1 {
		t.Fatalf("retained after failed atomic candidate = (%#v, %v)", retained, err)
	}

	successor.IssuedAt = canonicalTime(fixedNow.Add(4 * time.Minute))
	successor.EffectiveNotBefore = canonicalTime(fixedNow.Add(4 * time.Minute))
	validSuccessor = signManifest(t, successor,
		AuthorityRef{Kind: AuthorityLineage, KeyID: "current", Generation: 2}, initial.privateKeys["current"])

	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, acceptErr := store.Accept(context.Background(), Candidate{OperationID: uuid.New(),
				KeysetPayload: extended.body, KeysetETag: strongETag(extended.body),
				RevocationPayload: validSuccessor, RevocationETag: strongETag(validSuccessor),
				ObservedAt: fixedNow.Add(4 * time.Minute)})
			results <- acceptErr
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	for result := range results {
		if result != nil {
			t.Fatalf("concurrent same candidate error = %v", result)
		}
	}
	assertLKGCounts(t, pool, 3, 2)

	restarted := NewStore(pool, extended, func() time.Time { return storeNow })
	restored, err := restarted.Restore(t.Context())
	if err != nil || restored.Revision != 3 || restored.Keyset.ActiveKeyID != "next" ||
		restored.RevocationHead.Sequence != 2 || len(restored.Revocations) != 2 {
		t.Fatalf("restart restore = (%#v, %v)", restored, err)
	}
	runtime, err := NewRuntime(restored)
	if err != nil {
		t.Fatal(err)
	}
	if decision := runtime.DecideUpgradeGrant(SignerIdentity{KeyID: "root", Generation: 1}, fixedNow.Add(24*time.Hour)); decision.Allowed || decision.Reason != ReasonSignerRevoked {
		t.Fatalf("expired-transport revocation decision = %#v", decision)
	}
	if err := restarted.RecordOutage(t.Context(), uuid.New(), fixedNow.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	afterOutage, err := restarted.Restore(t.Context())
	if err != nil || afterOutage.Revision != restored.Revision || afterOutage.RevocationHead != restored.RevocationHead {
		t.Fatalf("outage changed LKG = (%#v, %v)", afterOutage, err)
	}
	var outageEvents int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM control_signer_revocation_events
		WHERE reason_code=$1`, ReasonTransportUnavailable).Scan(&outageEvents); err != nil || outageEvents != 1 {
		t.Fatalf("outage events = %d, err=%v", outageEvents, err)
	}

	assertAppendOnlyTables(t, pool)
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_signer_trust_snapshots
		DISABLE TRIGGER control_signer_trust_snapshots_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE control_signer_trust_snapshots
		SET keyset_payload=set_byte(keyset_payload,0,get_byte(keyset_payload,0)#1) WHERE revision=3`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_signer_trust_snapshots
		ENABLE TRIGGER control_signer_trust_snapshots_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Restore(t.Context()); !errors.Is(err, ErrInvalidStoredState) {
		t.Fatalf("SQL-tampered restore error = %v", err)
	}
}

func TestMigration064DownUpAndFactsFailClosed(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682), so the 064
	// round trip loads only migrations 1..064.
	t.Run("empty down up", func(t *testing.T) {
		pool := signerRevocationSchema(t, false)
		if err := databasetest.MigrateThrough(t.Context(), pool, "up", 64); err != nil {
			t.Fatalf("migrate 001 through 064: %v", err)
		}
		if err := databasetest.MigrateThrough(t.Context(), pool, "down", 64); err != nil {
			t.Fatalf("064 down: %v", err)
		}
		assertControlMigrationVersion(t, pool, 63)
		if err := databasetest.MigrateThrough(t.Context(), pool, "up", 64); err != nil {
			t.Fatalf("064 up: %v", err)
		}
		assertControlMigrationVersion(t, pool, 64)
		if err := database.Migrate(t.Context(), pool, "up"); err != nil {
			t.Fatalf("roll forward to release head: %v", err)
		}
	})

	t.Run("facts reject down", func(t *testing.T) {
		pool := signerRevocationSchema(t, false)
		if err := databasetest.MigrateThrough(t.Context(), pool, "up", 64); err != nil {
			t.Fatalf("migrate 001 through 064: %v", err)
		}
		fixture := makeTrustFixture(t, "root")
		store := NewStore(pool, fixture, func() time.Time { return fixedNow })
		if _, err := store.Accept(t.Context(), Candidate{OperationID: uuid.New(), KeysetPayload: fixture.body,
			KeysetETag: strongETag(fixture.body), ObservedAt: fixedNow}); err != nil {
			t.Fatal(err)
		}
		err := databasetest.MigrateThrough(t.Context(), pool, "down", 64)
		if err == nil || !strings.Contains(err.Error(), "064 facts exist") {
			t.Fatalf("used 064 down error = %v", err)
		}
		assertControlMigrationVersion(t, pool, 64)
	})
}

// signerRevocationPool returns a schema at the release head (a clone of
// TEST_DATABASE_TEMPLATE when it is set).
func signerRevocationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	return signerRevocationSchema(t, true)
}

func signerRevocationSchema(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	// A full migration from scratch takes minutes on a loaded machine.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "signer_revocation_lkg_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^signer_revocation_lkg_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
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
			_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
			admin.Close()
			t.Fatalf("migrate to release head: %v", err)
		}
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func assertControlMigrationVersion(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), "SELECT max(version) FROM schema_migrations").Scan(&got); err != nil || got != want {
		t.Fatalf("migration version = %d, want %d, err=%v", got, want, err)
	}
}

func assertLKGCounts(t *testing.T, pool *pgxpool.Pool, snapshots, manifests int) {
	t.Helper()
	var gotSnapshots, gotManifests int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM control_signer_trust_snapshots),
		(SELECT count(*) FROM control_signer_revocation_manifests)`).Scan(&gotSnapshots, &gotManifests); err != nil ||
		gotSnapshots != snapshots || gotManifests != manifests {
		t.Fatalf("LKG counts snapshots=%d/%d manifests=%d/%d err=%v", gotSnapshots, snapshots, gotManifests, manifests, err)
	}
}

func assertAppendOnlyTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	columns := map[string]string{
		"control_signer_trust_snapshots":      "accepted_at",
		"control_signer_revocation_manifests": "accepted_at",
		"control_signer_revocation_events":    "occurred_at",
		"control_signer_revocation_audit":     "occurred_at",
	}
	for table, column := range columns {
		t.Run(table, func(t *testing.T) {
			identifier := pgx.Identifier{table}.Sanitize()
			field := pgx.Identifier{column}.Sanitize()
			for _, statement := range []string{"UPDATE " + identifier + " SET " + field + "=" + field,
				"DELETE FROM " + identifier, "TRUNCATE " + identifier + " CASCADE"} {
				if _, err := pool.Exec(t.Context(), statement); err == nil || !strings.Contains(err.Error(), "append-only") {
					t.Fatalf("guard statement %q error = %v", statement, err)
				}
			}
		})
	}
}
