//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSignerRevocationCheckpoint077MigrationFilesEmbedded(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("077_signer_revocation_checkpoint_lkg.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlmigrations.FS.ReadFile("077_signer_revocation_checkpoint_lkg.down.sql"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"control_signer_checkpoint_snapshots",
		"control_signer_checkpoint_manifests",
		"control_signer_checkpoint_audit",
	} {
		if !strings.Contains(string(up), "CREATE TABLE "+table) {
			t.Errorf("077 up does not create %s", table)
		}
	}
	for _, marker := range []string{"append-only", "DEFERRABLE INITIALLY DEFERRED", "pg_advisory_xact_lock",
		"control_signer_checkpoint_audit_accept_revision_077", "matching_accept_count"} {
		if !strings.Contains(string(up), marker) {
			t.Errorf("077 up is missing %q", marker)
		}
	}
}

func TestSignerRevocationCheckpoint077RoundTripAndFactGuards(t *testing.T) {
	pool := signerCheckpoint077Pool(t)
	assertSignerCheckpoint077Version(t, pool, 77)
	if err := applySignerCheckpoint077Down(t.Context(), pool); err != nil {
		t.Fatalf("077 down: %v", err)
	}
	assertSignerCheckpoint077Version(t, pool, 76)
	migration, err := loadSignerCheckpoint077Migration(77)
	if err != nil {
		t.Fatal(err)
	}
	if err := applySignerCheckpoint077Up(t.Context(), pool, migration); err != nil {
		t.Fatalf("077 up: %v", err)
	}
	assertSignerCheckpoint077Version(t, pool, 77)

	digest := make([]byte, 32)
	etag := `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`
	acceptedAt := time.Now().UTC().Truncate(time.Microsecond)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_signer_checkpoint_snapshots(
		revision,accepted_previous_revision,previous_revision,previous_checkpoint_sha256,
		checkpoint_sha256,etag,signed_checkpoint,keyset_payload,keyset_sha256,
		head_sequence,head_manifest_sha256,accepted_at)
		VALUES(1,NULL,NULL,NULL,$1,$2,'x','x',$1,0,NULL,$3)`, digest, etag, acceptedAt); err != nil {
		t.Fatal(err)
	}
	assertSignerCheckpoint077Code(t, tx.Commit(t.Context()), "P0001")
	assertSignerCheckpoint077Counts(t, pool, 0, 0, 0)

	tx, err = pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_signer_checkpoint_snapshots(
		revision,accepted_previous_revision,previous_revision,previous_checkpoint_sha256,
		checkpoint_sha256,etag,signed_checkpoint,keyset_payload,keyset_sha256,
		head_sequence,head_manifest_sha256,accepted_at)
		VALUES(1,NULL,NULL,NULL,$1,$2,'x','x',$1,0,NULL,$3)`, digest, etag, acceptedAt); err != nil {
		t.Fatal(err)
	}
	mismatchedDigest := append([]byte(nil), digest...)
	mismatchedDigest[0] = 1
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_signer_checkpoint_audit(
		stream_position,operation_id,event_type,reason_code,checkpoint_revision,checkpoint_sha256,etag,
		occurred_at,previous_hash,event_hash) VALUES(1,$1,'accept','checkpoint_accepted',1,$2,$3,$4,NULL,$5)`,
		uuid.New(), mismatchedDigest, etag, acceptedAt, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	assertSignerCheckpoint077Code(t, tx.Commit(t.Context()), "P0001")
	assertSignerCheckpoint077Counts(t, pool, 0, 0, 0)

	tx, err = pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_signer_checkpoint_snapshots(
		revision,accepted_previous_revision,previous_revision,previous_checkpoint_sha256,
		checkpoint_sha256,etag,signed_checkpoint,keyset_payload,keyset_sha256,
		head_sequence,head_manifest_sha256,accepted_at)
		VALUES(1,NULL,NULL,NULL,$1,$2,'x','x',$1,0,NULL,$3)`, digest, etag, acceptedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_signer_checkpoint_audit(
		stream_position,operation_id,event_type,reason_code,checkpoint_revision,checkpoint_sha256,etag,
		occurred_at,previous_hash,event_hash) VALUES(1,$1,'accept','checkpoint_accepted',1,$2,$3,$4,NULL,$5)`,
		uuid.New(), digest, etag, acceptedAt, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertSignerCheckpoint077Counts(t, pool, 1, 0, 1)
	secondEventHash := make([]byte, 32)
	secondEventHash[0] = 1
	assertSignerCheckpoint077Code(t, func() error {
		_, err := pool.Exec(t.Context(), `INSERT INTO control_signer_checkpoint_audit(
			stream_position,operation_id,event_type,reason_code,checkpoint_revision,checkpoint_sha256,etag,
			occurred_at,previous_hash,event_hash) VALUES(2,$1,'accept','checkpoint_accepted',1,$2,$3,$4,$5,$6)`,
			uuid.New(), digest, etag, acceptedAt, make([]byte, 32), secondEventHash)
		return err
	}(), "23505")
	assertSignerCheckpoint077Counts(t, pool, 1, 0, 1)
	assertSignerCheckpoint077Code(t, func() error {
		_, err := pool.Exec(t.Context(), `UPDATE control_signer_checkpoint_snapshots
			SET accepted_at=accepted_at WHERE revision=1`)
		return err
	}(), "P0001")
	assertSignerCheckpoint077Code(t, applySignerCheckpoint077Down(t.Context(), pool), "55000")
	assertSignerCheckpoint077Version(t, pool, 77)
}

func assertSignerCheckpoint077Counts(t *testing.T, pool *pgxpool.Pool, snapshots, manifests, audit int) {
	t.Helper()
	var gotSnapshots, gotManifests, gotAudit int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM control_signer_checkpoint_snapshots),
		(SELECT count(*) FROM control_signer_checkpoint_manifests),
		(SELECT count(*) FROM control_signer_checkpoint_audit)`).Scan(&gotSnapshots, &gotManifests, &gotAudit); err != nil ||
		gotSnapshots != snapshots || gotManifests != manifests || gotAudit != audit {
		t.Fatalf("checkpoint counts snapshots=%d/%d manifests=%d/%d audit=%d/%d err=%v",
			gotSnapshots, snapshots, gotManifests, manifests, gotAudit, audit, err)
	}
}

func signerCheckpoint077Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "signer_checkpoint_077_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^signer_checkpoint_077_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
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
		admin.Close()
		t.Fatal(err)
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
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (
		version bigint PRIMARY KEY,
		migration_id text,
		checksum_sha256 text,
		down_checksum_sha256 text,
		integrity_state text,
		metadata_recorded_at timestamptz,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		t.Fatal(err)
	}
	for version := int64(1); version <= 77; version++ {
		migration, err := loadSignerCheckpoint077Migration(version)
		if err != nil {
			t.Fatal(err)
		}
		if err := applySignerCheckpoint077Up(ctx, pool, migration); err != nil {
			t.Fatalf("apply migration %03d: %v", version, err)
		}
	}
	return pool
}

func assertSignerCheckpoint077Version(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	var count, minimum, maximum, version078 int
	if err := pool.QueryRow(t.Context(), `SELECT count(*),COALESCE(min(version),0),COALESCE(max(version),0),
		count(*) FILTER (WHERE version=78) FROM schema_migrations`).Scan(
		&count, &minimum, &maximum, &version078); err != nil {
		t.Fatal(err)
	}
	if count != want || minimum != 1 || maximum != want || version078 != 0 {
		t.Fatalf("migration ledger count/min/max/078 = %d/%d/%d/%d, want %d/1/%d/0",
			count, minimum, maximum, version078, want, want)
	}
	for version := int64(1); version <= int64(want); version++ {
		migration, err := loadSignerCheckpoint077Migration(version)
		if err != nil {
			t.Fatal(err)
		}
		var identifier, upChecksum, downChecksum, integrity string
		var metadataRecorded, applied bool
		if err := pool.QueryRow(t.Context(), `SELECT migration_id,checksum_sha256,down_checksum_sha256,
			integrity_state,metadata_recorded_at IS NOT NULL,applied_at IS NOT NULL
			FROM schema_migrations WHERE version=$1`, version).Scan(
			&identifier, &upChecksum, &downChecksum, &integrity, &metadataRecorded, &applied); err != nil {
			t.Fatal(err)
		}
		if identifier != migration.identifier || upChecksum != migration.upChecksum ||
			downChecksum != migration.downChecksum || integrity != "verified" || !metadataRecorded || !applied {
			t.Fatalf("migration %03d ledger metadata mismatch", version)
		}
	}
}

type signerCheckpoint077Migration struct {
	version      int64
	identifier   string
	upScript     []byte
	downScript   []byte
	upChecksum   string
	downChecksum string
}

func loadSignerCheckpoint077Migration(version int64) (signerCheckpoint077Migration, error) {
	upMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
	if err != nil || len(upMatches) != 1 {
		return signerCheckpoint077Migration{}, fmt.Errorf(
			"resolve migration %03d up: matches=%v err=%v", version, upMatches, err)
	}
	downMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.down.sql", version))
	if err != nil || len(downMatches) != 1 {
		return signerCheckpoint077Migration{}, fmt.Errorf(
			"resolve migration %03d down: matches=%v err=%v", version, downMatches, err)
	}
	identifier := strings.TrimSuffix(upMatches[0], ".up.sql")
	if strings.TrimSuffix(downMatches[0], ".down.sql") != identifier {
		return signerCheckpoint077Migration{}, fmt.Errorf(
			"migration %03d up/down identifiers differ: %q/%q", version, upMatches[0], downMatches[0])
	}
	upScript, err := fs.ReadFile(controlmigrations.FS, upMatches[0])
	if err != nil {
		return signerCheckpoint077Migration{}, err
	}
	downScript, err := fs.ReadFile(controlmigrations.FS, downMatches[0])
	if err != nil {
		return signerCheckpoint077Migration{}, err
	}
	return signerCheckpoint077Migration{
		version:      version,
		identifier:   identifier,
		upScript:     upScript,
		downScript:   downScript,
		upChecksum:   fmt.Sprintf("%x", sha256.Sum256(upScript)),
		downChecksum: fmt.Sprintf("%x", sha256.Sum256(downScript)),
	}, nil
}

func applySignerCheckpoint077Up(ctx context.Context, pool *pgxpool.Pool, migration signerCheckpoint077Migration) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(migration.upScript)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(
			version,migration_id,checksum_sha256,down_checksum_sha256,
			integrity_state,metadata_recorded_at
		) VALUES($1,$2,$3,$4,'verified',now())`, migration.version, migration.identifier,
			migration.upChecksum, migration.downChecksum)
		return err
	})
}

func applySignerCheckpoint077Down(ctx context.Context, pool *pgxpool.Pool) error {
	migration, err := loadSignerCheckpoint077Migration(77)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(migration.downScript)); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=77`)
		if err == nil && command.RowsAffected() != 1 {
			return fmt.Errorf("delete 077 ledger rows = %d, want 1", command.RowsAffected())
		}
		return err
	})
}

func assertSignerCheckpoint077Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error = %v, want code %s", err, want)
	}
}
