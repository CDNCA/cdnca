//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 646 down refuses while a revision carries an explicit pow_difficulty and
// leaves the database unchanged; on an empty fact set it restores 053's
// function and drops the column, and up applies again.
func TestChallengePoWDifficulty646DownUpOnReleaseHead(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	ctx := t.Context()
	columnExists := func() bool {
		t.Helper()
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='challenge_policy_revisions'
			  AND column_name='pow_difficulty')`).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}
	functionMentionsPoW := func() bool {
		t.Helper()
		var source string
		if err := pool.QueryRow(ctx, `SELECT prosrc FROM pg_proc
			WHERE oid = to_regprocedure(current_schema() || '.validate_challenge_policy_revision_053()')`).Scan(&source); err != nil {
			t.Fatal(err)
		}
		return strings.Contains(source, "pow_difficulty")
	}
	if !columnExists() || !functionMentionsPoW() {
		t.Fatal("release head lacks 646 pow_difficulty column or function")
	}

	down, err := fs.ReadFile(controlmigrations.FS, "646_challenge_pow_difficulty.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO challenge_policy_revisions(policy_id,tenant_scope_id,tenant_id,site_id,host,
			revision,action,priority,mode,min_delay_seconds,challenge_ttl_seconds,pass_ttl_seconds,clock_skew_seconds,
			attempts_per_nonce,failure_window_seconds,max_failures_per_window,ip_binding,bind_user_agent,bypass_routes,
			key_reference,enabled,deleted,document,created_by_scope_id,created_by_user_id,request_id,trace_id,created_at,
			pow_difficulty)
			VALUES($1,$2,$3,$4,'pow.example.test',1,'create',10,'click',0,60,300,5,1,60,3,'exact',false,'[]',
			  'keyref:challenge-primary',true,false,'{}',$2,$5,'pow-646','pow-646',clock_timestamp(),20)`,
			uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, string(down))
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "explicit pow_difficulty facts") {
		t.Fatalf("646 down with an explicit difficulty error = %v", err)
	}
	if !columnExists() {
		t.Fatal("refused 646 down changed the schema")
	}

	if err := database.Migrate(context.Background(), pool, "down"); err != nil {
		t.Fatalf("646 down on empty facts: %v", err)
	}
	if columnExists() || functionMentionsPoW() {
		t.Fatal("646 down left pow_difficulty in the column set or the validate function")
	}
	if err := database.Migrate(context.Background(), pool, "up"); err != nil {
		t.Fatalf("646 up after down: %v", err)
	}
	if !columnExists() || !functionMentionsPoW() {
		t.Fatal("646 up after down did not restore pow_difficulty")
	}
}
