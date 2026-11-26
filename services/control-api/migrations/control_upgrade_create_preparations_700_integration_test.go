//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestControlUpgradeCreatePreparations700: a preparation names
// one 096 create intent; a failure needs its stable code, a License reason only comes with
// license_rejected, ready means phase done, only a preparing row may hold a claim; failed and
// ready are terminal, the row identity is immutable and rows are never deleted. Down drops the
// table and leaves the intents.
func TestControlUpgradeCreatePreparations700(t *testing.T) {
	const version = 700
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	identity := seedUpgradeRolloutIdentity093(t, pool)
	intent := func() uuid.UUID {
		id := uuid.New()
		digest := sha256.Sum256([]byte(id.String()))
		at := time.Now().UTC().Truncate(time.Microsecond)
		if _, err := pool.Exec(ctx, `INSERT INTO control_upgrade_grant_intents_096(
			id,actor_scope_id,actor_user_id,installation_id,candidate_plan_id,plan_id,
			idempotency_key,request_digest,request_id,state,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,NULL,$6,$7,'upgrade-request-700','reserved',$8,$8)`,
			id, identity.scopeID, identity.userID, identity.installationID, uuid.New(),
			"upgrade-intent-"+id.String()[:8], digest[:], at); err != nil {
			t.Fatal(err)
		}
		return id
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	insert := func(intentID uuid.UUID, state, phase string, code, reason, claim any, start ...any) error {
		startWhenReady, startCode := any(false), any(nil)
		if len(start) == 2 {
			startWhenReady, startCode = start[0], start[1]
		}
		var claimedBy, expires any
		if claim != nil {
			claimedBy, expires = "worker-700", time.Now().Add(time.Minute)
		}
		_, err := pool.Exec(ctx, `INSERT INTO control_upgrade_create_preparations(
			intent_id,plan_id,actor_scope_id,actor_user_id,node_ids,request_bytes,state,phase,failure_code,
			failure_reason,attempt_count,available_at,claimed_by,claim_token,claim_expires_at,created_at,updated_at,
			start_when_ready,start_failure_code)
			VALUES($1,$2,$3,$4,ARRAY[$5::uuid],'{}',$6,$7,$8,$9,0,now(),$10,$11,$12,now(),now(),$13,$14)`,
			intentID, uuid.New(), identity.scopeID, identity.userID, uuid.New(), state, phase, code, reason,
			claimedBy, claim, expires, startWhenReady, startCode)
		return err
	}
	sqlState := func(err error) string {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code
		}
		return ""
	}
	for name, err := range map[string]error{
		"unknown intent":             insert(uuid.New(), "preparing", "queued", nil, nil, nil),
		"failed without code":        insert(intent(), "failed", "downloading", nil, nil, nil),
		"unknown failure code":       insert(intent(), "failed", "downloading", "disk_full", nil, nil),
		"reason without refusal":     insert(intent(), "failed", "downloading", "artifact_invalid", "installation_banned", nil),
		"ready before done":          insert(intent(), "ready", "finalizing", nil, nil, nil),
		"claimed terminal":           insert(intent(), "failed", "issuing", "license_unavailable", nil, uuid.New()),
		"preparing with a code":      insert(intent(), "preparing", "queued", "internal_error", nil, nil),
		"done while still preparing": insert(intent(), "preparing", "done", nil, nil, nil),
		"start failure not asked":    insert(intent(), "ready", "done", nil, nil, nil, false, "approval_required"),
		"start failure before ready": insert(intent(), "preparing", "starting", nil, nil, nil, true, "start_refused"),
		"starting not asked":         insert(intent(), "preparing", "starting", nil, nil, nil, false, nil),
	} {
		if code := sqlState(err); code != "23503" && code != "23514" {
			t.Errorf("%s: err=%v, want a constraint violation", name, err)
		}
	}
	preparing := intent()
	if err := insert(preparing, "preparing", "queued", nil, nil, uuid.New()); err != nil {
		t.Fatalf("claimed preparing row: %v", err)
	}
	refused := intent()
	if err := insert(refused, "failed", "issuing", "license_rejected", "installation_banned", nil); err != nil {
		t.Fatalf("License refusal row: %v", err)
	}
	// A codeless License refusal of the auto-start keeps its HTTP status as the reason.
	startRefused := intent()
	if err := insert(startRefused, "ready", "done", nil, "http_403", nil, true, "license_rejected"); err != nil {
		t.Fatalf("auto-start refusal row: %v", err)
	}
	exec := func(sql string, args ...any) error {
		_, err := pool.Exec(ctx, sql, args...)
		return err
	}
	if err := exec(`UPDATE control_upgrade_create_preparations SET phase='downloading',updated_at=now()
		WHERE intent_id=$1`, preparing); err != nil {
		t.Fatalf("phase update: %v", err)
	}
	for name, err := range map[string]error{
		"node set change": exec(`UPDATE control_upgrade_create_preparations SET node_ids=ARRAY[$2::uuid]
			WHERE intent_id=$1`, preparing, uuid.New()),
		"start request change": exec(`UPDATE control_upgrade_create_preparations SET start_when_ready=true
			WHERE intent_id=$1`, preparing),
		"terminal row reopened": exec(`UPDATE control_upgrade_create_preparations SET state='preparing',phase='queued',
			failure_code=NULL,failure_reason=NULL WHERE intent_id=$1`, refused),
		"delete":   exec(`DELETE FROM control_upgrade_create_preparations WHERE intent_id=$1`, preparing),
		"truncate": exec(`TRUNCATE control_upgrade_create_preparations`),
	} {
		if sqlState(err) != "P7005" {
			t.Errorf("%s: err=%v, want P7005", name, err)
		}
	}
	if err := exec(`UPDATE control_upgrade_create_preparations SET state='ready',phase='done',claimed_by=NULL,
		claim_token=NULL,claim_expires_at=NULL,updated_at=now() WHERE intent_id=$1`, preparing); err != nil {
		t.Fatalf("ready: %v", err)
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	var table bool
	var intents int
	if err := pool.QueryRow(ctx, `SELECT to_regclass(current_schema() || '.control_upgrade_create_preparations') IS NOT NULL,
		(SELECT count(*) FROM control_upgrade_grant_intents_096 WHERE actor_scope_id=$1)`, identity.scopeID).Scan(
		&table, &intents); err != nil {
		t.Fatal(err)
	}
	if table || intents != 13 {
		t.Fatalf("after down table=%v intents=%d, want false and 13", table, intents)
	}
}
