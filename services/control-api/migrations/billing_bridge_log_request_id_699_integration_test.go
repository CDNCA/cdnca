//go:build integration

package migrations_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestBillingBridgeLogRequestID699: pre-699 rows keep a NULL
// request_id; a failure may now keep its reason code, denied still needs one and a success none; request_id
// follows the request ID pattern; down clears failure reasons and restores the 556 check.
func TestBillingBridgeLogRequestID699(t *testing.T) {
	const version = 699
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	exec := func(sql string, args ...any) error {
		_, err := pool.Exec(ctx, sql, args...)
		return err
	}
	checkViolation := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "23514"
	}
	at := time.Now().UTC()
	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY created_at LIMIT 1`).Scan(&platform); err != nil {
		platform = uuid.New()
		if err := exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
			t.Fatal(err)
		}
	}
	user := uuid.New()
	if err := exec(`INSERT INTO users(id,username,display_name,password_hash,status) VALUES($1,$2,'bb','unused','active')`,
		user, "bb699-"+user.String()[:8]); err != nil {
		t.Fatal(err)
	}
	const keyID = "cbb_RQRQRQRQRQRQRQRQRQRQRQ"
	if err := exec(`INSERT INTO billing_bridge_keys(id,owner_scope_id,owner_kind,name,key_id,secret_seed,pepper_version,
		ip_allowlist,status,created_by,revision,created_at,updated_at)
		VALUES($1,$2,'platform','whmcs',$3,$4,'v1',ARRAY['203.0.113.0/24']::cidr[],'active',$5,1,$6,$6)`,
		uuid.New(), platform, keyID, bytes.Repeat([]byte{1}, 32), user, at); err != nil {
		t.Fatal(err)
	}
	insert := func(result string, reason *string, requestID ...string) error {
		var request any
		if len(requestID) == 1 {
			request = requestID[0]
		}
		sql := `INSERT INTO billing_bridge_logs(id,key_id,owner_scope_id,action,result,reason_code,http_status,duration_ms,created_at)
			VALUES($1,$2,$3,'service.get',$4,$5,404,1,$6)`
		args := []any{uuid.New(), keyID, platform, result, reason, at}
		if request != nil {
			sql = `INSERT INTO billing_bridge_logs(id,key_id,owner_scope_id,action,result,reason_code,http_status,duration_ms,
				created_at,request_id) VALUES($1,$2,$3,'service.get',$4,$5,404,1,$6,$7)`
			args = append(args, request)
		}
		return exec(sql, args...)
	}
	notFound, denied := "bridge_service_not_found", "bridge.bad_signature"
	if err := insert("failure", nil); err != nil {
		t.Fatalf("pre-699 failure row: %v", err)
	}
	if err := insert("failure", &notFound); !checkViolation(err) {
		t.Fatalf("pre-699 failure with a reason err=%v", err)
	}

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	var nullRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM billing_bridge_logs WHERE key_id=$1 AND request_id IS NULL`,
		keyID).Scan(&nullRows); err != nil || nullRows != 1 {
		t.Fatalf("pre-699 rows with NULL request_id = %d, %v; want 1", nullRows, err)
	}
	if err := insert("failure", &notFound, "req-699.a_1"); err != nil {
		t.Fatalf("failure with reason: %v", err)
	}
	if err := insert("failure", nil, "req-699-b"); err != nil {
		t.Fatalf("failure without reason: %v", err)
	}
	if err := insert("denied", &denied, "req-699-c"); err != nil {
		t.Fatalf("denied with reason: %v", err)
	}
	for name, err := range map[string]error{
		"denied without reason": insert("denied", nil, "req-699-d"),
		"success with reason":   insert("success", &notFound, "req-699-e"),
		"bad request id":        insert("failure", &notFound, "req 699"),
	} {
		if !checkViolation(err) {
			t.Errorf("%s err=%v, want check violation", name, err)
		}
	}
	var indexes int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE tablename='billing_bridge_logs'
		AND indexname IN ('billing_bridge_logs_request_699_idx','billing_bridge_logs_service_699_idx')`).Scan(&indexes); err != nil || indexes != 2 {
		t.Fatalf("699 indexes = %d, %v", indexes, err)
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	var column bool
	var failureReasons, deniedReasons int
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
		AND table_name='billing_bridge_logs' AND column_name='request_id'),
		(SELECT count(*) FROM billing_bridge_logs WHERE key_id=$1 AND result='failure' AND reason_code IS NOT NULL),
		(SELECT count(*) FROM billing_bridge_logs WHERE key_id=$1 AND result='denied' AND reason_code IS NOT NULL)`,
		keyID).Scan(&column, &failureReasons, &deniedReasons); err != nil {
		t.Fatal(err)
	}
	if column || failureReasons != 0 || deniedReasons != 1 {
		t.Fatalf("after down column=%v failure reasons=%d denied reasons=%d", column, failureReasons, deniedReasons)
	}
	if err := insert("failure", &notFound); !checkViolation(err) {
		t.Fatalf("after down failure with a reason err=%v", err)
	}
}
