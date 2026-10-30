//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const billingPermissionDeniedCanonicalResponse099 = `{"code":"permission_denied"}`

func TestBillingAdjustmentDenialReceipts099Contract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("099_billing_adjustment_denial_receipts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("099_billing_adjustment_denial_receipts.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"migration 099 requires the exact verified 098 release head",
		"7e1ec92c377a0486ec2551334150d99ea58a61a0bc27b18054e8b33b23989102",
		"4a475ca2db6eb6aeb8e79883fa3f26345314a3331e5319d5fbbe7140f2e969cc",
		"CREATE TABLE billing_adjustment_denial_receipts",
		"FOREIGN KEY (actor_scope_id, actor_user_id)",
		"REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT",
		"UNIQUE (actor_scope_id, actor_user_id, operation, request_key)",
		"UNIQUE (actor_scope_id, actor_user_id, operation, request_id)",
		"CREATE UNIQUE INDEX audit_events_billing_adjustment_denied_identity_099",
		"CREATE FUNCTION prevent_billing_adjustment_denial_receipt_mutation_099",
		"BEFORE TRUNCATE ON billing_adjustment_denial_receipts",
		billingPermissionDeniedCanonicalResponse099,
		"ERRCODE = 'P9902'",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("099 up missing %q", fragment)
		}
	}
	upDigest := sha256.Sum256(up)
	for _, fragment := range []string{
		"migration 099 rollback requires the exact verified 099 head",
		hex.EncodeToString(upDigest[:]),
		"7e1ec92c377a0486ec2551334150d99ea58a61a0bc27b18054e8b33b23989102",
		"4a475ca2db6eb6aeb8e79883fa3f26345314a3331e5319d5fbbe7140f2e969cc",
		"migration 099 rollback would discard billing adjustment denial facts",
		"ERRCODE = 'P9901'",
		"DROP TABLE billing_adjustment_denial_receipts",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("099 down missing %q", fragment)
		}
	}
	if strings.Contains(string(down), "DELETE FROM schema_migrations") {
		t.Fatal("099 down must not delete its own schema_migrations row")
	}
}

func TestBillingAdjustmentDenialReceipts099FreshRoundTripAndConstraints(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 98)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 99); err != nil {
		t.Fatalf("fresh 1..99: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 99)
	var tableExists, indexExists bool
	if err := pool.QueryRow(t.Context(), `SELECT
		to_regclass('billing_adjustment_denial_receipts') IS NOT NULL,
		to_regclass('audit_events_billing_adjustment_denied_identity_099') IS NOT NULL`).Scan(
		&tableExists, &indexExists,
	); err != nil {
		t.Fatal(err)
	}
	if !tableExists || !indexExists {
		t.Fatalf("099 relations table/index = %t/%t", tableExists, indexExists)
	}
	var receiptIdentityIndexes int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_index index
		JOIN pg_class table_class ON table_class.oid=index.indrelid
		WHERE table_class.relnamespace=current_schema()::regnamespace
		  AND table_class.relname='billing_adjustment_denial_receipts'
		  AND index.indisunique AND (
			position('(actor_scope_id, actor_user_id, operation, request_key)' in pg_get_indexdef(index.indexrelid))>0 OR
			position('(actor_scope_id, actor_user_id, operation, request_id)' in pg_get_indexdef(index.indexrelid))>0
		  )`).Scan(&receiptIdentityIndexes); err != nil {
		t.Fatal(err)
	}
	if receiptIdentityIndexes != 2 {
		t.Fatalf("099 receipt identity unique indexes = %d, want 2", receiptIdentityIndexes)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 99); err != nil {
		t.Fatalf("empty 099 down: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 98)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 99); err != nil {
		t.Fatalf("reapply 099: %v", err)
	}
	scopeID, userID := seedBillingDenialActor099(t, pool)
	requestDigest := sha256.Sum256([]byte("billing-adjustment-denial-request"))
	responseDigest := sha256.Sum256([]byte(billingPermissionDeniedCanonicalResponse099))
	receiptID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO billing_adjustment_denial_receipts(
		id,actor_scope_id,actor_user_id,operation,request_key,request_id,
		request_digest,response_code,response_digest,created_at)
		VALUES($1,$2,$3,'billing.adjustment.create','valid-key','valid-request',$4,
		'permission_denied',$5,now())`, receiptID, scopeID, userID, requestDigest[:], responseDigest[:]); err != nil {
		t.Fatalf("insert valid denial receipt: %v", err)
	}

	invalid := []struct {
		name string
		key  string
		code string
		req  []byte
		resp []byte
		user uuid.UUID
	}{
		{name: "request key", key: "bad key", code: "permission_denied", req: requestDigest[:], resp: responseDigest[:], user: userID},
		{name: "request digest", key: "bad-request-digest", code: "permission_denied", req: requestDigest[:31], resp: responseDigest[:], user: userID},
		{name: "response code", key: "bad-response-code", code: "forbidden", req: requestDigest[:], resp: responseDigest[:], user: userID},
		{name: "response digest", key: "bad-response-digest", code: "permission_denied", req: requestDigest[:], resp: requestDigest[:], user: userID},
		{name: "membership", key: "bad-membership", code: "permission_denied", req: requestDigest[:], resp: responseDigest[:], user: uuid.New()},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, err := pool.Exec(t.Context(), `INSERT INTO billing_adjustment_denial_receipts(
				id,actor_scope_id,actor_user_id,operation,request_key,request_id,
				request_digest,response_code,response_digest,created_at)
				VALUES($1,$2,$3,'billing.adjustment.create',$4,'invalid-request',$5,$6,$7,now())`,
				uuid.New(), scopeID, test.user, test.key, test.req, test.code, test.resp)
			if err == nil {
				t.Fatal("invalid denial receipt unexpectedly succeeded")
			}
		})
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO billing_adjustment_denial_receipts(
		id,actor_scope_id,actor_user_id,operation,request_key,request_id,
		request_digest,response_code,response_digest,created_at)
		VALUES($1,$2,$3,'billing.adjustment.create','valid-key','duplicate-request',$4,
		'permission_denied',$5,now())`, uuid.New(), scopeID, userID, requestDigest[:], responseDigest[:]); err == nil {
		t.Fatal("duplicate denial receipt identity unexpectedly succeeded")
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO billing_adjustment_denial_receipts(
		id,actor_scope_id,actor_user_id,operation,request_key,request_id,
		request_digest,response_code,response_digest,created_at)
		VALUES($1,$2,$3,'billing.adjustment.create','different-key','valid-request',$4,
		'permission_denied',$5,now())`, uuid.New(), scopeID, userID, requestDigest[:], responseDigest[:]); err == nil {
		t.Fatal("duplicate denial receipt request ID unexpectedly succeeded")
	}
	for _, mutation := range []struct {
		name  string
		query string
	}{
		{name: "update", query: `UPDATE billing_adjustment_denial_receipts SET request_id='changed' WHERE id=$1`},
		{name: "delete", query: `DELETE FROM billing_adjustment_denial_receipts WHERE id=$1`},
		{name: "truncate", query: `TRUNCATE billing_adjustment_denial_receipts`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			args := []any{receiptID}
			if mutation.name == "truncate" {
				args = nil
			}
			_, err := pool.Exec(t.Context(), mutation.query, args...)
			assertBillingDenialPGCode099(t, err, "P9902")
		})
	}
}

func TestBillingAdjustmentDenialReceipts099DownRejectsFacts(t *testing.T) {
	pairs := []struct {
		name string
		seed string
	}{
		{name: "receipt", seed: "receipt"},
		{name: "denied audit", seed: "audit"},
	}
	for _, test := range pairs {
		t.Run(test.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 99)
			if test.seed == "receipt" {
				scopeID, userID := seedBillingDenialActor099(t, pool)
				requestDigest := sha256.Sum256([]byte("rollback-request"))
				responseDigest := sha256.Sum256([]byte(billingPermissionDeniedCanonicalResponse099))
				_, err := pool.Exec(t.Context(), `INSERT INTO billing_adjustment_denial_receipts(
					id,actor_scope_id,actor_user_id,operation,request_key,request_id,
					request_digest,response_code,response_digest,created_at)
					VALUES($1,$2,$3,'billing.adjustment.create','rollback-fact','rollback-fact',
					$4,'permission_denied',$5,now())`, uuid.New(), scopeID, userID, requestDigest[:], responseDigest[:])
				if err != nil {
					t.Fatal(err)
				}
			} else {
				scopeID, userID := seedBillingDenialActor099(t, pool)
				// Today's audit.Append writes the columns of migration 361 (unified log).
				databasetest.AddUnifiedAuditColumns(t, pool)
				if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
					return audit.New(pool).Append(t.Context(), tx, audit.Event{
						ScopeID: scopeID, ActorUserID: &userID, Action: "billing.adjustment.create",
						ResourceType: "billing_adjustment_denial", ResourceID: "billing.adjustment.create",
						RequestID: "rollback-audit", Result: "denied",
						Payload: map[string]any{"operation": "billing.adjustment.create", "reason_code": "permission_denied"},
					})
				}); err != nil {
					t.Fatalf("seed denied audit fact: %v", err)
				}
			}
			err := migrateVersionIsolated(t.Context(), pool, "down", 99)
			assertBillingDenialPGCode099(t, err, "P9901")
			assertPackageCommerceRBAC079Ledger(t, pool, 99)
		})
	}
}

func seedBillingDenialActor099(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	var scopeID uuid.UUID
	err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		scopeID = uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	username := "billing099-" + strings.ReplaceAll(userID.String(), "-", "")[:20]
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'Billing denial migration actor','not-used')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return scopeID, userID
}

func assertBillingDenialPGCode099(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}
