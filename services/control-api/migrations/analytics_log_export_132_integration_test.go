//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAnalyticsLogExport132RoundTripAndFences(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 131)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 132); err != nil {
		t.Fatalf("131 -> 132: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 132)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 132); err != nil {
		t.Fatalf("empty 132 down: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 131)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 132); err != nil {
		t.Fatalf("131 -> 132 reapply: %v", err)
	}

	identity := seedSiteGroup082Identity(t, pool, "analytics-export-132")
	other := seedSiteGroup082Identity(t, pool, "analytics-export-132-other")
	exportID, credentialID := uuid.New(), uuid.New()
	createdAt := time.Date(2026, 8, 7, 3, 0, 0, 0, time.UTC)
	filter, err := json.Marshal(map[string]any{
		"version": 1, "tenant_id": identity.tenantID.String(), "filter": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(filter)
	insert := `INSERT INTO analytics_log_exports_v1(
		id,scope_id,tenant_id,actor_scope_id,actor_user_id,credential_kind,credential_id,
		idempotency_key,request_digest,filter,created_at)
		VALUES($1,$2,$3,$2,$4,'session',$5,$6,$7,$8,$9)`
	if _, err := pool.Exec(t.Context(), insert, exportID, identity.scopeID, identity.tenantID,
		identity.userID, credentialID, "analytics-export-132-key", digest[:], filter, createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_log_export_events_v1(
		export_id,sequence,state,reason,occurred_at) VALUES($1,1,'pending','created',$2)`,
		exportID, createdAt); err != nil {
		t.Fatal(err)
	}

	_, err = pool.Exec(t.Context(), insert, uuid.New(), identity.scopeID, other.tenantID,
		identity.userID, uuid.New(), "analytics-export-132-scope", digest[:], filter, createdAt)
	assertAnalyticsLogExport132Code(t, err, "23503")
	_, err = pool.Exec(t.Context(), insert, uuid.New(), identity.scopeID, identity.tenantID,
		identity.userID, credentialID, "analytics-export-132-key", sha256.New().Sum(nil), filter, createdAt)
	assertAnalyticsLogExport132Code(t, err, "23505")

	firstWorker, secondWorker := uuid.New(), uuid.New()
	var claimed *uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT claim_analytics_log_export_132($1,$2,$3)`,
		firstWorker, createdAt, time.Minute).Scan(&claimed); err != nil || claimed == nil || *claimed != exportID {
		t.Fatalf("initial claim=%v err=%v", claimed, err)
	}
	claimed = nil
	if err := pool.QueryRow(t.Context(), `SELECT claim_analytics_log_export_132($1,$2,$3)`,
		secondWorker, createdAt.Add(30*time.Second), time.Minute).Scan(&claimed); err != nil || claimed != nil {
		t.Fatalf("live lease claim=%v err=%v, want nil", claimed, err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT claim_analytics_log_export_132($1,$2,$3)`,
		secondWorker, createdAt.Add(61*time.Second), time.Minute).Scan(&claimed); err != nil || claimed == nil || *claimed != exportID {
		t.Fatalf("expired lease takeover=%v err=%v", claimed, err)
	}

	_, err = pool.Exec(t.Context(), `UPDATE analytics_log_exports_v1 SET idempotency_key='mutated-export-key' WHERE id=$1`, exportID)
	assertAnalyticsLogExport132Code(t, err, "P1321")
	_, err = pool.Exec(t.Context(), `DELETE FROM analytics_log_export_events_v1 WHERE export_id=$1`, exportID)
	assertAnalyticsLogExport132Code(t, err, "P1321")
	_, err = pool.Exec(t.Context(), `TRUNCATE analytics_log_export_events_v1`)
	assertAnalyticsLogExport132Code(t, err, "P1321")

	artifactDigest := sha256.Sum256([]byte("event_id\r\nexport-event\r\n"))
	if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_log_export_artifacts_v1(
		export_id,content,content_sha256,row_count,artifact_expires_at,created_at)
		VALUES($1,$2,$3,1,statement_timestamp()+INTERVAL '1 hour',statement_timestamp())`,
		exportID, []byte("event_id\r\nexport-event\r\n"), artifactDigest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_log_export_events_v1(
		export_id,sequence,state,reason,snapshot_at,row_count,byte_count,artifact_sha256,occurred_at)
		VALUES($1,4,'completed','completed',$2,1,27,$3,$2)`, exportID,
		createdAt.Add(62*time.Second), artifactDigest[:]); err != nil {
		t.Fatal(err)
	}

	liveGrant, expiredGrant := uuid.New(), uuid.New()
	tokenDigest := sha256.Sum256([]byte("one-time-download-token"))
	if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_log_export_grants_v1(
		id,export_id,scope_id,actor_user_id,session_id,token_sha256,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,statement_timestamp(),statement_timestamp()+INTERVAL '5 minutes'),
		($7,$2,$3,$4,$5,$8,statement_timestamp()-INTERVAL '10 minutes',statement_timestamp()-INTERVAL '5 minutes')`,
		liveGrant, exportID, identity.scopeID, identity.userID, credentialID, tokenDigest[:], expiredGrant,
		sha256.New().Sum(nil)); err != nil {
		t.Fatal(err)
	}
	var consumed uuid.UUID
	if err := pool.QueryRow(t.Context(), `UPDATE analytics_log_export_grants_v1
		SET consumed_at=clock_timestamp() WHERE id=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()
		RETURNING id`, liveGrant).Scan(&consumed); err != nil || consumed != liveGrant {
		t.Fatalf("consume grant=%s err=%v", consumed, err)
	}
	if err := pool.QueryRow(t.Context(), `UPDATE analytics_log_export_grants_v1
		SET consumed_at=clock_timestamp() WHERE id=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()
		RETURNING id`, liveGrant).Scan(&consumed); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("grant replay error=%v, want no rows", err)
	}
	if err := pool.QueryRow(t.Context(), `UPDATE analytics_log_export_grants_v1
		SET consumed_at=clock_timestamp() WHERE id=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()
		RETURNING id`, expiredGrant).Scan(&consumed); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expired grant error=%v, want no rows", err)
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM analytics_log_export_grants_v1 WHERE id=$1`, expiredGrant); err != nil {
		t.Fatalf("expired grant cleanup: %v", err)
	}
	assertAnalyticsLogExport132Code(t, migrateVersionIsolated(t.Context(), pool, "down", 132), "P1323")
}

func assertAnalyticsLogExport132Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("error=%v, want SQLSTATE %s", err, want)
	}
}
