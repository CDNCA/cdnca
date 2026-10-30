//go:build integration

package certificateexpiry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func openExpiryTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "certificate_expiry_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}

type expiryTenant struct{ scopeID, userID uuid.UUID }

func seedExpiryTenant(t *testing.T, pool *pgxpool.Pool) expiryTenant {
	t.Helper()
	tenant := expiryTenant{scopeID: uuid.New(), userID: uuid.New()}
	tenantID := uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name,status) VALUES($1,'Certificate expiry','active');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash,status) VALUES($3,$4,'Expiry','unused','active');
		INSERT INTO memberships(scope_id,user_id,status) VALUES($2,$3,'active');
		INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($5,$2,'tenant_owner','owner',true);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($5,'certificates.manage');
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($2,$3,$5)`,
		pgx.QueryExecModeSimpleProtocol, tenantID, tenant.scopeID, tenant.userID,
		"cert-expiry-"+strings.ReplaceAll(tenant.userID.String(), "-", "")[:16], uuid.New()); err != nil {
		t.Fatal(err)
	}
	return tenant
}

// seedActiveCertificate inserts an uploaded asset whose only version is active.
func seedActiveCertificate(t *testing.T, pool *pgxpool.Pool, tenant expiryTenant, notAfter time.Time) (uuid.UUID, uuid.UUID) {
	t.Helper()
	assetID, versionID := uuid.New(), uuid.New()
	seed := sha256.Sum256([]byte(versionID.String()))
	reference := "cert-expiry:" + versionID.String()
	createdAt := notAfter.Add(-90 * 24 * time.Hour)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO certificate_assets(tenant_scope_id,id,name,source,revision,created_by_scope_id,
				created_by_user_id,updated_by_scope_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,$2,$3,'uploaded',1,$1,$4,$1,$4,$5,$5)`,
				[]any{tenant.scopeID, assetID, "expiry-" + assetID.String(), tenant.userID, createdAt}},
			{`INSERT INTO certificate_asset_versions(tenant_scope_id,id,asset_id,actor_scope_id,version,initial_status,
				fingerprint_sha256,certificate_pem,public_key_sha256,private_key_reference,private_key_aad_sha256,sans,
				leaf_subject,serial_number,public_key_algorithm,public_key_bits,signature_algorithm,not_before,not_after,
				imported_by_user_id,imported_at)
				VALUES($1,$2,$3,$1,1,'default',$4,$5,$4,$6,$4,ARRAY['expiry.example.test'],'CN=expiry.example.test',
				$7,'ed25519',256,'ed25519',$8,$9,$10,$8)`,
				[]any{tenant.scopeID, versionID, assetID, seed[:], []byte("cert-expiry-test-certificate"), reference,
					fmt.Sprintf("%x", versionID[:]), createdAt, notAfter, tenant.userID}},
			{`INSERT INTO certificate_asset_private_key_envelope_facts(tenant_scope_id,asset_id,version_id,actor_scope_id,
				sequence,certificate_fingerprint_sha256,certificate_public_key_sha256,private_key_reference,aad_sha256,
				private_key_ciphertext,private_key_key_id,private_key_nonce,private_key_metadata,change_kind,request_id,
				changed_by_user_id,changed_at)
				VALUES($1,$2,$3,$1,1,$4,$4,$5,$4,$6,'cert-expiry-test-key',$7,'{}'::jsonb,'initial',$8,$9,$10)`,
				[]any{tenant.scopeID, assetID, versionID, seed[:], reference, bytes.Repeat([]byte{1}, 16),
					bytes.Repeat([]byte{2}, 12), "cert-expiry-envelope-" + versionID.String(), tenant.userID, createdAt}},
			{`UPDATE certificate_assets SET revision=2,updated_at=$3 WHERE tenant_scope_id=$1 AND id=$2`,
				[]any{tenant.scopeID, assetID, createdAt.Add(time.Minute)}},
			{`INSERT INTO certificate_asset_activation_facts(tenant_scope_id,asset_id,actor_scope_id,sequence,version_id,
				previous_version_id,expected_asset_revision,resulting_asset_revision,request_id,activated_by_user_id,activated_at)
				VALUES($1,$2,$1,1,$3,NULL,1,2,$4,$5,$6)`,
				[]any{tenant.scopeID, assetID, versionID, "cert-expiry-activate-" + versionID.String(), tenant.userID,
					createdAt.Add(time.Minute)}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return assetID, versionID
}

func expiryEvents(t *testing.T, pool *pgxpool.Pool, assetID uuid.UUID) []string {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT (payload->>'stage')||'/'||(payload->>'source')||'/'||subject_sequence
		FROM domain_event_outbox_368 WHERE event_type='io.cdnca.certificate.v1.expiry_reached' AND subject=$1
		ORDER BY subject_sequence`, "certificate_asset/"+assetID.String())
	if err != nil {
		t.Fatal(err)
	}
	values, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func expiryAudits(t *testing.T, pool *pgxpool.Pool, assetID uuid.UUID) []string {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT (payload->>'stage')||'/'||actor_kind||'/'||result
		FROM audit_events WHERE action=$1 AND resource_id=$2 ORDER BY stream_position`, AuditAction, assetID.String())
	if err != nil {
		t.Fatal(err)
	}
	values, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func TestScannerRecordsEachExpiryStageOnceWithEventAndAudit(t *testing.T) {
	pool := openExpiryTestDatabase(t)
	tenant := seedExpiryTenant(t, pool)
	notAfter := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	assetID, versionID := seedActiveCertificate(t, pool, tenant, notAfter)
	// A revoked and an inactive version are never reported.
	revokedAsset, revokedVersion := seedActiveCertificate(t, pool, tenant, notAfter)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		revokedAt := notAfter.Add(-60 * 24 * time.Hour)
		if _, err := tx.Exec(t.Context(), `UPDATE certificate_assets SET revision=3,updated_at=$3
			WHERE tenant_scope_id=$1 AND id=$2`, tenant.scopeID, revokedAsset, revokedAt); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_revocation_facts(tenant_scope_id,asset_id,
			version_id,actor_scope_id,expected_asset_revision,resulting_asset_revision,reason,request_id,
			revoked_by_user_id,revoked_at) VALUES($1,$2,$3,$1,2,3,'test','cert-expiry-revoke',$4,$5)`,
			tenant.scopeID, revokedAsset, revokedVersion, tenant.userID, revokedAt)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	clock := notAfter.Add(-40 * 24 * time.Hour)
	scanner, err := New(pool, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	notices, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	scanner.EnableNotices(notices)
	step := func(at time.Time, want int) {
		t.Helper()
		clock = at
		facts, err := scanner.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(facts) != want {
			t.Fatalf("at %s recorded %+v, want %d", at, facts, want)
		}
	}
	step(notAfter.Add(-40*24*time.Hour), 0)
	step(notAfter.Add(-20*24*time.Hour), 1)
	step(notAfter.Add(-19*24*time.Hour), 0) // still 30d: already recorded
	// Skipping straight past 7d records only the nearest stage reached.
	step(notAfter.Add(-3*24*time.Hour), 1)
	step(notAfter.Add(-2*time.Hour), 1)
	step(notAfter.Add(time.Hour), 1)
	step(notAfter.Add(48*time.Hour), 0)

	want := []string{"expiring_30d/uploaded/1", "expiring_7d/uploaded/2", "expiring_1d/uploaded/3", "expired/uploaded/4"}
	if got := expiryEvents(t, pool, assetID); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expiry events = %v, want %v", got, want)
	}
	if got := expiryAudits(t, pool, assetID); strings.Join(got, ",") !=
		"expiring_30d/system/success,expiring_7d/system/success,expiring_1d/system/success,expired/system/success" {
		t.Fatalf("expiry audits = %v", got)
	}
	if got := expiryEvents(t, pool, revokedAsset); len(got) != 0 {
		t.Fatalf("revoked certificate events = %v", got)
	}
	// Notification center: the asset has no owner, so the tenant's certificate
	// manager (the seeded user) gets one notice per stage.
	rows, err := pool.Query(t.Context(), `SELECT event_type||'@'||source_event_id FROM notification_events
		WHERE scope_id=$1 AND recipient_user_id=$2 AND source_event_id LIKE $3 ORDER BY created_at, event_type`,
		tenant.scopeID, tenant.userID, "certificate-expiry/"+versionID.String()+"/%")
	if err != nil {
		t.Fatal(err)
	}
	gotNotices, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	prefix := "certificate-expiry/" + versionID.String() + "/"
	wantNotices := []string{NoticeExpiring + "@" + prefix + "expiring_30d", NoticeExpiring + "@" + prefix + "expiring_7d",
		NoticeExpiring + "@" + prefix + "expiring_1d", NoticeExpired + "@" + prefix + "expired"}
	if strings.Join(gotNotices, ",") != strings.Join(wantNotices, ",") {
		t.Fatalf("expiry notices = %v, want %v", gotNotices, wantNotices)
	}
	var facts int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM certificate_expiry_facts_371 WHERE version_id=$1`,
		versionID).Scan(&facts); err != nil || facts != 4 {
		t.Fatalf("expiry facts = %d, %v", facts, err)
	}
	// Facts are append-only.
	if _, err := pool.Exec(t.Context(), `DELETE FROM certificate_expiry_facts_371 WHERE version_id=$1`, versionID); err == nil ||
		!strings.Contains(err.Error(), "P3711") {
		t.Fatalf("delete expiry fact error = %v", err)
	}
}

// Two control nodes scanning at once record each stage once.
func TestScannerIsIdempotentAcrossConcurrentScanners(t *testing.T) {
	pool := openExpiryTestDatabase(t)
	tenant := seedExpiryTenant(t, pool)
	notAfter := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	assets := make([]uuid.UUID, 0, 8)
	for range 8 {
		assetID, _ := seedActiveCertificate(t, pool, tenant, notAfter)
		assets = append(assets, assetID)
	}
	now := func() time.Time { return notAfter.Add(-5 * 24 * time.Hour) }
	var wait sync.WaitGroup
	totals := make([]int, 4)
	errs := make([]error, 4)
	for index := range totals {
		scanner, err := New(pool, now)
		if err != nil {
			t.Fatal(err)
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			facts, err := scanner.RunOnce(context.Background())
			totals[index], errs[index] = len(facts), err
		}()
	}
	wait.Wait()
	sum := 0
	for index := range totals {
		if errs[index] != nil {
			t.Fatal(errs[index])
		}
		sum += totals[index]
	}
	if sum != len(assets) {
		t.Fatalf("concurrent scanners recorded %d facts, want %d", sum, len(assets))
	}
	for _, assetID := range assets {
		if got := expiryEvents(t, pool, assetID); strings.Join(got, ",") != "expiring_7d/uploaded/1" {
			t.Fatalf("asset %s events = %v", assetID, got)
		}
	}
}
