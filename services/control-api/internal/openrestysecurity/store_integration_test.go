package openrestysecurity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type integrationAuthorizer struct{}

func (integrationAuthorizer) Authorize(_ context.Context, _ pgx.Tx, actor Actor, scopeID uuid.UUID, permission string) error {
	return validateActor(actor, scopeID, permission)
}

type integrationSealer struct{}

func (integrationSealer) Seal(_ context.Context, plaintext []byte) ([]byte, error) {
	return append([]byte("sealed:"), plaintext...), nil
}

func TestPatchOverridePersistsRemovedFieldsAcrossReadbackAndReplay(t *testing.T) {
	// 迁移头上的独立库/schema（模板克隆或现迁），不依赖 TEST_DATABASE_URL 本身已迁移。
	pool := databasetest.MigratedPool(t, nil)
	var relation *string
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass(current_schema()||'.openresty_security_configs')::text`).Scan(&relation); err != nil {
		t.Fatal(err)
	}
	if relation == nil {
		t.Fatal("migration 217 OpenResty security schema is missing")
	}

	tenantID, scopeID, userID, configID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	username := "waf_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	now := time.Date(2026, 8, 30, 12, 0, 0, 123456000, time.UTC)
	config := mustConfig(map[string]any{"cc_enable": true, "icmp_drop": true})
	encoded, digest, err := canonicalOverride(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, "WAF override test"); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,$4)`,
			userID, username, "WAF override operator", "integration-test-only"); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO openresty_security_configs(
			id,tenant_scope_id,scope_type,scope_id,document,document_sha256,key_override,secret_ciphertext,revision,created_at,updated_at
		) VALUES($1,$2,'region','华东',$3,$4,true,$5,1,$6,$6)`, configID, scopeID, encoded, digest[:], []byte("sealed:old-key"), now)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(pool, integrationAuthorizer{}, integrationSealer{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopePlatform,
		Permissions: []string{PermissionManage, PermissionRead}}
	request := PatchOverrideRequest{Actor: actor, TargetScopeID: scopeID, ID: configID, ExpectedRevision: 1,
		IdempotencyKey: "override-remove-1", RequestID: "override-remove-request-1",
		Patch: mustConfig(map[string]any{"cc_enable": false}), RemovedFields: []string{"icmp_drop", "key"}}
	result, err := store.PatchOverride(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || result.Document.Revision != 2 || result.Document.KeyConfigured || result.Document.KeyOverride ||
		string(result.Document.Config["cc_enable"]) != "false" {
		t.Fatalf("result=%+v", result)
	}
	if _, exists := result.Document.Config["icmp_drop"]; exists {
		t.Fatalf("removed field returned after PATCH: %v", result.Document.Config)
	}

	page, err := store.ListOverrides(t.Context(), ListOverridesRequest{Actor: actor, TargetScopeID: scopeID, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Revision != 2 || page.Items[0].KeyConfigured {
		t.Fatalf("readback=%+v", page)
	}
	if _, exists := page.Items[0].Config["icmp_drop"]; exists {
		t.Fatalf("removed field restored on readback: %v", page.Items[0].Config)
	}

	var activeHasRemoved, revisionHasRemoved, outboxHasRemoved, activeKeyOverride, activeKeyConfigured bool
	var activeRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT document ? 'icmp_drop',key_override,secret_ciphertext IS NOT NULL,revision
		FROM openresty_security_configs WHERE id=$1`, configID).
		Scan(&activeHasRemoved, &activeKeyOverride, &activeKeyConfigured, &activeRevision); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT document ? 'icmp_drop' FROM openresty_security_config_revisions
		WHERE tenant_scope_id=$1 AND config_id=$2 AND revision=2`, scopeID, configID).Scan(&revisionHasRemoved); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT document ? 'icmp_drop' FROM openresty_security_publication_outbox
		WHERE tenant_scope_id=$1 AND config_id=$2 AND revision=2`, scopeID, configID).Scan(&outboxHasRemoved); err != nil {
		t.Fatal(err)
	}
	if activeHasRemoved || revisionHasRemoved || outboxHasRemoved || activeKeyOverride || activeKeyConfigured || activeRevision != 2 {
		t.Fatalf("durable state active=%t revision=%t outbox=%t key_override=%t key_configured=%t active_revision=%d",
			activeHasRemoved, revisionHasRemoved, outboxHasRemoved, activeKeyOverride, activeKeyConfigured, activeRevision)
	}
	var auditCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2
		AND action='openresty_security.override.patch' AND request_id=$3`, scopeID, userID, request.RequestID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("audit count=%d", auditCount)
	}

	retry := request
	retry.RequestID = "override-remove-request-2"
	replay, err := store.PatchOverride(t.Context(), retry)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.Document.Revision != 2 {
		t.Fatalf("replay=%+v", replay)
	}
	var retryAuditCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2
		AND action='openresty_security.override.patch' AND request_id=$3`, scopeID, userID, retry.RequestID).Scan(&retryAuditCount); err != nil {
		t.Fatal(err)
	}
	if retryAuditCount != 0 {
		t.Fatalf("retry audit count=%d", retryAuditCount)
	}
	conflict := retry
	conflict.Patch = mustConfig(map[string]any{"cc_enable": true})
	if _, err := store.PatchOverride(t.Context(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict error=%v", err)
	}
}

func TestPatchGlobalConcurrentFirstWriteReturnsRevisionConflict(t *testing.T) {
	// 迁移头上的独立库/schema（模板克隆或现迁），不依赖 TEST_DATABASE_URL 本身已迁移。
	pool := databasetest.MigratedPool(t, nil)
	var relation *string
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass(current_schema()||'.openresty_security_configs')::text`).Scan(&relation); err != nil {
		t.Fatal(err)
	}
	if relation == nil {
		t.Fatal("migration 217 OpenResty security schema is missing")
	}

	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	username := "waf_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, "WAF global concurrency test"); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,$4)`,
			userID, username, "WAF global operator", "integration-test-only"); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 31, 12, 0, 0, 123456000, time.UTC)
	store, err := NewStore(pool, integrationAuthorizer{}, integrationSealer{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopePlatform,
		Permissions: []string{PermissionManage, PermissionRead}}

	blocker, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocker.Rollback(context.Background()) })
	if _, err := blocker.Exec(t.Context(), `LOCK TABLE openresty_security_configs IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}

	testContext, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	results := make(chan error, 2)
	for index := 1; index <= 2; index++ {
		go func(index int) {
			_, err := store.PatchGlobal(testContext, PatchGlobalRequest{Actor: actor, TargetScopeID: scopeID,
				ExpectedRevision: 0, IdempotencyKey: "global-first-" + string(rune('0'+index)),
				RequestID: "global-first-request-" + string(rune('0'+index)),
				Patch:     mustConfig(map[string]any{"cc_enable": false})})
			results <- err
		}(index)
	}

	waitDeadline := time.Now().Add(5 * time.Second)
	waiting := 0
	for time.Now().Before(waitDeadline) {
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_locks
			WHERE locktype='relation' AND relation='openresty_security_configs'::regclass
			  AND mode='RowExclusiveLock' AND NOT granted`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if waiting < 2 {
		t.Fatalf("waiting first writes=%d, want 2", waiting)
	}
	if err := blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}

	successes, conflicts := 0, 0
	for range 2 {
		select {
		case err := <-results:
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrRevisionConflict):
				conflicts++
			default:
				t.Fatalf("first-write error=%v", err)
			}
		case <-testContext.Done():
			t.Fatal(testContext.Err())
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT revision FROM openresty_security_configs
		WHERE tenant_scope_id=$1 AND scope_type='global' AND scope_id='0' AND deleted_at IS NULL`, scopeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if revision != 1 {
		t.Fatalf("global revision=%d", revision)
	}
}
