package certificateasset

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type certificateAuditRow struct {
	scopeID      uuid.UUID
	actorUserID  *uuid.UUID
	resourceType string
	resourceID   string
	result       string
	payload      map[string]any
	changes      []audit.Change // the changes column
}

func certificateAuditRows(t *testing.T, pool *pgxpool.Pool, action, requestID string) []certificateAuditRow {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT scope_id,actor_user_id,resource_type,resource_id,result,payload,changes
		FROM audit_events WHERE action=$1 AND request_id=$2 ORDER BY stream_position`, action, requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []certificateAuditRow
	for rows.Next() {
		var row certificateAuditRow
		var payload, changes []byte
		if err := rows.Scan(&row.scopeID, &row.actorUserID, &row.resourceType, &row.resourceID, &row.result, &payload, &changes); err != nil {
			t.Fatal(err)
		}
		row.changes = audittest.DecodeChanges(t, changes)
		if err := json.Unmarshal(payload, &row.payload); err != nil {
			t.Fatal(err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func onlyCertificateAudit(t *testing.T, pool *pgxpool.Pool, action, requestID string) certificateAuditRow {
	t.Helper()
	rows := certificateAuditRows(t, pool, action, requestID)
	if len(rows) != 1 {
		t.Fatalf("%s %s: %d audit events, want 1", action, requestID, len(rows))
	}
	return rows[0]
}

func auditChange(t *testing.T, row certificateAuditRow, field string) (any, any) {
	t.Helper()
	change, ok := audittest.Find(row.changes, field)
	if !ok {
		t.Fatalf("audit changes %v have no change of %s", row.changes, field)
	}
	return change.Before, change.After
}

// Certificate operations record who, from where, on what, the outcome and
// what changed (BATCH-PLUGIN rule 10); a refused operation is recorded too,
// in the actor's own scope.
func TestCertificateOperationsWriteAuditEvents(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "certificate-audit")
	other := createCertificateTenant(t, pool, "certificate-audit-other")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool), func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := audit.WithSourceIP(t.Context(), netip.MustParseAddr("203.0.113.7"))
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	imported, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "audit certificate", Source: SourceUploaded,
		CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
		IdempotencyKey: "audit-import", RequestID: "audit-import",
	})
	if err != nil {
		t.Fatal(err)
	}
	row := onlyCertificateAudit(t, pool, operationImport, "audit-import")
	if row.result != "success" || row.scopeID != tenant.actor.ScopeID || row.actorUserID == nil ||
		*row.actorUserID != tenant.actor.UserID || row.payload["ip"] != "203.0.113.7" ||
		row.resourceID != imported.Asset.ID.String() {
		t.Fatalf("import audit = %+v", row)
	}
	if before, after := auditChange(t, row, "version_id"); before != nil || after != imported.Version.ID.String() {
		t.Fatalf("import change = %v -> %v", before, after)
	}

	if _, err := store.Activate(ctx, tenant.actor, ActivateRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		ExpectedRevision: 1, IdempotencyKey: "audit-activate", RequestID: "audit-activate",
	}); err != nil {
		t.Fatal(err)
	}
	if before, after := auditChange(t, onlyCertificateAudit(t, pool, operationActivate, "audit-activate"),
		"active_version_id"); before != nil || after != imported.Version.ID.String() {
		t.Fatalf("activate change = %v -> %v", before, after)
	}
	if _, err := store.Bind(ctx, tenant.actor, BindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, AssetID: imported.Asset.ID,
		VersionID: imported.Version.ID, IdempotencyKey: "audit-bind", RequestID: "audit-bind",
	}); err != nil {
		t.Fatal(err)
	}
	bind := onlyCertificateAudit(t, pool, operationBind, "audit-bind")
	if before, after := auditChange(t, bind, "certificate_version_id"); bind.resourceID != tenant.siteOne.String() ||
		before != nil || after != imported.Version.ID.String() {
		t.Fatalf("bind audit = %+v", bind)
	}

	// Refused: the certificate does not cover the site's domain.
	if _, err := store.Bind(ctx, tenant.actor, BindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOutside, AssetID: imported.Asset.ID,
		VersionID: imported.Version.ID, IdempotencyKey: "audit-bind-uncovered", RequestID: "audit-bind-uncovered",
	}); err == nil {
		t.Fatal("uncovered bind succeeded")
	}
	refused := onlyCertificateAudit(t, pool, operationBind, "audit-bind-uncovered")
	if refused.result != "denied" || refused.payload["reason_code"] != "domain_not_covered" ||
		refused.payload["ip"] != "203.0.113.7" || refused.resourceID != tenant.siteOutside.String() {
		t.Fatalf("refused bind audit = %+v", refused)
	}
	// Refused: another tenant's actor; recorded in that actor's scope only.
	if _, err := store.Delete(ctx, other.actor, DeleteRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID,
		ExpectedRevision: 2, IdempotencyKey: "audit-cross-delete", RequestID: "audit-cross-delete",
	}); err == nil {
		t.Fatal("cross-tenant delete succeeded")
	}
	cross := onlyCertificateAudit(t, pool, operationDelete, "audit-cross-delete")
	if cross.result != "denied" || cross.scopeID != other.actor.ScopeID || cross.payload["reason_code"] != "permission_denied" ||
		cross.payload["target_scope_id"] != tenant.actor.ScopeID.String() {
		t.Fatalf("cross-tenant audit = %+v", cross)
	}

	if _, err := store.Unbind(ctx, tenant.actor, UnbindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, ExpectedRevision: 1,
		IdempotencyKey: "audit-unbind", RequestID: "audit-unbind",
	}); err != nil {
		t.Fatal(err)
	}
	if before, after := auditChange(t, onlyCertificateAudit(t, pool, operationUnbind, "audit-unbind"),
		"certificate_version_id"); before != imported.Version.ID.String() || after != nil {
		t.Fatalf("unbind change = %v -> %v", before, after)
	}
}

// A publication intent's terminal failure is recorded as the system's
// (worker) action with the requester in the payload; a retry is not. The
// success outcome needs a real rollout: certificatepublish
// TestRecoverPartialOfUnpublishSendsTheRemovalAgain asserts it.
func TestPublicationIntentOutcomeWritesAuditEvent(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "publication-intent-audit")
	store := newPublicationStore(t, pool, &testEnvelopeCipher{}, certificateTestClock)
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	createBoundPublicationAsset(t, store, tenant, pki, tenant.siteOne)
	config := DefaultPublicationIntentStoreConfig()
	config.MaxAttempts, config.RetryBase, config.RetryMaximum = 2, 10*time.Millisecond, 10*time.Millisecond
	config.Jitter = func(time.Duration) time.Duration { return 0 }
	intents, err := NewPublicationIntentStore(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	claim := func() PublicationIntentLease {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			lease, found, err := intents.ClaimPublicationIntent(context.Background(), "audit-worker")
			if err != nil {
				t.Fatal(err)
			}
			if found {
				return lease
			}
			if time.Now().After(deadline) {
				t.Fatal("no publication intent to claim")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	first := claim()
	if err := intents.FailPublicationIntent(context.Background(), first, "publication_unavailable"); err != nil {
		t.Fatal(err)
	}
	if rows := certificateAuditRows(t, pool, AuditPublicationComplete, first.RequestID); len(rows) != 0 {
		t.Fatalf("a retry wrote %d outcome audits", len(rows))
	}
	final := claim()
	if final.SiteID != first.SiteID || final.Attempt != 2 {
		t.Fatalf("second attempt claimed %s attempt %d", final.SiteID, final.Attempt)
	}
	if err := intents.PermanentlyFailPublicationIntent(context.Background(), final, "actor_unauthenticated"); err != nil {
		t.Fatal(err)
	}
	failed := onlyCertificateAudit(t, pool, AuditPublicationComplete, final.RequestID)
	if failed.result != "failure" || failed.actorUserID != nil || failed.scopeID != tenant.actor.ScopeID ||
		failed.resourceID != tenant.siteOne.String() || failed.payload["reason_code"] != "actor_unauthenticated" ||
		failed.payload["requested_by_user_id"] != tenant.actor.UserID.String() || failed.payload["worker_id"] != "audit-worker" {
		t.Fatalf("publication failure audit = %+v", failed)
	}
}
