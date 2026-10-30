package certificateasset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	controldatabase "github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errCertificateAuditInjected = errors.New("injected certificate audit failure")

type failingCertificateAuditor struct{}

func (failingCertificateAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return errCertificateAuditInjected
}

type certificateTenantFixture struct {
	actor       Actor
	siteOne     uuid.UUID
	siteTwo     uuid.UUID
	siteThree   uuid.UUID
	siteOutside uuid.UUID
}

type legacyCertificateRoleIDs struct {
	owner  uuid.UUID
	viewer uuid.UUID
}

func TestCertificateAssetMigrationUpDownUp(t *testing.T) {
	pool := isolatedCertificateAssetPool039(t)
	legacyRoleIDs := insertLegacyCertificateRoles(t, pool)
	if !certificateMigrationApplied(t, pool, 39) || !certificateRelationExists(t, pool, "certificate_asset_versions") {
		t.Fatal("migration 39 is not applied")
	}
	if err := applyCertificateAssetMigration(context.Background(), pool, "down"); err != nil {
		t.Fatalf("migration down: %v", err)
	}
	if certificateMigrationApplied(t, pool, 39) || certificateRelationExists(t, pool, "certificate_asset_versions") {
		t.Fatal("migration 39 objects or ledger remain after down")
	}
	assertLegacyCertificateAccess(t, pool, legacyRoleIDs)
	if !certificateRelationExists(t, pool, "certificate_orders") {
		t.Fatal("039 down removed the 005 certificate order relation")
	}
	if err := applyCertificateAssetMigration(context.Background(), pool, "up"); err != nil {
		t.Fatalf("migration re-up: %v", err)
	}
	if !certificateMigrationApplied(t, pool, 39) || !certificateRelationExists(t, pool, "certificate_asset_versions") {
		t.Fatal("migration 39 did not reapply")
	}
	assertLegacyCertificateAccess(t, pool, legacyRoleIDs)
}

func TestCertificateAssetMigrationDownRejectsLiveFactsAtomically(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "down-guard")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool),
		func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	result, err := store.Import(context.Background(), tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "回滚保护证书", Source: SourceUploaded,
		CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
		IdempotencyKey: "down-guard-import", RequestID: "request-down-guard-import",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(context.Background(), tenant.actor, ActivateRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: result.Asset.ID, VersionID: result.Version.ID,
		ExpectedRevision: 1, IdempotencyKey: "down-guard-activate", RequestID: "request-down-guard-activate",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bind(context.Background(), tenant.actor, BindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, AssetID: result.Asset.ID,
		VersionID: result.Version.ID, ExpectedRevision: 0,
		IdempotencyKey: "down-guard-bind", RequestID: "request-down-guard-bind",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Unbind(context.Background(), tenant.actor, UnbindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, ExpectedRevision: 1,
		IdempotencyKey: "down-guard-unbind", RequestID: "request-down-guard-unbind",
	}); err != nil {
		t.Fatal(err)
	}
	seedCertificateRevocation(t, pool, tenant.actor, result.Asset.ID, result.Version.ID, "回滚保护吊销")

	tables := []string{
		"certificate_assets", "certificate_asset_versions", "certificate_asset_activation_facts",
		"certificate_asset_private_key_envelope_facts", "certificate_asset_revocation_facts",
		"certificate_site_binding_facts", "certificate_asset_write_requests",
	}
	before := make(map[string]int, len(tables))
	for _, table := range tables {
		before[table] = certificateRowCount(t, pool, table)
		if before[table] == 0 {
			t.Fatalf("down guard fixture did not populate %s", table)
		}
	}
	err = applyCertificateAssetMigration(context.Background(), pool, "down")
	if err == nil || !strings.Contains(err.Error(), "cannot roll back certificate assets while 039 facts exist") {
		t.Fatalf("migration down with live facts error = %v", err)
	}
	if !certificateMigrationApplied(t, pool, 39) {
		t.Fatal("rejected 039 down changed the migration ledger")
	}
	for _, table := range tables {
		if !certificateRelationExists(t, pool, table) || certificateRowCount(t, pool, table) != before[table] {
			t.Fatalf("rejected 039 down changed %s", table)
		}
	}
}

func TestCertificateVersionRequiresEnvelopeAtCommitAndActivation(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "version-envelope-required")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool),
		func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	result, err := store.Import(context.Background(), tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "版本 envelope 完整性证书", Source: SourceUploaded,
		CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
		IdempotencyKey: "version-envelope-normal-import", RequestID: "version-envelope-normal-import",
	})
	if err != nil || certificateRowCountWhere(t, pool,
		"certificate_asset_private_key_envelope_facts", "version_id", result.Version.ID) != 1 {
		t.Fatalf("normal same-transaction import = %#v, error = %v", result, err)
	}

	orphanID := uuid.New()
	fingerprint := sha256.Sum256([]byte("orphan-version-commit"))
	aadDigest := sha256.Sum256([]byte("orphan-version-aad"))
	err = pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		return insertOrphanCertificateVersion(context.Background(), tx, tenant.actor.ScopeID,
			result.Asset.ID, result.Version.ID, orphanID, fingerprint, aadDigest)
	})
	if err == nil || !strings.Contains(err.Error(), "certificate asset version requires an initial private key envelope") {
		t.Fatalf("orphan version commit error = %v", err)
	}
	var orphanExists bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS(
		SELECT 1 FROM certificate_asset_versions WHERE tenant_scope_id=$1 AND id=$2
	)`, tenant.actor.ScopeID, orphanID).Scan(&orphanExists); err != nil {
		t.Fatal(err)
	}
	if orphanExists {
		t.Fatal("failed deferred envelope constraint left an orphan version")
	}

	activationOrphanID := uuid.New()
	activationFingerprint := sha256.Sum256([]byte("orphan-version-activation"))
	activationAAD := sha256.Sum256([]byte("orphan-version-activation-aad"))
	err = pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		ctx := context.Background()
		if err := insertOrphanCertificateVersion(ctx, tx, tenant.actor.ScopeID,
			result.Asset.ID, result.Version.ID, activationOrphanID, activationFingerprint, activationAAD); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE certificate_assets
			SET revision=2,updated_by_scope_id=$1,updated_by_user_id=$3,updated_at=$4
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=1`, tenant.actor.ScopeID,
			result.Asset.ID, tenant.actor.UserID, certificateTestNow); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO certificate_asset_activation_facts (
			tenant_scope_id,asset_id,sequence,version_id,previous_version_id,
			expected_asset_revision,resulting_asset_revision,request_id,actor_scope_id,activated_by_user_id,activated_at
		) VALUES($1,$2,1,$3,NULL,1,2,'orphan-version-activation',$1,$4,$5)`,
			tenant.actor.ScopeID, result.Asset.ID, activationOrphanID, tenant.actor.UserID, certificateTestNow)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "certificate activation requires an initial private key envelope") {
		t.Fatalf("envelope-less activation error = %v", err)
	}
	asset, versions, err := store.Get(context.Background(), tenant.actor,
		tenant.actor.ScopeID, result.Asset.ID)
	if err != nil || asset.Revision != 1 || len(versions) != 1 {
		t.Fatalf("envelope-less activation did not roll back asset=%#v versions=%#v error=%v",
			asset, versions, err)
	}
}

func insertOrphanCertificateVersion(
	ctx context.Context,
	tx pgx.Tx,
	tenantScopeID, assetID, templateVersionID, orphanVersionID uuid.UUID,
	fingerprint, aadDigest [32]byte,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO certificate_asset_versions (
		tenant_scope_id,id,asset_id,version,initial_status,fingerprint_sha256,certificate_pem,
		public_key_sha256,private_key_reference,private_key_aad_sha256,sans,leaf_subject,
		serial_number,public_key_algorithm,public_key_bits,signature_algorithm,not_before,not_after,
		acme_order_id,renewal_due_at,actor_scope_id,imported_by_user_id,imported_at
	) SELECT tenant_scope_id,$4,asset_id,2,'pending_activation',$5,certificate_pem,
		public_key_sha256,private_key_reference,$6,sans,leaf_subject,serial_number,
		public_key_algorithm,public_key_bits,signature_algorithm,not_before,not_after,
		NULL,NULL,actor_scope_id,imported_by_user_id,imported_at
	FROM certificate_asset_versions
	WHERE tenant_scope_id=$1 AND asset_id=$2 AND id=$3`, tenantScopeID, assetID,
		templateVersionID, orphanVersionID, fingerprint[:], aadDigest[:])
	return err
}

func TestCertificateActivationMigratesBindingsAtomicallyAndBoundRevokeFailsClosed(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "activation-binding-migration")
	cipher := &testEnvelopeCipher{}
	store, err := NewStoreWithDependencies(pool, cipher, audit.New(pool),
		func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pkiV1 := newCertificateFixture(t, leafOptions{domains: []string{"*.example.com"}})
	v1, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "原子绑定迁移证书", Source: SourceUploaded,
		CertificatePEM: pkiV1.certificatePEM, PrivateKeyPEM: pkiV1.privateKeyPEM,
		IdempotencyKey: "binding-migration-import-v1", RequestID: "binding-migration-import-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(ctx, tenant.actor, ActivateRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: v1.Asset.ID, VersionID: v1.Version.ID,
		ExpectedRevision: 1, IdempotencyKey: "binding-migration-activate-v1",
		RequestID: "binding-migration-activate-v1",
	}); err != nil {
		t.Fatal(err)
	}
	for index, siteID := range []uuid.UUID{tenant.siteOne, tenant.siteTwo} {
		if _, err := store.Bind(ctx, tenant.actor, BindRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteID: siteID, AssetID: v1.Asset.ID,
			VersionID: v1.Version.ID, ExpectedRevision: 0, Default: index == 0,
			IdempotencyKey: fmt.Sprintf("binding-migration-bind-v1-%d", index),
			RequestID:      fmt.Sprintf("binding-migration-bind-v1-%d", index),
		}); err != nil {
			t.Fatal(err)
		}
	}
	pkiV2 := newCertificateFixture(t, leafOptions{domains: []string{"*.example.com"}})
	assetID := v1.Asset.ID
	v2, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: &assetID, ExpectedRevision: 2,
		Name: v1.Asset.Name, Source: SourceUploaded, CertificatePEM: pkiV2.certificatePEM,
		PrivateKeyPEM: pkiV2.privateKeyPEM, IdempotencyKey: "binding-migration-import-v2",
		RequestID: "binding-migration-import-v2",
	})
	if err != nil {
		t.Fatal(err)
	}

	failingStore, err := NewStoreWithDependencies(pool, cipher, failingCertificateAuditor{},
		func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingStore.Activate(ctx, tenant.actor, ActivateRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: assetID, VersionID: v2.Version.ID,
		ExpectedRevision: 3, IdempotencyKey: "binding-migration-audit-failure",
		RequestID: "binding-migration-audit-failure",
	}); !errors.Is(err, errCertificateAuditInjected) {
		t.Fatalf("activation binding audit failure = %v", err)
	}
	asset, versions, err := store.Get(ctx, tenant.actor, tenant.actor.ScopeID, assetID)
	if err != nil || asset.Revision != 3 || versions[1].Status != StatusPendingActivation ||
		certificateWriteExists(t, pool, "binding-migration-audit-failure") {
		t.Fatalf("failed activation changed asset=%#v versions=%#v error=%v", asset, versions, err)
	}
	for _, siteID := range []uuid.UUID{tenant.siteOne, tenant.siteTwo} {
		binding, version, err := store.GetSiteBinding(ctx, tenant.actor, tenant.actor.ScopeID, siteID)
		if err != nil || binding.Revision != 1 || binding.VersionID != v1.Version.ID ||
			version.Status != StatusActive {
			t.Fatalf("failed activation changed site %s binding=%#v version=%#v error=%v",
				siteID, binding, version, err)
		}
	}

	activated, err := store.Activate(ctx, tenant.actor, ActivateRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: assetID, VersionID: v2.Version.ID,
		ExpectedRevision: 3, IdempotencyKey: "binding-migration-activate-v2",
		RequestID: "binding-migration-activate-v2",
	})
	if err != nil || activated.Status != StatusActive {
		t.Fatalf("activate v2 = %#v, error = %v", activated, err)
	}
	for _, siteID := range []uuid.UUID{tenant.siteOne, tenant.siteTwo} {
		binding, version, err := store.GetSiteBinding(ctx, tenant.actor, tenant.actor.ScopeID, siteID)
		if err != nil || binding.Revision != 2 || binding.VersionID != v2.Version.ID ||
			version.Status != StatusActive {
			t.Fatalf("activation did not migrate site %s binding=%#v version=%#v error=%v",
				siteID, binding, version, err)
		}
	}
	var migratedBindingAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND request_id=$3`, tenant.actor.ScopeID,
		operationBind, "binding-migration-activate-v2").Scan(&migratedBindingAudits); err != nil {
		t.Fatal(err)
	}
	if migratedBindingAudits != 2 {
		t.Fatalf("activation migrated binding audits = %d", migratedBindingAudits)
	}
}

func TestConcurrentActivateAndBindNeverLeavesUnsafeBinding(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "concurrent-activation-binding")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool),
		func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v1PKI := newCertificateFixture(t, leafOptions{domains: []string{"*.example.com"}})
	v1, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "并发激活绑定证书", Source: SourceUploaded,
		CertificatePEM: v1PKI.certificatePEM, PrivateKeyPEM: v1PKI.privateKeyPEM,
		IdempotencyKey: "concurrent-state-import-v1", RequestID: "concurrent-state-import-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(ctx, tenant.actor, ActivateRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: v1.Asset.ID, VersionID: v1.Version.ID,
		ExpectedRevision: 1, IdempotencyKey: "concurrent-state-activate-v1",
		RequestID: "concurrent-state-activate-v1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bind(ctx, tenant.actor, BindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, AssetID: v1.Asset.ID,
		VersionID: v1.Version.ID, ExpectedRevision: 0,
		IdempotencyKey: "concurrent-state-bind-v1", RequestID: "concurrent-state-bind-v1",
	}); err != nil {
		t.Fatal(err)
	}
	v2PKI := newCertificateFixture(t, leafOptions{domains: []string{"*.example.com"}})
	assetID := v1.Asset.ID
	v2, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: &assetID, ExpectedRevision: 2,
		Name: v1.Asset.Name, Source: SourceUploaded, CertificatePEM: v2PKI.certificatePEM,
		PrivateKeyPEM: v2PKI.privateKeyPEM, IdempotencyKey: "concurrent-state-import-v2",
		RequestID: "concurrent-state-import-v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	var activateErr, bindErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, activateErr = store.Activate(ctx, tenant.actor, ActivateRequest{
			TenantScopeID: tenant.actor.ScopeID, AssetID: assetID, VersionID: v2.Version.ID,
			ExpectedRevision: 3, IdempotencyKey: "concurrent-state-activate-v2",
			RequestID: "concurrent-state-activate-v2",
		})
	}()
	go func() {
		defer wait.Done()
		_, bindErr = store.Bind(ctx, tenant.actor, BindRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteTwo, AssetID: assetID,
			VersionID: v1.Version.ID, ExpectedRevision: 0,
			IdempotencyKey: "concurrent-state-bind-site-two",
			RequestID:      "concurrent-state-bind-site-two",
		})
	}()
	wait.Wait()
	if activateErr != nil {
		t.Fatalf("concurrent activation failed: %v (bind=%v)", activateErr, bindErr)
	}
	for _, siteID := range []uuid.UUID{tenant.siteOne, tenant.siteTwo} {
		binding, version, err := store.GetSiteBinding(ctx, tenant.actor, tenant.actor.ScopeID, siteID)
		if errors.Is(err, ErrNotFound) && siteID == tenant.siteTwo && errors.Is(bindErr, ErrInvalidTransition) {
			continue
		}
		if err != nil || binding.VersionID != v2.Version.ID || version.Status != StatusActive {
			t.Fatalf("unsafe concurrent binding site=%s binding=%#v version=%#v error=%v bind_error=%v",
				siteID, binding, version, err, bindErr)
		}
	}
}

func TestCertificateAssetPostgresLifecycleIsolationAndTamperProtection(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenantA := createCertificateTenant(t, pool, "tenant-a")
	tenantB := createCertificateTenant(t, pool, "tenant-b")
	cipher := &testEnvelopeCipher{}
	store, err := NewStoreWithDependencies(pool, cipher, audit.New(pool), func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	firstPKI := newCertificateFixture(t, leafOptions{domains: []string{
		"www.example.com", "api.example.com", "*.example.com",
	}})
	firstRequest := ImportRequest{
		TenantScopeID: tenantA.actor.ScopeID, Name: `主站 "证书" \ production`, Source: SourceUploaded,
		CertificatePEM: firstPKI.certificatePEM, PrivateKeyPEM: firstPKI.privateKeyPEM,
		IdempotencyKey: "import-main-v1", RequestID: "request-import-main-v1",
	}
	first, err := store.Import(ctx, tenantA.actor, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if first.Asset.Revision != 1 || first.Version.Version != 1 || first.Version.Status != StatusDefault {
		t.Fatalf("first import = %#v", first)
	}
	assertPrivateKeyAbsent(t, pool, first, firstPKI.privateKeyPEM)

	replayed, err := store.Import(ctx, tenantA.actor, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.Asset.ID != first.Asset.ID ||
		certificateRowCount(t, pool, "certificate_asset_versions") != 1 {
		t.Fatalf("idempotent replay = %#v", replayed)
	}
	conflicting := firstRequest
	conflicting.Name = "异载荷名称"
	if _, err := store.Import(ctx, tenantA.actor, conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different idempotency payload error = %v", err)
	}
	naturalDuplicate := firstRequest
	naturalDuplicate.IdempotencyKey = "import-natural-duplicate"
	naturalDuplicate.RequestID = "request-natural-duplicate"
	natural, err := store.Import(ctx, tenantA.actor, naturalDuplicate)
	if err != nil || !natural.Replayed || natural.Asset.ID != first.Asset.ID {
		t.Fatalf("natural duplicate = %#v, error = %v", natural, err)
	}
	unauthorized := insertCertificateUnauthorizedActor(t, pool, tenantA.actor.ScopeID)
	if _, _, err := store.Get(ctx, unauthorized, tenantA.actor.ScopeID, first.Asset.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("same-tenant unprivileged Get() error = %v", err)
	}

	crossTenantRequest := firstRequest
	crossTenantRequest.TenantScopeID = tenantB.actor.ScopeID
	crossTenantRequest.IdempotencyKey = "import-cross-tenant"
	crossTenantRequest.RequestID = "request-cross-tenant"
	crossTenant, err := store.Import(ctx, tenantB.actor, crossTenantRequest)
	if err != nil {
		t.Fatal(err)
	}
	if crossTenant.Asset.ID == first.Asset.ID || crossTenant.Version.FingerprintSHA256 != first.Version.FingerprintSHA256 {
		t.Fatalf("cross tenant fingerprint isolation failed: %#v", crossTenant)
	}
	if _, _, err := store.Get(ctx, tenantB.actor, tenantA.actor.ScopeID, first.Asset.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross tenant Get() error = %v", err)
	}
	testEnvelopeContextBindingAndRewrap(t, pool, store, cipher, tenantA, tenantB, first, crossTenant)
	assertConcurrentCertificateImportDeduplicates(t, store, tenantA)

	secondPKI := newCertificateFixture(t, leafOptions{domains: []string{
		"www.example.com", "api.example.com", "*.example.com",
	}})
	assetID := first.Asset.ID
	second, err := store.Import(ctx, tenantA.actor, ImportRequest{
		TenantScopeID: tenantA.actor.ScopeID, AssetID: &assetID, ExpectedRevision: 1,
		Name: first.Asset.Name, Source: SourceUploaded, CertificatePEM: secondPKI.certificatePEM,
		PrivateKeyPEM: secondPKI.privateKeyPEM, IdempotencyKey: "import-main-v2",
		RequestID: "request-import-main-v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Asset.Revision != 2 || second.Version.Version != 2 || second.Version.Status != StatusPendingActivation {
		t.Fatalf("second version = %#v", second)
	}
	_, firstEnvelope, _ := loadStoredEnvelope(t, pool, tenantA.actor.ScopeID,
		first.Asset.ID, first.Version.ID)
	secondEnvelopeContext, _, _ := loadStoredEnvelope(t, pool, tenantA.actor.ScopeID,
		second.Asset.ID, second.Version.ID)
	if plaintext, err := cipher.Unseal(ctx, PrivateKeyUnsealRequest{
		Context: secondEnvelopeContext, Envelope: firstEnvelope,
	}); err == nil {
		zeroBytes(plaintext)
		t.Fatal("cross-version envelope row substitution unexpectedly decrypted")
	}
	activeOne, err := store.Activate(ctx, tenantA.actor, ActivateRequest{
		TenantScopeID: tenantA.actor.ScopeID, AssetID: first.Asset.ID, VersionID: first.Version.ID,
		ExpectedRevision: 2, IdempotencyKey: "activate-main-v1", RequestID: "request-activate-main-v1",
	})
	if err != nil || activeOne.Status != StatusActive {
		t.Fatalf("activate first = %#v, error = %v", activeOne, err)
	}

	winners := 0
	conflicts := 0
	var raceErrors []error
	var raceMu sync.Mutex
	var wait sync.WaitGroup
	for index := 0; index < 12; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, activateErr := store.Activate(ctx, tenantA.actor, ActivateRequest{
				TenantScopeID: tenantA.actor.ScopeID, AssetID: first.Asset.ID, VersionID: second.Version.ID,
				ExpectedRevision: 3, IdempotencyKey: fmt.Sprintf("activate-race-%02d", index),
				RequestID: fmt.Sprintf("request-activate-race-%02d", index),
			})
			raceMu.Lock()
			defer raceMu.Unlock()
			switch {
			case activateErr == nil:
				winners++
			case errors.Is(activateErr, ErrRevisionConflict):
				conflicts++
			default:
				raceErrors = append(raceErrors, activateErr)
			}
		}(index)
	}
	wait.Wait()
	if winners != 1 || conflicts != 11 || len(raceErrors) != 0 {
		t.Fatalf("activation race winners=%d conflicts=%d errors=%v", winners, conflicts, raceErrors)
	}
	asset, versions, err := store.Get(ctx, tenantA.actor, tenantA.actor.ScopeID, first.Asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if asset.Revision != 4 || versions[0].Status != StatusSuperseded || versions[1].Status != StatusActive {
		t.Fatalf("post-race asset=%#v versions=%#v", asset, versions)
	}

	if _, err := store.Bind(ctx, tenantA.actor, BindRequest{
		TenantScopeID: tenantA.actor.ScopeID, SiteID: tenantA.siteOne, AssetID: first.Asset.ID,
		VersionID: first.Version.ID, ExpectedRevision: 0, IdempotencyKey: "bind-superseded",
		RequestID: "request-bind-superseded",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("bind superseded error = %v", err)
	}
	boundOne, err := store.Bind(ctx, tenantA.actor, BindRequest{
		TenantScopeID: tenantA.actor.ScopeID, SiteID: tenantA.siteOne, AssetID: first.Asset.ID,
		VersionID: second.Version.ID, ExpectedRevision: 0, Default: true,
		IdempotencyKey: "bind-site-one", RequestID: "request-bind-site-one",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bind(ctx, tenantA.actor, BindRequest{
		TenantScopeID: tenantA.actor.ScopeID, SiteID: tenantA.siteOne, AssetID: first.Asset.ID,
		VersionID: second.Version.ID, ExpectedRevision: 0,
		IdempotencyKey: "bind-site-one-stale", RequestID: "request-bind-site-one-stale",
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale binding CAS error = %v", err)
	}
	boundTwo, err := store.Bind(ctx, tenantA.actor, BindRequest{
		TenantScopeID: tenantA.actor.ScopeID, SiteID: tenantA.siteTwo, AssetID: first.Asset.ID,
		VersionID: second.Version.ID, ExpectedRevision: 0,
		IdempotencyKey: "bind-site-two", RequestID: "request-bind-site-two",
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := store.ListBindings(ctx, tenantA.actor, tenantA.actor.ScopeID, first.Asset.ID)
	if err != nil || len(bindings) != 2 || !boundOne.Bound || !boundTwo.Bound {
		t.Fatalf("multi-site bindings = %#v, error = %v", bindings, err)
	}
	resolvedBinding, resolvedVersion, err := store.GetSiteBinding(ctx, tenantA.actor,
		tenantA.actor.ScopeID, tenantA.siteOne)
	if err != nil || resolvedBinding.AssetID != first.Asset.ID || resolvedVersion.ID != second.Version.ID ||
		resolvedVersion.Status != StatusActive {
		t.Fatalf("resolved site binding = %#v version=%#v error=%v", resolvedBinding, resolvedVersion, err)
	}
	if _, err := store.Bind(ctx, tenantA.actor, BindRequest{
		TenantScopeID: tenantA.actor.ScopeID, SiteID: tenantA.siteOutside, AssetID: first.Asset.ID,
		VersionID: second.Version.ID, ExpectedRevision: 0,
		IdempotencyKey: "bind-uncovered", RequestID: "request-bind-uncovered",
	}); !errors.Is(err, ErrDomainNotCovered) {
		t.Fatalf("uncovered bind error = %v", err)
	}
	if _, err := store.Delete(ctx, tenantA.actor, DeleteRequest{
		TenantScopeID: tenantA.actor.ScopeID, AssetID: first.Asset.ID, ExpectedRevision: 4,
		IdempotencyKey: "delete-referenced", RequestID: "request-delete-referenced",
	}); !errors.Is(err, ErrReferenced) {
		t.Fatalf("referenced delete error = %v", err)
	}

	assertCertificateFactsImmutable(t, pool, tenantA, first, second)

	failingStore, err := NewStoreWithDependencies(pool, cipher, failingCertificateAuditor{}, func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	beforeBindingFacts := certificateRowCountWhere(t, pool, "certificate_site_binding_facts", "site_id", tenantA.siteThree)
	if _, err := failingStore.Bind(ctx, tenantA.actor, BindRequest{
		TenantScopeID: tenantA.actor.ScopeID, SiteID: tenantA.siteThree, AssetID: first.Asset.ID,
		VersionID: second.Version.ID, ExpectedRevision: 0,
		IdempotencyKey: "bind-audit-failure", RequestID: "request-bind-audit-failure",
	}); !errors.Is(err, errCertificateAuditInjected) {
		t.Fatalf("binding audit failure = %v", err)
	}
	if certificateRowCountWhere(t, pool, "certificate_site_binding_facts", "site_id", tenantA.siteThree) != beforeBindingFacts ||
		certificateWriteExists(t, pool, "bind-audit-failure") {
		t.Fatal("binding audit failure did not roll back fact and idempotency rows")
	}

	auditFailurePKI := newCertificateFixture(t, leafOptions{domains: []string{"audit.example.com"}})
	auditFailureAsset, err := store.Import(ctx, tenantA.actor, ImportRequest{
		TenantScopeID: tenantA.actor.ScopeID, Name: "审计回滚证书", Source: SourceUploaded,
		CertificatePEM: auditFailurePKI.certificatePEM, PrivateKeyPEM: auditFailurePKI.privateKeyPEM,
		IdempotencyKey: "import-audit-asset", RequestID: "request-import-audit-asset",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingStore.Activate(ctx, tenantA.actor, ActivateRequest{
		TenantScopeID: tenantA.actor.ScopeID, AssetID: auditFailureAsset.Asset.ID,
		VersionID: auditFailureAsset.Version.ID, ExpectedRevision: 1,
		IdempotencyKey: "activate-audit-failure", RequestID: "request-activate-audit-failure",
	}); !errors.Is(err, errCertificateAuditInjected) {
		t.Fatalf("activation audit failure = %v", err)
	}
	auditAsset, auditVersions, err := store.Get(ctx, tenantA.actor, tenantA.actor.ScopeID, auditFailureAsset.Asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if auditAsset.Revision != 1 || auditVersions[0].Status != StatusDefault ||
		certificateWriteExists(t, pool, "activate-audit-failure") {
		t.Fatal("activation audit failure did not roll back revision, fact, and idempotency rows")
	}

	if _, err := store.Unbind(ctx, tenantA.actor, UnbindRequest{
		TenantScopeID: tenantA.actor.ScopeID, SiteID: tenantA.siteOne, ExpectedRevision: boundOne.Revision,
		IdempotencyKey: "unbind-site-one", RequestID: "request-unbind-site-one",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Unbind(ctx, tenantA.actor, UnbindRequest{
		TenantScopeID: tenantA.actor.ScopeID, SiteID: tenantA.siteTwo, ExpectedRevision: boundTwo.Revision,
		IdempotencyKey: "unbind-site-two", RequestID: "request-unbind-site-two",
	}); err != nil {
		t.Fatal(err)
	}
	tombstones, err := store.ListBindings(ctx, tenantA.actor, tenantA.actor.ScopeID, first.Asset.ID)
	if err != nil || len(tombstones) != 2 {
		t.Fatalf("unbound binding tombstones = %#v, error = %v", tombstones, err)
	}
	for _, tombstone := range tombstones {
		if tombstone.Bound || tombstone.Revision != 2 {
			t.Fatalf("unbound binding tombstone = %#v", tombstone)
		}
	}
	deleted, err := store.Delete(ctx, tenantA.actor, DeleteRequest{
		TenantScopeID: tenantA.actor.ScopeID, AssetID: first.Asset.ID, ExpectedRevision: 4,
		IdempotencyKey: "delete-unbound", RequestID: "request-delete-unbound",
	})
	if err != nil {
		t.Fatal(err)
	}
	if deleted.DeletedAt == nil || deleted.Revision != 5 ||
		certificateRowCountWhere(t, pool, "certificate_asset_versions", "asset_id", first.Asset.ID) != 2 {
		t.Fatalf("tombstone delete = %#v", deleted)
	}
	activeAssets, err := store.List(ctx, tenantA.actor, tenantA.actor.ScopeID, false)
	if err != nil {
		t.Fatal(err)
	}
	allAssets, err := store.List(ctx, tenantA.actor, tenantA.actor.ScopeID, true)
	if err != nil {
		t.Fatal(err)
	}
	if certificateAssetListed(activeAssets, first.Asset.ID) || !certificateAssetListed(allAssets, first.Asset.ID) {
		t.Fatalf("tombstone list visibility active=%#v all=%#v", activeAssets, allAssets)
	}

	activeAuditAsset, err := store.Activate(ctx, tenantA.actor, ActivateRequest{
		TenantScopeID: tenantA.actor.ScopeID, AssetID: auditFailureAsset.Asset.ID,
		VersionID: auditFailureAsset.Version.ID, ExpectedRevision: 1,
		IdempotencyKey: "activate-audit-asset", RequestID: "request-activate-audit-asset",
	})
	if err != nil || activeAuditAsset.Status != StatusActive {
		t.Fatalf("activate audit asset = %#v, error = %v", activeAuditAsset, err)
	}
	seedCertificateRevocation(t, pool, tenantA.actor, auditFailureAsset.Asset.ID, auditFailureAsset.Version.ID, "人工吊销")
	_, revokedVersions, err := store.Get(ctx, tenantA.actor, tenantA.actor.ScopeID, auditFailureAsset.Asset.ID)
	if err != nil || len(revokedVersions) != 1 || revokedVersions[0].Status != StatusRevoked {
		t.Fatalf("revoked version = %#v, error = %v", revokedVersions, err)
	}
	assertCertificateSQLRejected(t, pool, "certificate revocation facts are immutable",
		`UPDATE certificate_asset_revocation_facts SET reason='forged' WHERE tenant_scope_id=$1 AND asset_id=$2`,
		tenantA.actor.ScopeID, auditFailureAsset.Asset.ID)
	assertCertificateSQLRejected(t, pool, "certificate revocation facts are immutable",
		`DELETE FROM certificate_asset_revocation_facts WHERE tenant_scope_id=$1 AND asset_id=$2`,
		tenantA.actor.ScopeID, auditFailureAsset.Asset.ID)
	assertCertificateSQLRejected(t, pool, "certificate revocation facts are immutable",
		`TRUNCATE certificate_asset_revocation_facts`)
	assertCertificateSQLFails(t, pool, `TRUNCATE certificate_asset_revocation_facts CASCADE`)

	advancedStore, err := NewStoreWithDependencies(pool, cipher, audit.New(pool), func() time.Time {
		return certificateTestNow.Add(91 * 24 * time.Hour)
	})
	if err != nil {
		t.Fatal(err)
	}
	_, tenantBVersions, err := advancedStore.Get(ctx, tenantB.actor, tenantB.actor.ScopeID, crossTenant.Asset.ID)
	if err != nil || tenantBVersions[0].Status != StatusExpired {
		t.Fatalf("expired projection = %#v, error = %v", tenantBVersions, err)
	}

	testACMERenewalProjection(t, pool, store, tenantA)
}

func testACMERenewalProjection(t *testing.T, pool *pgxpool.Pool, store *Store, tenant certificateTenantFixture) {
	t.Helper()
	ctx := context.Background()
	pki := newCertificateFixture(t, leafOptions{
		domains: []string{"acme.example.com", "*.acme.example.com"}, notAfter: certificateTestNow.Add(60 * 24 * time.Hour),
	})
	orderID := insertCertificateOrder(t, pool, tenant.actor,
		[]string{"acme.example.com", "*.acme.example.com"}, pki.leaf.NotAfter)
	result, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "ACME 自动续签证书", Source: SourceACME,
		ACMEOrderID: &orderID, CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
		IdempotencyKey: "import-acme", RequestID: "request-import-acme",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Version.ACMEOrderID == nil || *result.Version.ACMEOrderID != orderID || result.Version.RenewalDueAt == nil {
		t.Fatalf("ACME association = %#v", result.Version)
	}
	dueNow, err := store.ListRenewalDue(ctx, tenant.actor, tenant.actor.ScopeID, certificateTestNow)
	if err != nil || len(dueNow) != 0 {
		t.Fatalf("renewal due now = %#v, error = %v", dueNow, err)
	}
	dueLater, err := store.ListRenewalDue(ctx, tenant.actor, tenant.actor.ScopeID,
		certificateTestNow.Add(31*24*time.Hour))
	if err != nil || len(dueLater) != 1 || dueLater[0].ID != result.Version.ID || !dueLater[0].RenewalDue {
		t.Fatalf("renewal due later = %#v, error = %v", dueLater, err)
	}

	wrongPKI := newCertificateFixture(t, leafOptions{domains: []string{"issued.example.com"}})
	wrongOrder := insertCertificateOrder(t, pool, tenant.actor, []string{"other.example.com"}, wrongPKI.leaf.NotAfter)
	if _, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "错误 ACME 关联", Source: SourceACME,
		ACMEOrderID: &wrongOrder, CertificatePEM: wrongPKI.certificatePEM, PrivateKeyPEM: wrongPKI.privateKeyPEM,
		IdempotencyKey: "import-acme-mismatch", RequestID: "request-import-acme-mismatch",
	}); !errors.Is(err, ErrACMEOrderMismatch) {
		t.Fatalf("ACME mismatch error = %v", err)
	}

	opaquePKI := newCertificateFixture(t, leafOptions{
		domains: []string{"opaque-acme.example.com"}, notAfter: certificateTestNow.Add(89 * 24 * time.Hour),
	})
	opaqueOrder := insertCertificateOrder(t, pool, tenant.actor,
		[]string{"opaque-acme.example.com"}, opaquePKI.leaf.NotAfter)
	wrappedKeyMaterial := bytes.Repeat([]byte{0x5a}, 64)
	opaqueResult, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "ACME KMS 不可导出密钥证书", Source: SourceACME,
		ACMEOrderID: &opaqueOrder, CertificatePEM: opaquePKI.certificatePEM,
		OpaquePrivateKey: &OpaquePrivateKey{
			KeyReference:       "kms-signer:test-acme-key-v1",
			PublicKeySPKIDER:   append([]byte(nil), opaquePKI.leaf.RawSubjectPublicKeyInfo...),
			WrappedKeyMaterial: wrappedKeyMaterial,
			Metadata:           json.RawMessage(`{"provider":"test-kms","format":"wrapped-key-v1"}`),
		},
		IdempotencyKey: "import-acme-opaque", RequestID: "request-import-acme-opaque",
	})
	if err != nil || opaqueResult.Version.ACMEOrderID == nil || *opaqueResult.Version.ACMEOrderID != opaqueOrder {
		t.Fatalf("opaque ACME key import = %#v, error = %v", opaqueResult, err)
	}
	opaqueContext, opaqueEnvelope, _ := loadStoredEnvelope(t, pool, tenant.actor.ScopeID,
		opaqueResult.Asset.ID, opaqueResult.Version.ID)
	if opaqueContext.PrivateKeyReference != "kms-signer:test-acme-key-v1" || len(opaqueEnvelope.Ciphertext) < 16 {
		t.Fatal("opaque ACME key reference was not persisted through the envelope boundary")
	}
	if bytes.Contains(opaqueEnvelope.Ciphertext, wrappedKeyMaterial) {
		t.Fatal("opaque ACME wrapped key material was persisted without contextual sealing")
	}
	var opaqueAuditPayload string
	if err := pool.QueryRow(ctx, `SELECT payload::text FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND request_id=$3`, tenant.actor.ScopeID,
		operationImport, "request-import-acme-opaque").Scan(&opaqueAuditPayload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(opaqueAuditPayload, string(wrappedKeyMaterial)) {
		t.Fatal("opaque ACME wrapped key material leaked into audit")
	}
}

func assertConcurrentCertificateImportDeduplicates(t *testing.T, store *Store, tenant certificateTenantFixture) {
	t.Helper()
	pki := newCertificateFixture(t, leafOptions{domains: []string{"concurrent.example.com"}})
	const workers = 8
	ids := make([]uuid.UUID, workers)
	errorsByWorker := make([]error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			result, err := store.Import(context.Background(), tenant.actor, ImportRequest{
				TenantScopeID: tenant.actor.ScopeID, Name: "并发去重证书", Source: SourceUploaded,
				CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
				IdempotencyKey: fmt.Sprintf("concurrent-import-%d", index),
				RequestID:      fmt.Sprintf("request-concurrent-import-%d", index),
			})
			errorsByWorker[index] = err
			ids[index] = result.Asset.ID
		}(index)
	}
	wait.Wait()
	for index := range errorsByWorker {
		if errorsByWorker[index] != nil {
			t.Fatalf("concurrent import %d error = %v", index, errorsByWorker[index])
		}
		if ids[index] == uuid.Nil || ids[index] != ids[0] {
			t.Fatalf("concurrent import IDs = %#v", ids)
		}
	}
}

func testEnvelopeContextBindingAndRewrap(
	t *testing.T,
	pool *pgxpool.Pool,
	store *Store,
	cipher *testEnvelopeCipher,
	tenant, otherTenant certificateTenantFixture,
	result, crossTenant ImportResult,
) {
	t.Helper()
	ctx := context.Background()
	envelopeContext, initialEnvelope, sequence := loadStoredEnvelope(t, pool,
		tenant.actor.ScopeID, result.Asset.ID, result.Version.ID)
	if sequence != 1 {
		t.Fatalf("initial envelope sequence = %d", sequence)
	}
	for name, mutated := range map[string]PrivateKeyEnvelopeContext{
		"asset": func() PrivateKeyEnvelopeContext {
			value := envelopeContext
			value.AssetID = uuid.New()
			return value
		}(),
		"version": func() PrivateKeyEnvelopeContext {
			value := envelopeContext
			value.VersionID = uuid.New()
			return value
		}(),
		"tenant": func() PrivateKeyEnvelopeContext {
			value := envelopeContext
			value.TenantScopeID = otherTenant.actor.ScopeID
			return value
		}(),
	} {
		if plaintext, err := cipher.Unseal(ctx, PrivateKeyUnsealRequest{
			Context: mutated, Envelope: initialEnvelope,
		}); err == nil {
			zeroBytes(plaintext)
			t.Fatalf("%s envelope context substitution unexpectedly decrypted", name)
		}
	}
	crossContext, _, _ := loadStoredEnvelope(t, pool, otherTenant.actor.ScopeID,
		crossTenant.Asset.ID, crossTenant.Version.ID)
	if plaintext, err := cipher.Unseal(ctx, PrivateKeyUnsealRequest{
		Context: crossContext, Envelope: initialEnvelope,
	}); err == nil {
		zeroBytes(plaintext)
		t.Fatal("cross-tenant envelope row substitution unexpectedly decrypted")
	}

	mismatchedStore, err := NewStoreWithDependencies(pool,
		&mismatchedRewrapEnvelope{testEnvelopeCipher: cipher}, audit.New(pool),
		func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mismatchedStore.Rewrap(ctx, tenant.actor, RewrapRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: result.Asset.ID, VersionID: result.Version.ID,
		ExpectedEnvelopeSequence: 1, TargetKeyID: "test-kek-v2",
		IdempotencyKey: "rewrap-mismatched-key", RequestID: "request-rewrap-mismatched-key",
	}); !errors.Is(err, ErrEnvelopeUnavailable) {
		t.Fatalf("mismatched rewrap key error = %v", err)
	}
	if certificateRowCountWhere(t, pool, "certificate_asset_private_key_envelope_facts", "version_id", result.Version.ID) != 1 ||
		certificateWriteExists(t, pool, "rewrap-mismatched-key") {
		t.Fatal("mismatched rewrap key persisted envelope or idempotency facts")
	}

	_, versionsBefore, err := store.Get(ctx, tenant.actor, tenant.actor.ScopeID, result.Asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	publicFactsBefore, err := json.Marshal(versionsBefore)
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, err := store.Rewrap(ctx, tenant.actor, RewrapRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: result.Asset.ID, VersionID: result.Version.ID,
		ExpectedEnvelopeSequence: 1, TargetKeyID: "test-kek-v2",
		IdempotencyKey: "rewrap-main-v1", RequestID: "request-rewrap-main-v1",
	})
	if err != nil || rewrapped.Sequence != 2 {
		t.Fatalf("rewrap result = %#v, error = %v", rewrapped, err)
	}
	latestContext, latestEnvelope, latestSequence := loadStoredEnvelope(t, pool,
		tenant.actor.ScopeID, result.Asset.ID, result.Version.ID)
	if latestSequence != 2 || latestEnvelope.KeyID != "test-kek-v2" || latestContext != envelopeContext {
		t.Fatalf("latest rewrapped envelope context=%#v sequence=%d key=%q",
			latestContext, latestSequence, latestEnvelope.KeyID)
	}
	plaintext, err := cipher.Unseal(ctx, PrivateKeyUnsealRequest{
		Context: latestContext, Envelope: latestEnvelope,
	})
	if err != nil || len(plaintext) == 0 {
		t.Fatalf("rewrapped envelope cannot be unsealed under original context: %v", err)
	}
	zeroBytes(plaintext)
	_, versionsAfter, err := store.Get(ctx, tenant.actor, tenant.actor.ScopeID, result.Asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	publicFactsAfter, err := json.Marshal(versionsAfter)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publicFactsBefore, publicFactsAfter) ||
		certificateRowCountWhere(t, pool, "certificate_asset_private_key_envelope_facts", "version_id", result.Version.ID) != 2 {
		t.Fatal("rewrap changed certificate facts or failed to append its envelope fact")
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND request_id=$3`, tenant.actor.ScopeID,
		operationRewrap, "request-rewrap-main-v1").Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("rewrap audit count = %d", auditCount)
	}

	failingStore, err := NewStoreWithDependencies(pool, cipher, failingCertificateAuditor{},
		func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingStore.Rewrap(ctx, tenant.actor, RewrapRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: result.Asset.ID, VersionID: result.Version.ID,
		ExpectedEnvelopeSequence: 2, TargetKeyID: "test-kek-v3",
		IdempotencyKey: "rewrap-audit-failure", RequestID: "request-rewrap-audit-failure",
	}); !errors.Is(err, errCertificateAuditInjected) {
		t.Fatalf("rewrap audit failure = %v", err)
	}
	if certificateRowCountWhere(t, pool, "certificate_asset_private_key_envelope_facts", "version_id", result.Version.ID) != 2 ||
		certificateWriteExists(t, pool, "rewrap-audit-failure") {
		t.Fatal("rewrap audit failure did not roll back envelope and idempotency facts")
	}

	aadDigest, _ := envelopeContext.AADDigest()
	assertCertificateSQLRejected(t, pool, "certificate private key envelope context is invalid",
		`INSERT INTO certificate_asset_private_key_envelope_facts (
			tenant_scope_id,asset_id,version_id,sequence,certificate_fingerprint_sha256,
			certificate_public_key_sha256,private_key_reference,aad_sha256,private_key_ciphertext,
			private_key_key_id,private_key_nonce,private_key_metadata,change_kind,request_id,
			actor_scope_id,changed_by_user_id,changed_at
		) VALUES($1,$2,$3,2,$4,$5,$6,$7,$8,$9,$10,$11,'rewrap','forged-envelope-swap',$1,$12,$13)`,
		otherTenant.actor.ScopeID, crossTenant.Asset.ID, crossTenant.Version.ID,
		envelopeContext.CertificateFingerprintSHA256[:], envelopeContext.CertificatePublicKeySHA256[:],
		envelopeContext.PrivateKeyReference, aadDigest[:], initialEnvelope.Ciphertext,
		initialEnvelope.KeyID, initialEnvelope.Nonce, initialEnvelope.Metadata,
		otherTenant.actor.UserID, certificateTestNow)
}

type mismatchedRewrapEnvelope struct {
	*testEnvelopeCipher
}

func (enveloper *mismatchedRewrapEnvelope) Rewrap(
	ctx context.Context,
	request PrivateKeyRewrapRequest,
) (PrivateKeyEnvelope, error) {
	envelope, err := enveloper.testEnvelopeCipher.Rewrap(ctx, request)
	if err == nil {
		envelope.KeyID = "unexpected-kek"
	}
	return envelope, err
}

func certificateAssetListed(assets []Asset, target uuid.UUID) bool {
	for _, asset := range assets {
		if asset.ID == target {
			return true
		}
	}
	return false
}

func assertPrivateKeyAbsent(t *testing.T, pool *pgxpool.Pool, result ImportResult, privateKey []byte) {
	t.Helper()
	var ciphertext, nonce, certificatePEM []byte
	var keyID, metadata string
	var aadDigest []byte
	if err := pool.QueryRow(context.Background(), `SELECT envelope.private_key_ciphertext,
		envelope.private_key_nonce,envelope.private_key_key_id,envelope.private_key_metadata::text,
		version.certificate_pem,envelope.aad_sha256
		FROM certificate_asset_versions version
		JOIN certificate_asset_private_key_envelope_facts envelope
		  ON envelope.tenant_scope_id=version.tenant_scope_id
		 AND envelope.asset_id=version.asset_id AND envelope.version_id=version.id
		WHERE version.tenant_scope_id=$1 AND version.id=$2
		ORDER BY envelope.sequence DESC LIMIT 1`,
		result.Asset.TenantScopeID, result.Version.ID).Scan(
		&ciphertext, &nonce, &keyID, &metadata, &certificatePEM, &aadDigest); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) < 16 || len(nonce) < 8 || keyID == "" || metadata == "" || len(certificatePEM) == 0 ||
		len(aadDigest) != 32 || bytes.Contains(ciphertext, privateKey) ||
		bytes.Contains(certificatePEM, []byte("PRIVATE KEY")) {
		t.Fatal("database private key envelope/public certificate separation failed")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, privateKey) {
		t.Fatal("returned certificate model leaked private key")
	}
	var auditPayload string
	if err := pool.QueryRow(context.Background(), `SELECT payload::text FROM audit_events
		WHERE scope_id=$1 AND action=$2 ORDER BY stream_position DESC LIMIT 1`,
		result.Asset.TenantScopeID, operationImport).Scan(&auditPayload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditPayload, "PRIVATE KEY") || strings.Contains(auditPayload, string(privateKey)) {
		t.Fatal("audit payload leaked private key")
	}
}

func loadStoredEnvelope(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantScopeID, assetID, versionID uuid.UUID,
) (PrivateKeyEnvelopeContext, PrivateKeyEnvelope, int64) {
	t.Helper()
	var version, sequence int64
	var fingerprint, publicKeyDigest, storedAADDigest []byte
	var keyReference string
	var envelope PrivateKeyEnvelope
	err := pool.QueryRow(context.Background(), `SELECT version.version,version.fingerprint_sha256,
		version.public_key_sha256,version.private_key_reference,version.private_key_aad_sha256,
		envelope.sequence,envelope.private_key_ciphertext,envelope.private_key_key_id,
		envelope.private_key_nonce,envelope.private_key_metadata
		FROM certificate_asset_versions version
		JOIN certificate_asset_private_key_envelope_facts envelope
		  ON envelope.tenant_scope_id=version.tenant_scope_id
		 AND envelope.asset_id=version.asset_id AND envelope.version_id=version.id
		WHERE version.tenant_scope_id=$1 AND version.asset_id=$2 AND version.id=$3
		ORDER BY envelope.sequence DESC LIMIT 1`, tenantScopeID, assetID, versionID).Scan(
		&version, &fingerprint, &publicKeyDigest, &keyReference, &storedAADDigest, &sequence,
		&envelope.Ciphertext, &envelope.KeyID, &envelope.Nonce, &envelope.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(fingerprint) != 32 || len(publicKeyDigest) != 32 || len(storedAADDigest) != 32 {
		t.Fatal("stored certificate private-key envelope context digest is invalid")
	}
	var fingerprintArray, publicKeyArray [32]byte
	copy(fingerprintArray[:], fingerprint)
	copy(publicKeyArray[:], publicKeyDigest)
	envelopeContext := PrivateKeyEnvelopeContext{
		TenantScopeID: tenantScopeID, AssetID: assetID, VersionID: versionID, Version: version,
		CertificateFingerprintSHA256: fingerprintArray,
		CertificatePublicKeySHA256:   publicKeyArray, PrivateKeyReference: keyReference,
	}
	computed, err := envelopeContext.AADDigest()
	if err != nil || !bytes.Equal(computed[:], storedAADDigest) {
		t.Fatal("stored certificate private-key envelope AAD digest does not match its row context")
	}
	return envelopeContext, envelope, sequence
}

func assertCertificateFactsImmutable(
	t *testing.T,
	pool *pgxpool.Pool,
	tenant certificateTenantFixture,
	first, second ImportResult,
) {
	t.Helper()
	assertCertificateSQLRejected(t, pool, "certificate asset revision must advance by one",
		`UPDATE certificate_assets SET name='forged' WHERE tenant_scope_id=$1 AND id=$2`,
		tenant.actor.ScopeID, first.Asset.ID)
	assertCertificateSQLRejected(t, pool, "certificate assets cannot be physically removed",
		`DELETE FROM certificate_assets WHERE tenant_scope_id=$1 AND id=$2`,
		tenant.actor.ScopeID, first.Asset.ID)
	assertCertificateSQLFails(t, pool, `TRUNCATE certificate_assets`)
	assertCertificateSQLFails(t, pool, `TRUNCATE certificate_assets CASCADE`)
	assertCertificateSQLRejected(t, pool, "certificate asset versions are immutable",
		`UPDATE certificate_asset_versions SET leaf_subject='forged' WHERE tenant_scope_id=$1 AND id=$2`,
		tenant.actor.ScopeID, first.Version.ID)
	assertCertificateSQLRejected(t, pool, "certificate asset versions are immutable",
		`DELETE FROM certificate_asset_versions WHERE tenant_scope_id=$1 AND id=$2`,
		tenant.actor.ScopeID, first.Version.ID)
	assertCertificateSQLFails(t, pool, `TRUNCATE certificate_asset_versions`)
	assertCertificateSQLFails(t, pool, `TRUNCATE certificate_asset_versions CASCADE`)
	assertCertificateSQLRejected(t, pool, "certificate private key envelope facts are immutable",
		`UPDATE certificate_asset_private_key_envelope_facts SET private_key_key_id='forged'
		 WHERE tenant_scope_id=$1 AND version_id=$2`, tenant.actor.ScopeID, first.Version.ID)
	assertCertificateSQLRejected(t, pool, "certificate private key envelope facts are immutable",
		`DELETE FROM certificate_asset_private_key_envelope_facts
		 WHERE tenant_scope_id=$1 AND version_id=$2`, tenant.actor.ScopeID, first.Version.ID)
	assertCertificateSQLRejected(t, pool, "certificate private key envelope facts are immutable",
		`TRUNCATE certificate_asset_private_key_envelope_facts`)
	assertCertificateSQLFails(t, pool, `TRUNCATE certificate_asset_private_key_envelope_facts CASCADE`)
	assertCertificateSQLRejected(t, pool, "certificate activation facts are immutable",
		`UPDATE certificate_asset_activation_facts SET request_id='forged' WHERE tenant_scope_id=$1 AND asset_id=$2`,
		tenant.actor.ScopeID, first.Asset.ID)
	assertCertificateSQLRejected(t, pool, "certificate activation facts are immutable",
		`DELETE FROM certificate_asset_activation_facts WHERE tenant_scope_id=$1 AND asset_id=$2`,
		tenant.actor.ScopeID, first.Asset.ID)
	assertCertificateSQLRejected(t, pool, "certificate activation facts are immutable",
		`TRUNCATE certificate_asset_activation_facts`)
	assertCertificateSQLFails(t, pool, `TRUNCATE certificate_asset_activation_facts CASCADE`)
	assertCertificateSQLRejected(t, pool, "certificate site binding facts are immutable",
		`UPDATE certificate_site_binding_facts SET version_id=$3 WHERE tenant_scope_id=$1 AND site_id=$2`,
		tenant.actor.ScopeID, tenant.siteOne, second.Version.ID)
	assertCertificateSQLRejected(t, pool, "certificate site binding facts are immutable",
		`DELETE FROM certificate_site_binding_facts WHERE tenant_scope_id=$1 AND site_id=$2`,
		tenant.actor.ScopeID, tenant.siteOne)
	// Publication intents (116) reference binding facts: a plain TRUNCATE is
	// refused by that foreign key before the immutability trigger runs.
	assertCertificateSQLFails(t, pool, `TRUNCATE certificate_site_binding_facts`)
	assertCertificateSQLFails(t, pool, `TRUNCATE certificate_site_binding_facts CASCADE`)
	assertCertificateSQLRejected(t, pool, "completed certificate asset write request is immutable",
		`UPDATE certificate_asset_write_requests SET response_body='{"forged":true}'
		 WHERE tenant_scope_id=$1 AND idempotency_key='import-main-v1'`, tenant.actor.ScopeID)
	assertCertificateSQLRejected(t, pool, "certificate asset write requests cannot be deleted",
		`DELETE FROM certificate_asset_write_requests
		 WHERE tenant_scope_id=$1 AND idempotency_key='import-main-v1'`, tenant.actor.ScopeID)
	assertCertificateSQLRejected(t, pool, "certificate asset write requests cannot be truncated",
		`TRUNCATE certificate_asset_write_requests`)
	assertCertificateSQLFails(t, pool, `TRUNCATE certificate_asset_write_requests CASCADE`)
	assertCertificateWriteRequestLifecycle(t, pool, tenant.actor, first.Asset.ID)
}

func assertCertificateWriteRequestLifecycle(
	t *testing.T,
	pool *pgxpool.Pool,
	actor Actor,
	resourceID uuid.UUID,
) {
	t.Helper()
	requestID := uuid.New()
	createdAt := certificateTestNow.Add(time.Minute)
	if _, err := pool.Exec(context.Background(), `INSERT INTO certificate_asset_write_requests (
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at
	) VALUES($1,$2,$2,$3,'certificate.asset.rewrap','direct-write-lifecycle',$4,$5)`,
		requestID, actor.ScopeID, actor.UserID, bytes.Repeat([]byte{0x31}, 32), createdAt); err != nil {
		t.Fatal(err)
	}
	assertCertificateSQLRejected(t, pool, "certificate asset write request must complete atomically",
		`UPDATE certificate_asset_write_requests SET resource_id=$2 WHERE id=$1`, requestID, resourceID)
	if _, err := pool.Exec(context.Background(), `UPDATE certificate_asset_write_requests
		SET resource_id=$2,response_body='{"completed":true}',completed_at=$3 WHERE id=$1`,
		requestID, resourceID, createdAt.Add(time.Second)); err != nil {
		t.Fatalf("complete certificate write request once: %v", err)
	}
	var completed bool
	if err := pool.QueryRow(context.Background(), `SELECT completed_at IS NOT NULL AND
		resource_id=$2 AND response_body='{"completed":true}'::jsonb
		FROM certificate_asset_write_requests WHERE id=$1`, requestID, resourceID).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if !completed {
		t.Fatal("certificate write request did not complete atomically")
	}
	assertCertificateSQLRejected(t, pool, "completed certificate asset write request is immutable",
		`UPDATE certificate_asset_write_requests SET response_body='{"second":true}' WHERE id=$1`, requestID)
	assertCertificateSQLRejected(t, pool, "certificate asset write requests cannot be deleted",
		`DELETE FROM certificate_asset_write_requests WHERE id=$1`, requestID)
	assertCertificateSQLRejected(t, pool, "certificate asset write request must start unfinished",
		`INSERT INTO certificate_asset_write_requests (
			id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			resource_id,response_body,created_at,completed_at
		) VALUES($1,$2,$2,$3,'certificate.asset.rewrap','direct-write-completed-insert',$4,$5,
			'{"forged":true}',$6,$6)`, uuid.New(), actor.ScopeID, actor.UserID,
		bytes.Repeat([]byte{0x32}, 32), resourceID, createdAt)
}

func createCertificateTenant(t *testing.T, pool *pgxpool.Pool, name string) certificateTenantFixture {
	t.Helper()
	tenantID := uuid.New()
	scopeID := uuid.New()
	userID := uuid.New()
	roleID := uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$3,'test-password-hash')`, userID, name+"-owner", name+" owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	// Custom roles go through RBAC facts at head; the system owner role is a
	// plain row, as the tenant bootstrap writes it.
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'tenant_owner','certificate test owner',true)`, roleID, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'certificates.read'),($1,'certificates.manage')`, roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
	actor := Actor{
		UserID: userID, ScopeID: scopeID, ScopeKind: ScopeTenant,
		SessionID: insertCertificateActorSession(t, pool, scopeID, userID),
	}
	return certificateTenantFixture{
		actor:       actor,
		siteOne:     insertCertificateSite(t, pool, actor, "www.example.com"),
		siteTwo:     insertCertificateSite(t, pool, actor, "api.example.com"),
		siteThree:   insertCertificateSite(t, pool, actor, "shop.example.com"),
		siteOutside: insertCertificateSite(t, pool, actor, "outside.example.net"),
	}
}

func insertLegacyCertificateRoles(t *testing.T, pool *pgxpool.Pool) legacyCertificateRoleIDs {
	t.Helper()
	tenantID := uuid.New()
	scopeID := uuid.New()
	roles := legacyCertificateRoleIDs{owner: uuid.New(), viewer: uuid.New()}
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'legacy certificate roles')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
		($1,$3,'tenant_owner','legacy tenant owner',true),
		($2,$3,'tenant_viewer','legacy tenant viewer',true)`, roles.owner, roles.viewer, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES
		($1,'certificates.read'),($1,'certificates.manage'),($2,'certificates.read')`,
		roles.owner, roles.viewer); err != nil {
		t.Fatal(err)
	}
	return roles
}

func assertLegacyCertificateAccess(t *testing.T, pool *pgxpool.Pool, roles legacyCertificateRoleIDs) {
	t.Helper()
	var permissionCount, ownerCount, viewerReadCount, viewerManageCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM permissions
		WHERE name IN ('certificates.read','certificates.manage')`).Scan(&permissionCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM role_permissions
		WHERE role_id=$1 AND permission_name IN ('certificates.read','certificates.manage')`,
		roles.owner).Scan(&ownerCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM role_permissions
		WHERE role_id=$1 AND permission_name='certificates.read'`, roles.viewer).Scan(&viewerReadCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM role_permissions
		WHERE role_id=$1 AND permission_name='certificates.manage'`, roles.viewer).Scan(&viewerManageCount); err != nil {
		t.Fatal(err)
	}
	if permissionCount != 2 || ownerCount != 2 || viewerReadCount != 1 || viewerManageCount != 0 {
		t.Fatalf("legacy certificate access changed: permissions=%d owner=%d viewer_read=%d viewer_manage=%d",
			permissionCount, ownerCount, viewerReadCount, viewerManageCount)
	}
}

func insertCertificateUnauthorizedActor(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) Actor {
	t.Helper()
	userID := uuid.New()
	username := "certificate-unprivileged-" + strings.ReplaceAll(userID.String(), "-", "")
	if _, err := pool.Exec(context.Background(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'unprivileged certificate user','test-password-hash')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
		scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return Actor{
		UserID: userID, ScopeID: scopeID, ScopeKind: ScopeTenant,
		SessionID: insertCertificateActorSession(t, pool, scopeID, userID),
	}
}

func insertCertificateActorSession(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID, userID uuid.UUID,
) uuid.UUID {
	t.Helper()
	sessionID, familyID := uuid.New(), uuid.New()
	digest := sha256.Sum256(sessionID[:])
	now := time.Now().UTC()
	if _, err := pool.Exec(context.Background(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, familyID, userID, scopeID,
		digest[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return sessionID
}

func insertCertificateSite(t *testing.T, pool *pgxpool.Pool, actor Actor, domain string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `INSERT INTO sites (
			id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id
		) VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2),$2,$3,$4,
			ARRAY['origin.example.test:443'],ARRAY['origin.example.test'],$3,$3)`,
			id, actor.ScopeID, actor.UserID, domain); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, id); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO site_origins(site_id,position,host,port)
			VALUES($1,1,'origin.example.test',443)`, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// insertCertificateOrder seeds an issued ACME order covering domains until
// notAfter. Issuance provenance (asset, ACME operation and key facts) belongs
// to the ACME runtime (migration 048, acmeworker tests); the certificate store
// only reads domains, status and not_after, so the seed bypasses the runtime
// trigger and the asset reference (session_replication_role=replica).
func insertCertificateOrder(t *testing.T, pool *pgxpool.Pool, actor Actor, domains []string, notAfter time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	digest := bytes.Repeat([]byte{0x48}, 32)
	seedCertificateOrderFact(t, pool, `INSERT INTO certificate_orders (
		id,scope_id,domains,challenge_type,status,auto_renew,not_after,created_by_user_id,updated_by_user_id,
		issued_asset_id,issued_asset_version_id,issued_at,leaf_fingerprint_sha256,leaf_spki_sha256,
		acme_directory_url,acme_account_key_ref,certificate_key_ref,external_order_url,
		authorization_urls_sha256,certificate_url
	) VALUES($1,$2,$3,'http-01','issued',true,$4,$5,$5,$6,$7,$8,$9,$9,
		'https://ca.example.test/directory','account-key','certificate-key','https://ca.example.test/order',
		$9,'https://ca.example.test/certificate')`, id, actor.ScopeID, domains, notAfter, actor.UserID,
		uuid.New(), uuid.New(), certificateTestNow.Add(-time.Hour), digest)
	return id
}

// seedCertificateOrderFact runs one statement on certificate_orders without
// its ACME runtime trigger and foreign keys: test-only state the runtime
// would have reached through its own operation facts.
// seedCertificateRevocation writes a historical revocation fact the way the
// retired Store.Revoke did (fix-certmenu, user 10-28: the asset revoke API is
// gone, revoked versions stay readable): advance the asset revision by one
// and record the fact at that revision.
func seedCertificateRevocation(t *testing.T, pool *pgxpool.Pool, actor Actor, assetID, versionID uuid.UUID, reason string) {
	t.Helper()
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		var revision int64
		if err := tx.QueryRow(context.Background(), `UPDATE certificate_assets SET revision=revision+1
			WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL RETURNING revision`,
			actor.ScopeID, assetID).Scan(&revision); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO certificate_asset_revocation_facts(
			tenant_scope_id,asset_id,version_id,expected_asset_revision,resulting_asset_revision,
			reason,request_id,actor_scope_id,revoked_by_user_id,revoked_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$1,$8,$9)`, actor.ScopeID, assetID, versionID, revision-1, revision,
			reason, "seed-revoke-"+versionID.String(), actor.UserID, certificateTestNow)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func seedCertificateOrderFact(t *testing.T, pool *pgxpool.Pool, statement string, arguments ...any) {
	t.Helper()
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		for _, setup := range []string{`SET LOCAL session_replication_role=replica`,
			`ALTER TABLE certificate_orders DISABLE TRIGGER certificate_orders_runtime_048`} {
			if _, err := tx.Exec(context.Background(), setup); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(context.Background(), statement, arguments...); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `ALTER TABLE certificate_orders ENABLE ALWAYS TRIGGER certificate_orders_runtime_048`)
		return err
	}); err != nil {
		t.Fatalf("seed certificate order: %v", err)
	}
}

// advanceCertificateOrder moves an order through the runtime's legal
// transitions (pending -> validating -> issuing, or to failed).
func advanceCertificateOrder(t *testing.T, query interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, orderID uuid.UUID, statuses ...string) {
	t.Helper()
	for _, status := range statuses {
		if _, err := query.Exec(context.Background(), `UPDATE certificate_orders
			SET status=$2,revision=revision+1,failure_code=CASE WHEN $2='failed' THEN 'test_failure' END
			WHERE id=$1`, orderID, status); err != nil {
			t.Fatalf("advance certificate order to %s: %v", status, err)
		}
	}
}

func assertCertificateSQLRejected(t *testing.T, pool *pgxpool.Pool, message, query string, arguments ...any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), query, arguments...)
	if err == nil || !strings.Contains(err.Error(), message) {
		t.Fatalf("SQL mutation error = %v, want message %q", err, message)
	}
}

func assertCertificateSQLFails(t *testing.T, pool *pgxpool.Pool, query string, arguments ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), query, arguments...); err == nil {
		t.Fatalf("SQL mutation unexpectedly succeeded: %s", query)
	}
}

func certificateRowCount(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	allowed := map[string]bool{
		"certificate_assets": true, "certificate_asset_versions": true,
		"certificate_asset_private_key_envelope_facts": true,
		"certificate_asset_activation_facts":           true,
		"certificate_asset_revocation_facts":           true,
		"certificate_site_binding_facts":               true,
		"certificate_asset_write_requests":             true,
	}
	if !allowed[table] {
		t.Fatalf("refusing count for unexpected table %q", table)
	}
	var count int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func certificateRowCountWhere(t *testing.T, pool *pgxpool.Pool, table, column string, value uuid.UUID) int {
	t.Helper()
	allowed := map[string]map[string]bool{
		"certificate_asset_versions":                   {"asset_id": true},
		"certificate_asset_private_key_envelope_facts": {"version_id": true},
		"certificate_site_binding_facts":               {"site_id": true},
	}
	if !allowed[table][column] {
		t.Fatalf("refusing count for unexpected %s.%s", table, column)
	}
	var count int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table+" WHERE "+column+"=$1", value).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func certificateWriteExists(t *testing.T, pool *pgxpool.Pool, key string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS(
		SELECT 1 FROM certificate_asset_write_requests WHERE idempotency_key=$1
	)`, key).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func applyCertificateAssetMigration(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	name := "039_certificate_assets." + direction + ".sql"
	script, err := fs.ReadFile(controlmigrations.FS, name)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return err
		}
		if direction == "down" {
			_, err = tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=39`)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES(39)`)
		}
		return err
	})
}

func certificateMigrationApplied(t *testing.T, pool *pgxpool.Pool, version int64) bool {
	t.Helper()
	var applied bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS(
		SELECT 1 FROM schema_migrations WHERE version=$1
	)`, version).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	return applied
}

func certificateRelationExists(t *testing.T, pool *pgxpool.Pool, relation string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, relation).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

// isolatedCertificateAssetPool is an isolated schema at the current migration
// head: the store's SQL targets the head schema.
func isolatedCertificateAssetPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// A release-head clone of the template when one is configured: a full
	// migration within the 45s budget below timed out on a loaded host.
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	return isolatedCertificateAssetPoolWith(t, func(ctx context.Context, pool *pgxpool.Pool) error {
		return controldatabase.Migrate(ctx, pool, "up")
	})
}

// isolatedCertificateAssetPool039 stops at 039 (plus the later actor scope
// columns): only the 039 up/down migration tests use it.
func isolatedCertificateAssetPool039(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return isolatedCertificateAssetPoolWith(t, migrateCertificateAssetsThrough039)
}

func isolatedCertificateAssetPoolWith(t *testing.T, migrate func(context.Context, *pgxpool.Pool) error) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "certificate_asset_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^certificate_asset_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("refusing unexpected schema %q", schema)
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
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("migrate isolated certificate asset schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated certificate asset schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func migrateCertificateAssetsThrough039(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(
		version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(controlmigrations.FS, ".")
	if err != nil {
		return err
	}
	type migrationFile struct {
		version int64
		name    string
	}
	items := make([]migrationFile, 0, 39)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		separator := strings.IndexByte(name, '_')
		if separator < 1 {
			return fmt.Errorf("invalid migration filename %q", name)
		}
		version, err := strconv.ParseInt(name[:separator], 10, 64)
		if err != nil {
			return err
		}
		if version <= 39 {
			items = append(items, migrationFile{version: version, name: name})
		}
	}
	sort.Slice(items, func(left, right int) bool { return items[left].version < items[right].version })
	if len(items) != 39 {
		return fmt.Errorf("migration count through 039 = %d, want 39", len(items))
	}
	for index, item := range items {
		if item.version != int64(index+1) {
			return fmt.Errorf("migration gap through 039 at version %d", item.version)
		}
		script, err := fs.ReadFile(controlmigrations.FS, item.name)
		if err != nil {
			return err
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(script)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, item.version)
			return err
		}); err != nil {
			return fmt.Errorf("apply migration %03d: %w", item.version, err)
		}
	}
	lockScript, err := fs.ReadFile(controlmigrations.FS, "069_iam_global_lock_protocol.up.sql")
	if err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, string(lockScript)); err != nil {
		return fmt.Errorf("install IAM lock protocol in certificate test fixture: %w", err)
	}
	for _, statement := range []string{
		`ALTER TABLE certificate_assets ADD COLUMN created_by_scope_id uuid,
			ADD COLUMN updated_by_scope_id uuid, ADD COLUMN deleted_by_scope_id uuid`,
		`ALTER TABLE certificate_asset_versions ADD COLUMN actor_scope_id uuid`,
		`ALTER TABLE certificate_asset_private_key_envelope_facts ADD COLUMN actor_scope_id uuid`,
		`ALTER TABLE certificate_asset_activation_facts ADD COLUMN actor_scope_id uuid`,
		`ALTER TABLE certificate_asset_revocation_facts ADD COLUMN actor_scope_id uuid`,
		`ALTER TABLE certificate_site_binding_facts ADD COLUMN actor_scope_id uuid`,
		`ALTER TABLE certificate_asset_write_requests ADD COLUMN actor_scope_id uuid`,
		`CREATE UNIQUE INDEX certificate_asset_write_actor_idempotency_085_test_idx
			ON certificate_asset_write_requests(
				tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key
			)`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("apply certificate actor-scope test fixture: %w", err)
		}
	}
	return nil
}
