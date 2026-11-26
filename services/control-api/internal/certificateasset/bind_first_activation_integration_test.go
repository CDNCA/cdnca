package certificateasset

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// an ACME order's issued certificate (first version, never
// activated, status default) is bound straight from the site HTTPS page; the
// binding activates it in the same transaction.
func TestBindActivatesNeverActivatedFirstVersion(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "bind-first-activation")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool),
		func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	orderID := insertCertificateOrder(t, pool, tenant.actor, []string{"www.example.com"}, pki.leaf.NotAfter)
	imported, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "ACME 首签证书", Source: SourceACME,
		ACMEOrderID: &orderID, CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
		IdempotencyKey: "first-activation-import", RequestID: "first-activation-import",
	})
	if err != nil {
		t.Fatal(err)
	}
	if imported.Version.Status != StatusDefault || imported.Asset.Revision != 1 {
		t.Fatalf("imported = %#v", imported)
	}
	seedCertificateOrderFact(t, pool, `UPDATE certificate_orders SET issued_asset_id=$2,issued_asset_version_id=$3
		WHERE id=$1`, orderID, imported.Asset.ID, imported.Version.ID)

	// An uncovered site is refused without activating the version.
	if _, err := store.Bind(ctx, tenant.actor, BindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOutside, AssetID: imported.Asset.ID,
		VersionID: imported.Version.ID, ExpectedRevision: 0, Default: true,
		IdempotencyKey: "first-activation-bind-outside", RequestID: "first-activation-bind-outside",
	}); !errors.Is(err, ErrDomainNotCovered) {
		t.Fatalf("uncovered bind error = %v", err)
	}
	if asset, versions, err := store.Get(ctx, tenant.actor, tenant.actor.ScopeID, imported.Asset.ID); err != nil ||
		asset.Revision != 1 || versions[0].Status != StatusDefault {
		t.Fatalf("after refused bind asset=%#v versions=%#v error=%v", asset, versions, err)
	}

	request := BindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, AssetID: imported.Asset.ID,
		VersionID: imported.Version.ID, ExpectedRevision: 0, Default: true,
		IdempotencyKey: "first-activation-bind", RequestID: "first-activation-bind",
	}
	bound, err := store.Bind(ctx, tenant.actor, request)
	if err != nil {
		t.Fatal(err)
	}
	if !bound.Bound || bound.VersionID != imported.Version.ID || bound.Revision != 1 || !bound.Default {
		t.Fatalf("binding = %#v", bound)
	}
	asset, versions, err := store.Get(ctx, tenant.actor, tenant.actor.ScopeID, imported.Asset.ID)
	if err != nil || asset.Revision != 2 || len(versions) != 1 || versions[0].Status != StatusActive {
		t.Fatalf("after bind asset=%#v versions=%#v error=%v", asset, versions, err)
	}
	siteBinding, siteVersion, err := store.GetSiteBinding(ctx, tenant.actor, tenant.actor.ScopeID, tenant.siteOne)
	if err != nil || !siteBinding.Bound || siteBinding.VersionID != imported.Version.ID || siteVersion.Status != StatusActive {
		t.Fatalf("site binding=%#v version=%#v error=%v", siteBinding, siteVersion, err)
	}
	var orderStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM certificate_orders WHERE id=$1`, orderID).Scan(&orderStatus); err != nil {
		t.Fatal(err)
	}
	if orderStatus != "active" {
		t.Fatalf("order status = %q, want active once its certificate is activated", orderStatus)
	}
	if n := certificateRowCountWhere(t, pool, "certificate_asset_activation_facts", "asset_id", imported.Asset.ID); n != 1 {
		t.Fatalf("activation facts = %d", n)
	}

	replayed, err := store.Bind(ctx, tenant.actor, request)
	if err != nil || replayed.Revision != bound.Revision || replayed.VersionID != bound.VersionID {
		t.Fatalf("replayed binding = %#v error=%v", replayed, err)
	}
	if n := certificateRowCountWhere(t, pool, "certificate_asset_activation_facts", "asset_id", imported.Asset.ID); n != 1 {
		t.Fatalf("activation facts after replay = %d", n)
	}
}

// A first version left default after another version was activated is not a
// first use: binding it stays refused.
func TestBindRefusesDefaultVersionOnceAssetWasActivated(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "bind-default-after-activation")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool),
		func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v1PKI := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	v1, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "两版证书", Source: SourceUploaded,
		CertificatePEM: v1PKI.certificatePEM, PrivateKeyPEM: v1PKI.privateKeyPEM,
		IdempotencyKey: "default-after-activation-v1", RequestID: "default-after-activation-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	assetID := v1.Asset.ID
	v2PKI := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	v2, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: &assetID, ExpectedRevision: 1,
		Name: v1.Asset.Name, Source: SourceUploaded, CertificatePEM: v2PKI.certificatePEM,
		PrivateKeyPEM:  v2PKI.privateKeyPEM,
		IdempotencyKey: "default-after-activation-v2", RequestID: "default-after-activation-v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(ctx, tenant.actor, ActivateRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: assetID, VersionID: v2.Version.ID,
		ExpectedRevision: 2, IdempotencyKey: "default-after-activation-activate-v2",
		RequestID: "default-after-activation-activate-v2",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bind(ctx, tenant.actor, BindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, AssetID: assetID,
		VersionID: v1.Version.ID, ExpectedRevision: 0, Default: true,
		IdempotencyKey: "default-after-activation-bind-v1", RequestID: "default-after-activation-bind-v1",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("bind default v1 after v2 activation error = %v", err)
	}
	if _, _, err := store.GetSiteBinding(ctx, tenant.actor, tenant.actor.ScopeID, tenant.siteOne); !errors.Is(err, ErrNotFound) {
		t.Fatalf("site binding after refused bind error = %v", err)
	}
}
