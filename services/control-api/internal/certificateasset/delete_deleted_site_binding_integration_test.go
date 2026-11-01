//go:build integration

package certificateasset

import (
	"context"
	"errors"
	"testing"
)

// 73 11-01: site e1035b-site was deleted (soft, 204); deleting the
// certificate it was bound to then failed 409 certificate_asset_referenced,
// and unbinding a deleted site is 404. A deleted site's binding no longer
// references the certificate (migration 613); a live site's still does.
func TestDeleteCertificateBoundOnlyToDeletedSite(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "delete-deleted-site-binding")
	store := newPublicationStore(t, pool, &testEnvelopeCipher{}, certificateTestClock)
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	imported := createBoundPublicationAsset(t, store, tenant, pki, tenant.siteOne)
	ctx := context.Background()
	current, _, err := store.Get(ctx, tenant.actor, tenant.actor.ScopeID, imported.Asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Delete(ctx, tenant.actor, DeleteRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, ExpectedRevision: current.Revision,
		IdempotencyKey: "delete-live-site-cert", RequestID: "request-delete-live-site-cert",
	}); !errors.Is(err, ErrReferenced) {
		t.Fatalf("delete while the site is live: %v, want ErrReferenced", err)
	}
	// the site is deleted the way site.Store.Delete does it (soft delete)
	if _, err := pool.Exec(ctx, `UPDATE sites SET deleted_at=now(),updated_at=now(),revision=revision+1
		WHERE id=$1 AND deleted_at IS NULL`, tenant.siteOne); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.Delete(ctx, tenant.actor, DeleteRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, ExpectedRevision: current.Revision,
		IdempotencyKey: "delete-deleted-site-cert", RequestID: "request-delete-deleted-site-cert",
	})
	if err != nil || deleted.DeletedAt == nil {
		t.Fatalf("delete after the site was deleted = %+v, %v", deleted, err)
	}
}
