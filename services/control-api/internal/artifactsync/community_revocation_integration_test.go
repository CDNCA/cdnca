//go:build integration

package artifactsync_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/jackc/pgx/v5"
)

// cdncaCE: with the community guard, a pack bought on the market is granted
// from the verified catalog; a delivery that then fails verification clears
// the grant (the previous catalog is not kept as a grant) and the next
// verified delivery restores it.
func TestCommunityPurchaseRevokedByRejectedDelivery(t *testing.T) {
	f := newFixture(t)
	guard := entitlementguard.NewGuard(f.pool, func() time.Time { return f.now }, nil)
	f.store = artifactsync.NewStore(f.pool, func() time.Time { return f.now }).WithFeatures(guard).WithCRSRepublisher(f.recorder)
	f.syncer = f.newSyncer()
	granted := func() bool {
		t.Helper()
		var features map[string]bool
		if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
			var err error
			features, err = guard.ReadValidFeatures(t.Context(), tx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return features["pack.crs"]
	}
	seed := rulecatalog.CurrentSeed()
	f.license.PublishRule(artifactsynctest.SystemRule(t, seed, paidRule), "pack.crs", true)
	// Bought on the market but not resident: fetched without a download request.
	f.license.PublishRule(artifactsynctest.SystemRule(t, seed, onDemand), "pack.crs", false)
	f.sync()
	if !granted() {
		t.Fatal("verified purchase not granted")
	}
	if _, ok := f.local()["ruleset/"+onDemand]; !ok {
		t.Fatalf("bought non-resident pack not downloaded: %v", f.local())
	}
	newer := artifactsynctest.SystemRule(t, seed, freeRule)
	f.license.PublishRule(newer, "", true)
	f.license.TamperDelivery = func(signed *artifactcatalog.Signed) {
		signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
		signature[0] ^= 0x01
		signed.Signature = base64.RawURLEncoding.EncodeToString(signature)
	}
	f.sync()
	if f.lastErrorCode() != artifactsync.CodeInvalidSignature || granted() {
		t.Fatalf("after a forged delivery: code %q granted %v", f.lastErrorCode(), granted())
	}
	f.license.TamperDelivery = nil
	f.sync()
	if f.lastErrorCode() != "" || !granted() {
		t.Fatalf("after a verified delivery: code %q granted %v", f.lastErrorCode(), granted())
	}
}
