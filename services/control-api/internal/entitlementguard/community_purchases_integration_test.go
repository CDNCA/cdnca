package entitlementguard

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// cdncaCE: a pack/theme bought on the plugin market is granted once the
// verified per-installation artifact catalog lists an active entry requiring
// it, and not before or after it is withdrawn. A delivery that fails
// verification or a catalog past its validity grants nothing (the previous
// catalog is not kept); the next verified delivery restores the grant.
func TestCommunityGrantsMarketPurchasesFromTheCatalog(t *testing.T) {
	pool := isolatedEntitlementPool(t)
	guard := NewGuard(pool, time.Now, nil)
	read := func() (map[string]bool, ModuleGrants) {
		t.Helper()
		var features map[string]bool
		var grants ModuleGrants
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var err error
			if features, err = guard.ReadValidFeatures(t.Context(), tx); err != nil {
				return err
			}
			grants, err = guard.GrantedModules(t.Context(), tx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return features, grants
	}
	features, grants := read()
	if features["pack.crs"] || slices.Contains(grants.Codes, "pack.crs") || !features[FeatureSitesManage] {
		t.Fatalf("before a purchase: features %v grants %v", features, grants.Codes)
	}
	now := time.Now().UTC()
	insert := func(artifactID, feature string) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), `INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,
			media_type,requires_feature,resident,encryption,status,delivery_id,first_seen_at,updated_at)
			VALUES($1,split_part($1,'/',1),'1.0.0',1,repeat('a',64),1,'application/json',$2,true,'none','active',$3,$4,$4)`,
			artifactID, feature, uuid.New(), now); err != nil {
			t.Fatal(err)
		}
	}
	insert("crs_profile/strict", "pack.crs")
	insert("market_theme/aurora", "theme.aurora")
	insert("ruleset/free", "")
	if features, grants = read(); features["pack.crs"] || slices.Contains(grants.Codes, "pack.crs") {
		t.Fatalf("entries without a verified catalog head granted: %v %v", features, grants.Codes)
	}
	// What artifactsync.ApplyCatalog stores for a verified delivery.
	if _, err := pool.Exec(t.Context(), `UPDATE artifact_catalog_state SET delivery_id=$1,scope_revision=1,
		catalog_sha256=repeat('a',43),key_id='k1',signed_document='{}',valid_from=$2,expires_at=$3,applied_at=$2,
		last_success_at=$2,last_error_code='',updated_at=$2`, uuid.New(), now, now.Add(7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	features, grants = read()
	for _, code := range []string{"pack.crs", "theme.aurora"} {
		if !features[code] || !slices.Contains(grants.Codes, code) {
			t.Fatalf("purchase %s not granted: features %v grants %v", code, features, grants.Codes)
		}
	}
	if features["module.autodefense"] || slices.Contains(grants.Codes, "module.escalate") {
		t.Fatalf("commercial modules leaked: %v %v", features, grants.Codes)
	}
	state := func(statement string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, code := range CommunityCatalogRejections {
		// artifactsync.RejectDelivery: the head stays, the error is recorded.
		state(`UPDATE artifact_catalog_state SET last_error_code=$1`, code)
		if features, grants = read(); features["theme.aurora"] || slices.Contains(grants.Codes, "theme.aurora") {
			t.Fatalf("%s: purchases still granted after a rejected delivery: %v %v", code, features, grants.Codes)
		}
	}
	for _, code := range []string{"resolve_failed", "atomic_apply_failed", ""} {
		state(`UPDATE artifact_catalog_state SET last_error_code=$1`, code)
		if features, _ = read(); !features["theme.aurora"] {
			t.Fatalf("%s: purchases revoked by a non-verification failure", code)
		}
	}
	state(`UPDATE artifact_catalog_state SET valid_from=$1,applied_at=$1,expires_at=$2`, now.Add(-8*24*time.Hour), now.Add(-time.Minute))
	if features, _ = read(); features["theme.aurora"] {
		t.Fatal("purchases granted from an expired catalog")
	}
	state(`UPDATE artifact_catalog_state SET expires_at=$1`, now.Add(7*24*time.Hour))
	if _, err := pool.Exec(t.Context(), `UPDATE artifact_catalog_entries SET status='withdrawn',withdrawn_at=$1
		WHERE artifact_id='crs_profile/strict'`, now); err != nil {
		t.Fatal(err)
	}
	if features, grants = read(); features["pack.crs"] || slices.Contains(grants.Codes, "pack.crs") {
		t.Fatalf("withdrawn purchase still granted: %v %v", features, grants.Codes)
	}
}
