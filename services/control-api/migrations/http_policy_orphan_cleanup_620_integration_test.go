//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestHTTPPolicyOrphanCleanup620 seeds the 73 orphan at 619 (an enabled HTTP
// policy whose site the old delete marked deleted), applies 620 and checks
// the policy is deleted through a revision (projection, publication head,
// cleanup record), the live site's policy untouched; then down and up again.
func TestHTTPPolicyOrphanCleanup620(t *testing.T) {
	const version = 620
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	seed := edgepublish.NewE2EPublisherForTest(t, pool, "orphan-cleanup-620")
	now := time.Now().UTC().Truncate(time.Second)
	config, err := httppolicycontrol.NewSitePolicyConfig(4<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	newSite := func(domain string) (uuid.UUID, uuid.UUID) {
		t.Helper()
		siteID := uuid.New()
		var policyID uuid.UUID
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `
				WITH allocated AS (
					INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,$5)
					ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1,
						updated_at=EXCLUDED.updated_at
					RETURNING next_value-1 AS display_id
				)
				INSERT INTO sites (id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
					https_enabled,enabled,status,created_by_user_id,updated_by_user_id,created_at,updated_at)
				SELECT $1,allocated.display_id,$2,$3,$4,'{80}','{}','{203.0.113.10:8080}','{203.0.113.10}',
					false,true,'active',$3,$3,$5,$5 FROM allocated`,
				siteID, seed.ScopeID, seed.UserID, domain, now); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools (site_id,balance_method,failover_tries,
				connect_timeout_ms,read_timeout_ms,updated_at) VALUES ($1,'round_robin',1,3000,30000,$2)`, siteID, now); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origins (site_id,position,host,port,weight,enabled)
				VALUES ($1,1,'203.0.113.10',8080,1,true)`, siteID); err != nil {
				return err
			}
			var err error
			policyID, err = httppolicycontrol.CreateForNewSiteTx(ctx, tx, seed.PlatformScopeID, seed.PlatformUserID,
				seed.ScopeID, seed.TenantID, siteID, seed.UserID, config, now)
			return err
		}); err != nil {
			t.Fatalf("seed %s: %v", domain, err)
		}
		return siteID, policyID
	}
	goneSite, gonePolicy := newSite("gone.cleanup-620.example.test")
	_, keptPolicy := newSite("kept.cleanup-620.example.test")
	if _, err := pool.Exec(ctx, `UPDATE sites SET deleted_at=$2,updated_at=$2,revision=revision+1 WHERE id=$1`,
		goneSite, now); err != nil {
		t.Fatal(err)
	}
	head := func() int64 {
		t.Helper()
		var revision int64
		if err := pool.QueryRow(ctx, `SELECT revision FROM http_policy_publication_heads WHERE tenant_scope_id=$1`,
			seed.ScopeID).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		return revision
	}
	state := func(policyID uuid.UUID) (int64, bool, bool, bool) {
		t.Helper()
		var revision int64
		var enabled, deleted, deletedAt bool
		if err := pool.QueryRow(ctx, `SELECT current_revision,current_enabled,current_deleted,deleted_at IS NOT NULL
			FROM http_policies WHERE id=$1`, policyID).Scan(&revision, &enabled, &deleted, &deletedAt); err != nil {
			t.Fatal(err)
		}
		return revision, enabled, deleted, deletedAt
	}
	before := head()

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	if revision, enabled, deleted, deletedAt := state(gonePolicy); revision != 2 || enabled || !deleted || !deletedAt {
		t.Fatalf("orphan after 620: revision=%d enabled=%v deleted=%v deleted_at=%v", revision, enabled, deleted, deletedAt)
	}
	if revision, enabled, deleted, _ := state(keptPolicy); revision != 1 || !enabled || deleted {
		t.Fatalf("live site policy changed: revision=%d enabled=%v deleted=%v", revision, enabled, deleted)
	}
	if after := head(); after != before+1 {
		t.Fatalf("publication head %d -> %d, want one advance", before, after)
	}
	var action, requestID string
	var recorded bool
	if err := pool.QueryRow(ctx, `SELECT revision.action,revision.request_id,
		EXISTS(SELECT 1 FROM http_policy_orphan_cleanup_620 cleanup WHERE cleanup.policy_id=revision.policy_id
		  AND cleanup.revision=revision.revision AND cleanup.previous_enabled AND cleanup.site_id=$2)
		FROM http_policy_revisions revision WHERE revision.policy_id=$1 AND revision.revision=2`,
		gonePolicy, goneSite).Scan(&action, &requestID, &recorded); err != nil {
		t.Fatal(err)
	}
	if action != "delete" || requestID != "migration-620-orphan-cleanup" || !recorded {
		t.Fatalf("cleanup revision action=%s request_id=%s recorded=%v", action, requestID, recorded)
	}
	// A deleted site's policy accepts nothing but the delete (already done).
	if _, err := pool.Exec(ctx, `DELETE FROM http_policy_orphan_cleanup_620`); err == nil {
		t.Fatal("cleanup record deleted")
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if revision, _, deleted, _ := state(gonePolicy); revision != 2 || !deleted {
		t.Fatalf("down restored the orphan: revision=%d deleted=%v", revision, deleted)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("re-up %d: %v", version, err)
	}
	if revision, _, deleted, _ := state(gonePolicy); revision != 2 || !deleted {
		t.Fatalf("re-up changed the cleaned policy: revision=%d deleted=%v", revision, deleted)
	}
}
