package marketsupply

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestPurgeSiteTargetsCarryingPlatformNodes purges a market site through the
// real cachecontrol store on the seller's platform node once the tenant's
// configuration is on it: long lists split at the 16-target limit, no list
// purges the whole site, and nothing is queued before any node carries it.
func TestPurgeSiteTargetsCarryingPlatformNodes(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Now().UTC()
	svc := newTestService(t, pool, func() time.Time { return now })
	store, err := cachecontrol.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: poolID.String(), Limits: spec.LimitSet{{Metric: spec.MetricDomains, Cap: 2, Action: spec.ActionRejectNew}},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{},
		IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	mustSync(t, svc, g)
	tenant, err := svc.ensureTenant(ctx, actor, Key(g))
	if err != nil {
		t.Fatal(err)
	}
	domain := "purge-" + uuid.NewString()[:8] + ".example.cn"
	leaf := siteRef{id: insertTenantSite(t, tenant, domain), domain: domain}
	if _, err := svc.purgeSite(ctx, tenant, leaf, siteconf.PurgeRequest{}, uuid.New()); !errors.Is(err, ErrUnsupportedOp) {
		t.Fatalf("purge without cache operations: %v", err)
	}
	svc.WithPurge(store)
	if _, err := svc.purgeSite(ctx, tenant, leaf, siteconf.PurgeRequest{}, uuid.New()); !errors.Is(err, ErrNoCarryingNode) {
		t.Fatalf("purge before any node carries the site: %v", err)
	}

	// The seller's platform node now runs the tenant's configuration.
	var node uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT node_id FROM node_line_endpoints WHERE line_group_id=$1`, poolID).Scan(&node); err != nil {
		t.Fatal(err)
	}
	version := uuid.New()
	digest := sha256.Sum256([]byte(version.String()))
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
				generator_version,status,idempotency_key,request_digest,created_at,published_at)
				VALUES($1,$2,'\x01',$3,'test','1','releasable',$4,$3,now(),now())`,
				[]any{version, tenant.scopeID, digest[:], "purge-" + version.String()[:8]}},
			{`INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
				VALUES($1,$2,$3,now())`, []any{node, tenant.scopeID, version}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return fmt.Errorf("%.60s: %w", statement.query, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	urls := make([]string, 20)
	for index := range urls {
		urls[index] = fmt.Sprintf("/asset-%02d.js", index)
	}
	// One operation per kind (ge-cache: 500 targets each).
	operations, err := svc.purgeSite(ctx, tenant, leaf, siteconf.PurgeRequest{URLs: urls, Dirs: []string{"/img/"}}, uuid.New())
	if err != nil || len(operations) != 2 {
		t.Fatalf("purge 20 URLs and a dir: operations=%v err=%v", operations, err)
	}
	whole, err := svc.purgeSite(ctx, tenant, leaf, siteconf.PurgeRequest{}, uuid.New())
	if err != nil || len(whole) != 1 {
		t.Fatalf("whole-site purge: operations=%v err=%v", whole, err)
	}
	var targeted int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cache_operation_nodes
		WHERE scope_id=$1 AND node_id=$2 AND operation_id=ANY($3)`, tenant.scopeID, node,
		append(operations, whole...)).Scan(&targeted); err != nil || targeted != 3 {
		t.Fatalf("operations on the platform node = %d, %v", targeted, err)
	}
}
