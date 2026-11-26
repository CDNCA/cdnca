//go:build integration

// Package packagelinefixture builds the package-change scenario of the
// integration tests that check a reader follows the entitlement in effect
// (701 package_subscription_current_product_snapshot) rather than the purchase
// snapshot: line A serves only node 甲, line B only node 乙; a subscription is
// bought on package A (product A, snapshot A, entitlement revision 1) and
// Change moves it to B (or back) with a new entitlement version, leaving
// package_subscriptions.product_snapshot on A.
package packagelinefixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options of New. Scope and User are required: the tenant scope owning the
// subscription (and the line groups and nodes unless NodeScope / LineScope
// say otherwise) and a user of it.
type Options struct {
	Scope, User uuid.UUID
	// NodeScope owns the nodes (default Scope); LineScope the line groups
	// and their endpoints (default Scope).
	NodeScope, LineScope uuid.UUID
	// Spec is the package spec of a line (default {"node_group_id": line}).
	Spec func(line uuid.UUID) map[string]any
}

type Fixture struct {
	t    testing.TB
	pool *pgxpool.Pool
	opts Options

	LineA, LineB         uuid.UUID
	NodeJia, NodeYi      uuid.UUID
	EndpointA, EndpointB uuid.UUID
	ProductA, ProductB   uuid.UUID
	Subscription         uuid.UUID
	revision             int
}

// Exec runs query with triggers off (session_replication_role = replica), as
// the fixtures of the packages under test insert their rows.
func Exec(t testing.TB, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	ctx := context.Background()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, query, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// New creates lines A (node 甲) and B (node 乙) and the subscription bought
// on A, in force as A (entitlement revision 1).
func New(t testing.TB, pool *pgxpool.Pool, opts Options) *Fixture {
	t.Helper()
	if opts.NodeScope == uuid.Nil {
		opts.NodeScope = opts.Scope
	}
	if opts.LineScope == uuid.Nil {
		opts.LineScope = opts.Scope
	}
	if opts.Spec == nil {
		opts.Spec = func(line uuid.UUID) map[string]any { return map[string]any{"node_group_id": line.String()} }
	}
	f := &Fixture{t: t, pool: pool, opts: opts, ProductA: uuid.New(), ProductB: uuid.New(), Subscription: uuid.New()}
	f.LineA, f.NodeJia, f.EndpointA = f.line("pkgline-a")
	f.LineB, f.NodeYi, f.EndpointB = f.line("pkgline-b")
	Exec(t, pool, `INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,
		domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,
		tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,1,$4::jsonb,100,100,100,0,now()-interval '1 day',now()+interval '30 days',
		'UTC','monthly',1,1,$5,$5,now()-interval '1 day',now()-interval '1 day')`,
		f.Subscription, opts.Scope, f.ProductA, f.snapshot(f.LineA), opts.User)
	f.Change(f.LineA)
	return f
}

func (f *Fixture) line(name string) (group, node, endpoint uuid.UUID) {
	f.t.Helper()
	group, node, endpoint = uuid.New(), uuid.New(), uuid.New()
	address := fmt.Sprintf("10.%d.%d.%d", node[0], node[1], node[2]|1)
	Exec(f.t, f.pool, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4)
		VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes),$5)`,
		node, f.opts.NodeScope, name+"-"+node.String()[:8], f.opts.User, address)
	Exec(f.t, f.pool, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,
		created_at,updated_at,display_id,resolved_value,ipv4_resolved_value) VALUES($1,$2,$3,1,$4,$4,now(),now(),
		(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),'lg-'||replace($1::uuid::text,'-',''),
		'v4-'||replace($1::uuid::text,'-',''))`, group, f.opts.LineScope, name+"-"+group.String()[:8], f.opts.User)
	Exec(f.t, f.pool, `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,
		ipv4_resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,
		recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at,sealed_at)
		VALUES($1,$2,1,$3,'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,
		$4,$5,now(),now())`, group, f.opts.LineScope, name+"-"+group.String()[:8], make([]byte, 32), f.opts.User)
	Exec(f.t, f.pool, `INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,
		address_family,port,region,carrier,priority,weight,enabled) VALUES($1,$2,$3,$4,1,$5::inet,4,80,'hk','bgp',0,1,true)`,
		endpoint, node, f.opts.LineScope, group, address)
	return group, node, endpoint
}

func (f *Fixture) snapshot(line uuid.UUID) string {
	raw, err := json.Marshal(map[string]any{"revision": 1, "name": "pkgline-" + line.String()[:8], "spec": f.opts.Spec(line)})
	if err != nil {
		f.t.Fatal(err)
	}
	return string(raw)
}

// Product is the product of a line's package (A or B).
func (f *Fixture) Product(line uuid.UUID) uuid.UUID {
	if line == f.LineB {
		return f.ProductB
	}
	return f.ProductA
}

// Change puts line's package in force now (a new entitlement version; the
// purchase snapshot stays on A).
func (f *Fixture) Change(line uuid.UUID) {
	f.t.Helper()
	f.revision++
	operation, supersedes, effective := "manual_open", any(nil), "now() - interval '1 hour'"
	if f.revision > 1 {
		operation, supersedes, effective = "admin_edit", f.revision-1, "clock_timestamp()"
	}
	Exec(f.t, f.pool, `INSERT INTO package_subscription_entitlement_versions(subscription_id,revision,supersedes_subscription_id,
		supersedes_revision,tenant_scope_id,effective_at,effective_until,product_id,product_revision,product_snapshot,
		site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,
		currency,entitlement_status,source_order_id,operation,created_by_user_id,created_at,commit_sequence)
		VALUES($1::uuid,$2,CASE WHEN $3::bigint IS NULL THEN NULL ELSE $1::uuid END,$3,$4,`+effective+`,NULL,$5,1,$6::jsonb,
		100,100,100,0,'UTC','monthly',1,1,'CNY','active',NULL,$7,$8,clock_timestamp(),$2)`,
		f.Subscription, f.revision, supersedes, f.opts.Scope, f.Product(line), f.snapshot(line), operation, f.opts.User)
}

// Site creates a live site of the scope on the subscription, following the
// package's line (node_group_id NULL).
func (f *Fixture) Site(domain string) uuid.UUID {
	f.t.Helper()
	site := uuid.New()
	Exec(f.t, f.pool, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,package_subscription_id,
		package_id,node_group_id,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,(SELECT COALESCE(max(display_id),0)+1 FROM sites),$3,$4,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$5,$6,NULL,$3,$3)`,
		site, f.opts.Scope, f.opts.User, domain, f.Subscription, f.ProductA)
	return site
}

// Node is the node of a line.
func (f *Fixture) Node(line uuid.UUID) uuid.UUID {
	if line == f.LineB {
		return f.NodeYi
	}
	return f.NodeJia
}

// Tenant creates a tenant scope and a member user of it.
func Tenant(t testing.TB, pool *pgxpool.Pool) (scope, user uuid.UUID) {
	t.Helper()
	tenant, scope, user := uuid.New(), uuid.New(), uuid.New()
	Exec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'pkgline')`, tenant)
	Exec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenant)
	Exec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'pkgline','unused')`,
		user, "pkgline-"+user.String())
	Exec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, user)
	return scope, user
}

// Platform is the platform scope (created when the database has none).
func Platform(t testing.TB, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var scope uuid.UUID
	err := pool.QueryRow(context.Background(), `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL LIMIT 1`).Scan(&scope)
	if errors.Is(err, pgx.ErrNoRows) {
		scope = uuid.New()
		Exec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope)
	} else if err != nil {
		t.Fatal(err)
	}
	return scope
}

// MarketEndpoint adds to line an endpoint of a subscribed market node of a new
// active market supply owned by owner (migration 624), returning both.
func (f *Fixture) MarketEndpoint(line, owner uuid.UUID) (supply, market uuid.UUID) {
	f.t.Helper()
	supply, market = uuid.New(), uuid.New()
	Exec(f.t, f.pool, `INSERT INTO site_supplies(id,owner_scope_id,kind,name,market_subscription_id,status,created_at,updated_at)
		VALUES($1,$2,'market_subscription',$3,gen_random_uuid(),'active',now(),now())`, supply, owner, "pkgline-"+supply.String()[:8])
	address := fmt.Sprintf("10.%d.%d.%d", market[0], market[1], market[2]|1)
	Exec(f.t, f.pool, `INSERT INTO market_subscribed_nodes(id,supply_id,market_subscription_id,leaf_member_id,node_pool_ref,ref,
		address,synced_at,created_at,updated_at) SELECT $1,$2,market_subscription_id,gen_random_uuid(),'p1',$3,$4,now(),now(),now()
		FROM site_supplies WHERE id=$2`, market, supply, strings.ReplaceAll(market.String(), "-", "")[:16], address)
	Exec(f.t, f.pool, `INSERT INTO node_line_endpoints(id,node_id,market_node_id,tenant_scope_id,line_group_id,config_revision,
		address,address_family,port,region,carrier,priority,weight,enabled)
		VALUES(gen_random_uuid(),NULL,$1,$2,$3,1,$4::inet,4,80,'hk','bgp',0,1,true)`, market, f.opts.LineScope, line, address)
	return supply, market
}

// Forward creates a live TCP stream of the scope on the subscription listening
// on port, following the package's lines (no own line group).
func (f *Fixture) Forward(port int) uuid.UUID {
	f.t.Helper()
	forward := uuid.New()
	Exec(f.t, f.pool, `INSERT INTO l4_forwards(id,scope_id,owner_user_id,name,protocol,listen_port,upstream_address,upstream_port,
		connect_timeout_ms,response_timeout_ms,package_subscription_id,max_connections_per_client,
		created_by_user_id,updated_by_user_id,created_at,updated_at,display_id)
		VALUES($1,$2,$3,$4,'tcp',$5,'192.0.2.20',443,3000,30000,$6,100,$3,$3,now(),now(),
		(SELECT COALESCE(max(display_id),0)+1 FROM l4_forwards))`,
		forward, f.opts.Scope, f.opts.User, "pkgline-"+forward.String()[:8], port, f.Subscription)
	return forward
}
