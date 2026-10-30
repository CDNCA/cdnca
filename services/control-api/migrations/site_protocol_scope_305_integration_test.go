//go:build integration

package migrations_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestSiteProtocolScope305 covers the 136 defect: validate_site_protocol_scope_136
// read NEW.site_id / NEW.node_id inside IF expressions that PL/pgSQL resolves
// as a whole, so inserts into site_protocol_batches (no site_id) and into
// states/items (no node_id) failed with 42703 and HTTP/3 batch create always
// returned 503. 305 must make those inserts work while keeping the scope
// checks, and roll back cleanly.
func TestSiteProtocolScope305(t *testing.T) {
	// Renumbered on merge: 305_site_protocol_scope_fields is 319 (1632cdcf).
	const version = 319
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, tenantScope, platformScope := uuid.New(), uuid.New(), uuid.New()
	otherTenant, otherScope := uuid.New(), uuid.New()
	userID, siteID, otherSiteID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Protocol A'),($2,'Protocol B')`, []any{tenantID, otherTenant}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'platform',NULL),($4,'tenant',$5)`,
			[]any{tenantScope, tenantID, platformScope, otherScope, otherTenant}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'protocol-305','Protocol','unused')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($3,$2)`, []any{tenantScope, userID, otherScope}},
		{`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,1,$2,'node-305','active',$3)`,
			[]any{nodeID, tenantScope, userID}},
	} {
		if _, err := pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatalf("seed %q: %v", seed.sql, err)
		}
	}
	for index, site := range []struct{ id, scope uuid.UUID }{{siteID, tenantScope}, {otherSiteID, otherScope}} {
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
				created_by_user_id,updated_by_user_id) VALUES($1,$2,1,$3,$4,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3)`,
				site.id, site.scope, userID, fmt.Sprintf("protocol-305-%d.example.test", index)); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, site.id); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, site.id)
			return err
		}); err != nil {
			t.Fatalf("seed site: %v", err)
		}
	}
	insertBatch := func(scope uuid.UUID) (uuid.UUID, error) {
		id := uuid.New()
		_, err := pool.Exec(ctx, `INSERT INTO site_protocol_batches(
			id,tenant_scope_id,actor_user_id,action,http3_enabled,state,revision,request_sha256,request_id,trace_id,created_at,updated_at
		) VALUES($1,$2,$3,'apply',true,'queued',1,$4,'request-305','trace-305',now(),now())`, id, scope, userID, make([]byte, 32))
		return id, err
	}
	insertItem := func(batchID, site uuid.UUID, position int) error {
		_, err := pool.Exec(ctx, `INSERT INTO site_protocol_batch_items(
			batch_id,tenant_scope_id,position,site_id,previous_http3_enabled,desired_http3_enabled,state,attempt,created_at,updated_at
		) VALUES($1,$2,$3,$4,false,true,'pending',1,now(),now())`, batchID, tenantScope, position, site)
		return err
	}
	insertState := func(site uuid.UUID, batchID uuid.UUID) error {
		_, err := pool.Exec(ctx, `INSERT INTO site_protocol_states(
			tenant_scope_id,site_id,active_http3_enabled,desired_http3_enabled,revision,last_batch_id,updated_at
		) VALUES($1,$2,false,true,1,$3,now())`, tenantScope, site, batchID)
		return err
	}
	insertNodeResult := func(batchID, node uuid.UUID) error {
		_, err := pool.Exec(ctx, `INSERT INTO site_protocol_node_results(
			batch_id,tenant_scope_id,node_id,site_id,state,attempt,updated_at
		) VALUES($1,$2,$3,$4,'pending',1,now())`, batchID, tenantScope, node, siteID)
		return err
	}

	// Red on the 304 schema: the batch insert itself fails with 42703.
	if _, err := insertBatch(tenantScope); !pgCode(err, "42703") {
		t.Fatalf("304 batch insert = %v, want 42703 (the defect)", err)
	}

	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	batchID, err := insertBatch(tenantScope)
	if err != nil {
		t.Fatalf("batch insert after 305 = %v", err)
	}
	if err := insertItem(batchID, siteID, 0); err != nil {
		t.Fatalf("item insert after 305 = %v", err)
	}
	if err := insertState(siteID, batchID); err != nil {
		t.Fatalf("state insert after 305 = %v", err)
	}
	if err := insertNodeResult(batchID, nodeID); err != nil {
		t.Fatalf("node result insert after 305 = %v", err)
	}
	// The scope checks themselves still hold.
	if _, err := insertBatch(platformScope); !pgCode(err, "P1361") {
		t.Fatalf("platform-scope batch = %v, want P1361", err)
	}
	if err := insertItem(batchID, otherSiteID, 1); !pgCode(err, "P1362") {
		t.Fatalf("cross-scope item = %v, want P1362", err)
	}
	if err := insertState(otherSiteID, batchID); !pgCode(err, "P1362") {
		t.Fatalf("cross-scope state = %v, want P1362", err)
	}
	if err := insertNodeResult(batchID, uuid.New()); !pgCode(err, "P1362") && !pgCode(err, "23503") {
		t.Fatalf("unknown node result = %v, want P1362", err)
	}
}

func pgCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
