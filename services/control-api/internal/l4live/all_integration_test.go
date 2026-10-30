//go:build integration

package l4live

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The forwards 实时连接 asks without a picked forward: platform sees every
// tenant's enabled TCP forwards (tenant_id narrows by tenants.id), a tenant
// session only its own; deleted, disabled and UDP forwards are skipped;
// listen_port matches the primary port, a port range or an extra listener.
func TestLoadStreamsScopesPlatformAndTenant(t *testing.T) {
	pool := integrationPool(t)
	ctx := t.Context()
	tenantA, tenantB := uuid.New(), uuid.New()
	scopeA, scopeB, user, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ownA, otherA, ownB, ranged, deleted, disabled, udp := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		exec := func(sql string, args ...any) {
			if _, err := tx.Exec(ctx, sql, args...); err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
		}
		exec(`SET LOCAL session_replication_role = replica`)
		exec(`INSERT INTO tenants(id,display_name) VALUES($1,'a'),($2,'b')`, tenantA, tenantB)
		exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$3),($2,'tenant',$4)`, scopeA, scopeB, tenantA, tenantB)
		for _, id := range []uuid.UUID{user, other} {
			exec(`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at) VALUES($1,$2,'live','x',now(),now())`, id, "live-"+id.String()[:8])
		}
		at := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
		forward := func(id, scope, owner uuid.UUID, protocol string, port, portEnd int, enabled, gone bool, minute int) {
			var end any
			if portEnd != 0 {
				end = portEnd
			}
			var deletedAt any
			if gone {
				deletedAt = at
			}
			exec(`INSERT INTO l4_forwards(id,scope_id,owner_user_id,name,protocol,listen_port,listen_port_end,upstream_address,upstream_port,
				connect_timeout_ms,response_timeout_ms,enabled,created_by_user_id,updated_by_user_id,created_at,updated_at,deleted_at,package_subscription_id,max_connections_per_client,display_id)
				VALUES($1,$2,$3,$4,$5,$6,$7,'192.0.2.1',80,1000,1000,$8,$3,$3,$9,$9,$10,$11,100,(SELECT COALESCE(max(display_id),0)+1 FROM l4_forwards))`,
				id, scope, owner, "f-"+id.String()[:8], protocol, port, end, enabled, at.Add(time.Duration(minute)*time.Minute), deletedAt, uuid.New())
		}
		forward(ownA, scopeA, user, "tcp", 9001, 0, true, false, 1)
		forward(otherA, scopeA, other, "tcp", 9002, 0, true, false, 2)
		forward(ownB, scopeB, other, "tcp", 9003, 0, true, false, 3)
		forward(ranged, scopeB, other, "tcp", 9100, 9200, true, false, 4)
		forward(deleted, scopeA, user, "tcp", 9004, 0, true, true, 5)
		forward(disabled, scopeA, user, "tcp", 9005, 0, false, false, 6)
		forward(udp, scopeA, user, "udp", 9006, 0, true, false, 7)
		exec(`INSERT INTO l4_forward_listeners(id,stream_id,protocol,address,port,reserved) VALUES($1,$2,'tcp','*',9500,true)`, uuid.New(), ownA)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(pool, requesterFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	ids := func(filter AllFilter) []uuid.UUID {
		t.Helper()
		refs, err := service.loadStreams(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]uuid.UUID, len(refs))
		for index, ref := range refs {
			out[index] = ref.id
		}
		return out
	}
	equal := func(name string, got []uuid.UUID, want ...uuid.UUID) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: got %v want %v", name, got, want)
		}
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("%s: got %v want %v", name, got, want)
			}
		}
	}
	equal("platform all, newest first", ids(AllFilter{Platform: true}), ranged, ownB, otherA, ownA)
	equal("platform one tenant", ids(AllFilter{Platform: true, TenantID: tenantA}), otherA, ownA)
	equal("tenant own only", ids(AllFilter{OwnerScopeID: scopeA, OwnerUserID: user}), ownA)
	equal("port range", ids(AllFilter{Platform: true, ListenPort: 9150}), ranged)
	equal("extra listener", ids(AllFilter{Platform: true, ListenPort: 9500}), ownA)
	equal("stream", ids(AllFilter{OwnerScopeID: scopeA, OwnerUserID: user, StreamID: otherA}))
}
