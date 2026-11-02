//go:build integration

package node

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestUpdateNodeIPMovesLineGroupEndpoints: changing a node IP that a current
// line group revision publishes is the administrator's authoritative fix (the
// node was registered with a CDN edge address): the endpoints follow in a new
// revision, the audit records old/new IP and the groups, and clearing the IP
// without a replacement is still refused.
func TestUpdateNodeIPMovesLineGroupEndpoints(t *testing.T) {
	pool := nodeAddressTestPool(t)
	ctx := t.Context()
	scopeID, userID, nodeID, groupID, endpointID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'repro-user','r','x')`, []any{userID}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,'n','active',$3,1,'162.158.193.46')`, []any{nodeID, scopeID, userID}},
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,region,resolved_value,ipv4_resolved_value,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,'g','','lg-r','v4-r',1,$3,$3,now(),now())`, []any{groupID, scopeID, userID}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,region,resolved_value,ipv4_resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at) VALUES($1,$2,1,'g','','lg-r','v4-r',10000,3000,3,3,0,0,1,$3,$4,now())`, []any{groupID, scopeID, make([]byte, 32), userID}},
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,priority,weight,enabled) VALUES($1,$2,$3,$4,1,'162.158.193.46',4,443,0,1,true)`, []any{endpointID, nodeID, scopeID, groupID}},
			{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at) SELECT $1,$2,1,$3,'unknown',0,0,0,created_at,1,created_at,created_at FROM node_line_group_revisions WHERE line_group_id=$2`, []any{scopeID, groupID, endpointID}},
			{`UPDATE node_line_group_revisions SET sealed_at=created_at WHERE line_group_id=$1`, []any{groupID}},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(NewStore(pool))
	actor := Actor{UserID: userID, ScopeID: scopeID}
	current, err := service.store.Get(ctx, scopeID, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	ip := "203.0.113.9"
	updated, err := service.UpdateNode(ctx, actor, UpdateRequest{ID: nodeID, ExpectedRevision: current.Revision,
		Fields: UpdateFields{IPv4: &ip}, IdempotencyKey: "ip-move", RequestID: "ip-move"})
	if err != nil {
		t.Fatalf("change the node IP: %v", err)
	}
	if updated.Node.IPv4 == nil || *updated.Node.IPv4 != ip {
		t.Fatalf("node IP = %v", updated.Node.IPv4)
	}
	var revision int64
	var address string
	var sameID bool
	if err := pool.QueryRow(ctx, `SELECT line_group.current_revision,host(endpoint.address),endpoint.id=$2
		FROM node_line_groups line_group JOIN node_line_endpoints endpoint ON endpoint.line_group_id=line_group.id
		 AND endpoint.config_revision=line_group.current_revision WHERE line_group.id=$1`, groupID, endpointID).
		Scan(&revision, &address, &sameID); err != nil {
		t.Fatal(err)
	}
	if revision != 2 || address != ip || !sameID {
		t.Fatalf("line group revision %d endpoint %s same id %v, want 2 %s true", revision, address, sameID, ip)
	}
	var oldIP, newIP, auditGroup string
	if err := pool.QueryRow(ctx, `SELECT payload->'line_group_address_moves'->0->>'old_ip',
		payload->'line_group_address_moves'->0->>'new_ip',
		payload->'line_group_address_moves'->0->'line_groups'->0->>'line_group_id'
		FROM audit_events WHERE action='node.update' AND resource_id=$1`, nodeID.String()).
		Scan(&oldIP, &newIP, &auditGroup); err != nil {
		t.Fatal(err)
	}
	if oldIP != "162.158.193.46" || newIP != ip || auditGroup != groupID.String() {
		t.Fatalf("audit old %q new %q group %q", oldIP, newIP, auditGroup)
	}
	empty := ""
	if _, err := service.UpdateNode(ctx, actor, UpdateRequest{ID: nodeID, ExpectedRevision: updated.Node.Revision,
		Fields: UpdateFields{IPv4: &empty}, IdempotencyKey: "ip-clear", RequestID: "ip-clear"}); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("clearing an in-use IP: %v, want ErrAddressInUse", err)
	}
}
