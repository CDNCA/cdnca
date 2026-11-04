package marketprobe

import (
	"context"
	"os"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAssignRolesJoinsPoolNodesAndWithdrawsTheRest runs the
// role target query on a migrated schema (MARKET_PROBE_TEST_DATABASE_URL):
// the active pool's MARKET_ROLE nodes are assigned join_market, a node the
// controller joined that no active pool holds is assigned probe_only, an
// older Agent and a disabled endpoint get nothing.
func TestAssignRolesJoinsPoolNodesAndWithdrawsTheRest(t *testing.T) {
	url := os.Getenv("MARKET_PROBE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("MARKET_PROBE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	roles := capabilities(t, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_ROLE)
	legacy := capabilities(t, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE)
	platform, user, group := uuid.New(), uuid.New(), uuid.New()
	member, older, switchedOff, outsider := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		exec := func(sql string, args ...any) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}
		if err := exec(`SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if err := exec(`INSERT INTO access_scopes(id,kind) SELECT $1,'platform'
			WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, platform); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); err != nil {
			return err
		}
		if err := exec(`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
			VALUES($1,$2,'role test','x',now(),now())`, user, "role-"+user.String()[:8]); err != nil {
			return err
		}
		for _, node := range []uuid.UUID{member, older, switchedOff, outsider} {
			if err := exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
				VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`,
				node, platform, "role-"+node.String()[:8], user); err != nil {
				return err
			}
		}
		if err := exec(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,
			updated_by_user_id,created_at,updated_at,display_id,resolved_value,ipv4_resolved_value)
			VALUES($1,$2,$3,1,$4,$4,now(),now(),(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),
			'lg-'||replace($1::uuid::text,'-',''),'lg4-'||replace($1::uuid::text,'-',''))`,
			group, platform, "role-"+group.String()[:8], user); err != nil {
			return err
		}
		for i, e := range []struct {
			node    uuid.UUID
			enabled bool
		}{{member, true}, {older, true}, {switchedOff, false}} {
			if err := exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,
				address_family,port,region,carrier,priority,weight,enabled)
				VALUES($1,$2,$3,$4,1,$5::inet,4,443,'CN','电信',0,100,$6)`,
				uuid.New(), e.node, platform, group, []string{"8.8.8.1", "8.8.8.2", "8.8.8.3"}[i], e.enabled); err != nil {
				return err
			}
		}
		for _, n := range []struct {
			node uuid.UUID
			caps []byte
			role string
		}{{member, roles, "probe_only"}, {older, legacy, "probe_only"}, {switchedOff, roles, "probe_only"}, {outsider, roles, "join_market"}} {
			if err := exec(`INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,
				artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
				facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
				VALUES($1,1,$2,$3,'k',1,0,$4,$3,'\x00',$3,'gw','gw-1',now())`, n.node, uuid.New(), make([]byte, 32), n.caps); err != nil {
				return err
			}
			if err := setRole(ctx, tx, n.node, ptr(n.role), true); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	nodes := &fakeNodes{reply: func(command *agentv1.MarketProbeCommand) ([]byte, error) {
		return roleReply(command.AssignedRole, RoleSourceAssigned)(command)
	}}
	s := New(pool, nil, nodes, Config{}, quiet())
	answers, err := s.AssignRoles(ctx, []string{group.String()})
	if err != nil {
		t.Fatal(err)
	}
	sent := func(node uuid.UUID) agentv1.MarketProbeRole {
		if commands := nodes.commands[node.String()]; len(commands) == 1 {
			return commands[0].AssignedRole
		}
		return agentv1.MarketProbeRole_MARKET_PROBE_ROLE_UNSPECIFIED
	}
	if sent(member) != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET ||
		sent(outsider) != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY ||
		sent(older) != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_UNSPECIFIED ||
		sent(switchedOff) != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_UNSPECIFIED {
		t.Fatalf("sent %v", nodes.commands)
	}
	if answers[member.String()].Role != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET {
		t.Fatalf("answers %v", answers)
	}
	// The next round sends nothing new: the answers stand.
	if _, err := s.AssignRoles(ctx, []string{group.String()}); err != nil {
		t.Fatal(err)
	}
	if len(nodes.commands[member.String()]) != 1 {
		t.Fatalf("join_market sent again: %d", len(nodes.commands[member.String()]))
	}
	// The pool report lists every node of the current revision with its role
	// (no serving rows are seeded: none is serving yet).
	report, err := NewReporter(pool, s, "").Report(ctx, group)
	if err != nil || report.Probe != "running" || report.Total != 3 || report.Reportable != 0 {
		t.Fatalf("report %+v %v", report, err)
	}
	for _, n := range report.Nodes {
		if n.Reason != ReasonNotServing || n.NodeID == member && (n.Role != "join_market" || !n.RoleCapable) ||
			n.NodeID == older && n.RoleCapable {
			t.Fatalf("node %+v", n)
		}
	}
}
