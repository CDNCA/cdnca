//go:build integration

package firewallcontrol

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// per-node-dist (待出包前全量跑): tenant A owns two nodes, each the only node of
// its own line group, with one site on each group. A rule bound to site 1
// reaches only node 1's command for site 1; a rule of every site reaches
// both nodes; the command set (site × owned node) is unchanged.
func TestHostRuleBoundToSiteReachesOnlyItsLineGroupNodes(t *testing.T) {
	f := newSharedNodeFixture(t, true)
	node1, node2 := f.ownedNodeA, uuid.New()
	site1, site2 := uuid.New(), uuid.New()
	now := time.Now().UTC()
	if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		exec := func(sql string, args ...any) {
			if _, err := tx.Exec(t.Context(), sql, args...); err != nil {
				t.Fatalf("%.90s: %v", sql, err)
			}
		}
		exec(`SET LOCAL session_replication_role = replica`)
		exec(`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,97050,$2,'pnd-2','active',$3)`,
			node2, f.tenantA, f.user)
		// The fixture's site A rides the platform group: retire it here.
		exec(`UPDATE sites SET deleted_at=now() WHERE id=$1`, f.siteA)
		for index, node := range []uuid.UUID{node1, node2} {
			group := uuid.New()
			exec(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,
				created_at,updated_at,display_id,resolved_value,ipv4_resolved_value)
				VALUES($1::uuid,$2,$3,1,$4::uuid,$4::uuid,$5,$5,$6,'lg-'||replace($1::uuid::text,'-',''),'lg4-'||replace($1::uuid::text,'-',''))`,
				group, f.tenantA, "pnd-"+group.String()[:8], f.user, now, 97950+index)
			exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
				port,priority,weight,enabled) VALUES($1,$2,$3,$4,1,$5::inet,4,80,0,1,true)`,
				uuid.New(), node, f.tenantA, group, []string{"198.51.100.91", "198.51.100.92"}[index])
			exec(`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,
				display_id,node_group_id) VALUES($1,$2,$3,$4,'{203.0.113.20}','{203.0.113.20}',$3,$3,$5,$6)`,
				[]uuid.UUID{site1, site2}[index], f.tenantA, f.user, "pnd-"+uuid.NewString()[:8]+".example", 97960+index, group)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	policy := PolicyInput{Enabled: true, DefaultAction: ActionAllow, Rules: []RuleInput{
		{ID: uuid.New(), Priority: 1, Action: ActionDeny, CIDRs: []string{"192.0.2.0/24"}, Protocol: ProtocolAny, SiteIDs: []uuid.UUID{site1}},
		{ID: uuid.New(), Priority: 2, Action: ActionDeny, CIDRs: []string{"198.51.100.0/24"}, Protocol: ProtocolAny},
	}}
	document, _ := json.Marshal(policy)
	if _, err := NewStore(f.pool, allowAuthorizer{}, nil, time.Now).Put(t.Context(), PutRequest{
		Actor:         Actor{UserID: f.user, ScopeID: f.tenantA, ScopeKind: ScopeTenant, Permissions: []string{PermissionManage}},
		TargetScopeID: f.tenantA, Policy: policy, DocumentSHA256: sha256.Sum256(document),
		IdempotencyKey: "pnd-" + uuid.NewString()[:8], RequestSHA256: sha256.Sum256([]byte(uuid.NewString())), RequestID: uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	f.project(t)
	rows, err := f.pool.Query(t.Context(), `SELECT node_id,site_id,command_bytes FROM firewall_command_outbox
		WHERE policy_kind='global' AND tenant_scope_id=$1`, f.tenantA)
	if err != nil {
		t.Fatal(err)
	}
	type key struct{ node, site uuid.UUID }
	got := map[key][]string{}
	for rows.Next() {
		var node, site uuid.UUID
		var encoded []byte
		if err := rows.Scan(&node, &site, &encoded); err != nil {
			t.Fatal(err)
		}
		command := new(agentv1.FirewallCommand)
		if err := proto.Unmarshal(encoded, command); err != nil {
			t.Fatal(err)
		}
		for _, target := range command.Targets {
			got[key{node, site}] = append(got[key{node, site}], target.Cidr)
		}
		if got[key{node, site}] == nil {
			got[key{node, site}] = []string{}
		}
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	want := map[key][]string{
		{node1, site1}: {"192.0.2.0/24", "198.51.100.0/24"},
		{node2, site1}: {"198.51.100.0/24"},
		{node1, site2}: {"198.51.100.0/24"},
		{node2, site2}: {"198.51.100.0/24"},
	}
	if len(got) != len(want) {
		t.Fatalf("commands = %v, want %v", got, want)
	}
	for k, cidrs := range want {
		if !slices.Equal(got[k], cidrs) {
			t.Fatalf("node %s site %s targets = %v, want %v", k.node, k.site, got[k], cidrs)
		}
	}
}
