//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 486 (A08): a tenant host firewall command queued for a shared platform node
// before the fix is ended on upgrade, the tenant's own node keeps its command,
// and the publication with no node of its own fails.
func TestSharedNodeHostFirewall486EndsQueuedSharedNodeCommands(t *testing.T) {
	pool := migrationSnapshotPool(t, 484)
	ctx := t.Context()
	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); err == pgx.ErrNoRows {
		platform = uuid.New()
	} else if err != nil {
		t.Fatal(err)
	}
	owner, sharedOnly, user := uuid.New(), uuid.New(), uuid.New()
	sharedNode, ownedNode := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	type queued struct{ id, tenant, node uuid.UUID }
	var commands []queued
	publications := map[uuid.UUID]uuid.UUID{}
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		exec := func(sql string, args ...any) {
			if _, err := tx.Exec(ctx, sql, args...); err != nil {
				t.Fatalf("%.90s: %v", sql, err)
			}
		}
		// Foreign keys and guards off: the pre-486 schema cannot hold a global
		// command at all (its policy kind key names security_policies).
		exec(`SET LOCAL session_replication_role = replica`)
		exec(`INSERT INTO control_installation_entitlement(installation_id) SELECT 'p0a-486'
			WHERE NOT EXISTS (SELECT 1 FROM control_installation_entitlement)`)
		exec(`INSERT INTO access_scopes(id,kind) SELECT $1,'platform' WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, platform)
		for _, scope := range []uuid.UUID{owner, sharedOnly} {
			exec(`INSERT INTO tenants(id,display_name) VALUES($1,'p0a')`, scope)
			exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, scope)
		}
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'p0a','x')`, user, "p0a486-"+user.String()[:8])
		exec(`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,98001,$2,'p0a-shared','active',$4),
			($3,98002,$5,'p0a-owned','active',$4)`, sharedNode, platform, ownedNode, user, owner)
		var installation string
		if err := tx.QueryRow(ctx, `SELECT installation_id FROM control_installation_entitlement`).Scan(&installation); err != nil {
			t.Fatal(err)
		}
		digest := make([]byte, 32)
		for index, tenant := range []uuid.UUID{owner, sharedOnly} {
			policy, publication, site := uuid.New(), uuid.New(), uuid.New()
			publications[tenant] = publication
			exec(`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,display_id)
				VALUES($1,$2,$3,$4,'{203.0.113.20}','{203.0.113.20}',$3,$3,$5)`, site, tenant, user, "p0a486-"+site.String()[:8]+".example", 98100+index)
			exec(`INSERT INTO global_firewall_policies(id,tenant_scope_id,document,document_sha256,revision,active_revision,deployment_state,created_at,updated_at)
				VALUES($1,$2,'{}',$3,1,0,'canary',$4,$4)`, policy, tenant, digest, now)
			exec(`INSERT INTO global_firewall_publication_outbox(id,tenant_scope_id,policy_id,revision,operation,document,document_sha256,state,attempts,available_at,projected_at,created_at,updated_at)
				VALUES($1,$2,$3,1,'apply','{}',$4,'projected',1,$5,$5,$5,$5)`, publication, tenant, policy, digest, now)
			nodes := []uuid.UUID{sharedNode}
			if tenant == owner {
				nodes = append(nodes, ownedNode)
			}
			for _, node := range nodes {
				id := uuid.New()
				commands = append(commands, queued{id, tenant, node})
				exec(`INSERT INTO firewall_command_outbox(id,installation_id,tenant_scope_id,site_id,policy_id,policy_kind,binding_id,publication_id,node_id,
					policy_version,expected_active_policy_version,idempotency_key,command_bytes,command_sha256,publication_bundle_sha256,
					canonical_payload_sha256,runtime_snapshot_sha256,signing_key_id,signature_algorithm,state,attempts,available_at,created_at,updated_at,global_revision)
					VALUES($1,$2,$3,$4,$5,'global',NULL,$6,$7,1,0,$8,'\x01',$9,$9,$9,$9,'k','ed25519',$10,0,$11,$11,$11,1)`,
					id, installation, tenant, site, policy, publication, node, uuid.NewString(), digest, []string{"pending", "published"}[index], now)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", 486); err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		var state, lastError string
		if err := pool.QueryRow(ctx, `SELECT state,COALESCE(last_error,'') FROM firewall_command_outbox WHERE id=$1`, command.id).Scan(&state, &lastError); err != nil {
			t.Fatal(err)
		}
		shared := command.node == sharedNode
		if shared && (state != "failed" || lastError != "shared_node_host_firewall_unsupported") {
			t.Errorf("shared-node command of %s: state=%s error=%q, want failed", command.tenant, state, lastError)
		}
		if !shared && state != "pending" {
			t.Errorf("owned-node command: state=%s, want pending", state)
		}
	}
	for tenant, want := range map[uuid.UUID]string{owner: "projected", sharedOnly: "failed"} {
		var state string
		if err := pool.QueryRow(ctx, `SELECT state FROM global_firewall_publication_outbox WHERE id=$1`, publications[tenant]).Scan(&state); err != nil || state != want {
			t.Errorf("publication of %s: state=%q err=%v, want %s", tenant, state, err, want)
		}
	}
	var policyState string
	if err := pool.QueryRow(ctx, `SELECT deployment_state FROM global_firewall_policies WHERE tenant_scope_id=$1`, sharedOnly).Scan(&policyState); err != nil || policyState != "failed" {
		t.Errorf("shared-only policy deployment_state=%q err=%v, want failed", policyState, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", 486); err == nil {
		t.Fatal("486 down with global commands present succeeded, want refusal")
	}
}
