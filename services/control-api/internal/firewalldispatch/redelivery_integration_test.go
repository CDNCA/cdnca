//go:build integration

package firewalldispatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type redeliverySigner struct{}

func (redeliverySigner) KeyID() string                                { return "firewall-redelivery-test" }
func (redeliverySigner) Sign(context.Context, []byte) ([]byte, error) { return make([]byte, 64), nil }

type redeliveryAuthorizer struct{}

func (redeliveryAuthorizer) Authorize(context.Context, pgx.Tx, firewallcontrol.Actor, uuid.UUID, string) error {
	return nil
}

// redeliveryFixture: a tenant owning node1 (online), one enabled site on a
// platform line group, the real projector, redeliverer and dispatcher (fake
// NATS) on PostgreSQL. ack plays the agent: every published command applied.
type redeliveryFixture struct {
	pool               *pgxpool.Pool
	tenant, user, site uuid.UUID
	node1              uuid.UUID
	revision           int64
	offset             time.Duration // the redeliverer's clock runs this far ahead of the wall clock
	projector          *firewallcontrol.Projector
	redeliverer        *firewallcontrol.Redeliverer
	dispatcher         *Dispatcher
	displayID          int
}

func newRedeliveryFixture(t *testing.T) *redeliveryFixture {
	t.Helper()
	ctx := t.Context()
	f := &redeliveryFixture{pool: databasetest.MigratedPool(t, nil), tenant: uuid.New(), user: uuid.New(), site: uuid.New(),
		node1: uuid.New(), displayID: 98100}
	var platform uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); err != nil {
		platform = uuid.New()
	}
	f.seed(t, func(exec func(string, ...any)) {
		exec(`INSERT INTO control_installation_entitlement(installation_id) SELECT 'fwr-install'
			WHERE NOT EXISTS (SELECT 1 FROM control_installation_entitlement)`)
		exec(`INSERT INTO access_scopes(id,kind) SELECT $1,'platform' WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, platform)
		exec(`INSERT INTO tenants(id,display_name) VALUES($1,'fwr')`, f.tenant)
		exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, f.tenant)
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'fwr','x')`, f.user, "fwr-"+f.user.String()[:8])
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, f.tenant, f.user)
		group := uuid.New()
		exec(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,
			created_at,updated_at,display_id,resolved_value,ipv4_resolved_value)
			VALUES($1::uuid,$2,$3,1,$4::uuid,$4::uuid,now(),now(),98900,'lg-'||replace($1::uuid::text,'-',''),'lg4-'||replace($1::uuid::text,'-',''))`,
			group, platform, "fwr-"+group.String()[:8], f.user)
		exec(`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,
			display_id,node_group_id) VALUES($1,$2,$3,$4,'{203.0.113.20}','{203.0.113.20}',$3,$3,98001,$5)`,
			f.site, f.tenant, f.user, "fwr-"+uuid.NewString()[:8]+".example", group)
	})
	f.addNode(t, f.node1, true)
	var err error
	if f.projector, err = firewallcontrol.NewProjector(f.pool, redeliverySigner{}, firewallcontrol.ProjectorConfig{}); err != nil {
		t.Fatal(err)
	}
	if f.redeliverer, err = firewallcontrol.NewRedeliverer(f.pool, f.projector, firewallcontrol.RedelivererConfig{
		RetryBase: 10 * time.Minute, RetryMaximum: time.Hour, Now: func() time.Time { return time.Now().Add(f.offset) }}, nil); err != nil {
		t.Fatal(err)
	}
	if f.dispatcher, err = newDispatcher(&postgresDB{pool: f.pool}, &fakeMessages{ack: &publishAck{stream: CommandStream, sequence: 1}},
		DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *redeliveryFixture) seed(t *testing.T, statements func(exec func(string, ...any))) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		exec := func(sql string, args ...any) {
			if _, err := tx.Exec(t.Context(), sql, args...); err != nil {
				t.Fatalf("%.90s: %v", sql, err)
			}
		}
		exec(`SET LOCAL session_replication_role = replica`)
		statements(exec)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// addNode adds an active node the tenant owns; online gives it a presence.
func (f *redeliveryFixture) addNode(t *testing.T, node uuid.UUID, online bool) {
	t.Helper()
	f.displayID++
	f.seed(t, func(exec func(string, ...any)) {
		exec(`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,$2,$3,$4,'active',$5)`,
			node, f.displayID, f.tenant, "fwr-"+node.String()[:8], f.user)
		if online {
			digest := sha256.Sum256(node[:])
			exec(`INSERT INTO node_presence(
				node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
				last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
				confirmed_payload_digest,online_since,openresty_state,firewall_state,
				filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
				VALUES($1,'online',1,1,$2,$3,$4,now(),now(),now(),1,1,$2,$3,$4,now(),'running','running',100,50,0,now())`,
				node, uuid.New(), uuid.New(), digest[:])
		}
	})
}

// reinstall records a new initial enrollment of node (a new host, same ID).
func (f *redeliveryFixture) reinstall(t *testing.T, node uuid.UUID) {
	t.Helper()
	certificateID := uuid.New()
	digest := sha256.Sum256(certificateID[:])
	f.seed(t, func(exec func(string, ...any)) {
		exec(`INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,
			serial_number,csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,
			leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at)
			VALUES($1,$2,'initial',$3,$4,$5,$5,$6,clock_timestamp(),clock_timestamp()+interval '2 days',clock_timestamp()+interval '1 day',
			  'test',ARRAY['test'::bytea],$5,'active',clock_timestamp())`, certificateID, node, uuid.New(),
			hex.EncodeToString(digest[:8]), digest[:], "spiffe://cdn-platform/node/"+node.String())
	})
}

// publish stores the next revision of the tenant's policy (one deny on every site).
func (f *redeliveryFixture) publish(t *testing.T, cidr string) {
	t.Helper()
	policy := firewallcontrol.PolicyInput{Enabled: true, DefaultAction: firewallcontrol.ActionAllow, Rules: []firewallcontrol.RuleInput{{
		ID: uuid.New(), Priority: 1, Action: firewallcontrol.ActionDeny, CIDRs: []string{cidr}, Protocol: firewallcontrol.ProtocolAny}}}
	document, _ := json.Marshal(policy)
	digest := sha256.Sum256(document)
	if _, err := firewallcontrol.NewStore(f.pool, redeliveryAuthorizer{}, nil, time.Now).Put(t.Context(), firewallcontrol.PutRequest{
		Actor: firewallcontrol.Actor{UserID: f.user, ScopeID: f.tenant, ScopeKind: firewallcontrol.ScopeTenant,
			Permissions: []string{firewallcontrol.PermissionManage}},
		TargetScopeID: f.tenant, ExpectedRevision: f.revision, Policy: policy, DocumentSHA256: digest,
		IdempotencyKey: "fwr-" + uuid.NewString()[:8], RequestSHA256: sha256.Sum256([]byte(uuid.NewString())), RequestID: uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	f.revision++
}

// project runs one projection pass; it reports whether a publication was projected.
func (f *redeliveryFixture) project(t *testing.T) bool {
	t.Helper()
	projected, err := f.projector.ProjectBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return projected > 0
}

// deliver dispatches every claimable command and ACKs it as applied.
func (f *redeliveryFixture) deliver(t *testing.T) {
	t.Helper()
	for {
		result, err := f.dispatcher.DispatchBatch(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if result.Claimed == 0 {
			break
		}
	}
	rows, err := f.pool.Query(t.Context(), `SELECT id,command_bytes FROM firewall_command_outbox
		WHERE tenant_scope_id=$1 AND state='published' ORDER BY created_at,id`, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	type published struct {
		id    uuid.UUID
		bytes []byte
	}
	commands, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (published, error) {
		var item published
		return item, row.Scan(&item.id, &item.bytes)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range commands {
		status := validStatus(t, claimedCommand{commandBytes: item.bytes})
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.dispatcher.HandleStatus(t.Context(), payload); err != nil {
			t.Fatalf("ACK command %s: %v", item.id, err)
		}
	}
}

// publishActive publishes the next revision and brings it to active on the current nodes.
func (f *redeliveryFixture) publishActive(t *testing.T, cidr string) {
	t.Helper()
	f.publish(t, cidr)
	if !f.project(t) {
		t.Fatal("publication was not projected")
	}
	f.deliver(t)
	f.requirePolicy(t, "active", f.revision)
}

func (f *redeliveryFixture) requirePolicy(t *testing.T, state string, active int64) {
	t.Helper()
	var deployment, publication string
	var activeRevision int64
	if err := f.pool.QueryRow(t.Context(), `SELECT policy.deployment_state,policy.active_revision,outbox.state
		FROM global_firewall_policies policy JOIN global_firewall_publication_outbox outbox
		  ON outbox.tenant_scope_id=policy.tenant_scope_id AND outbox.revision=policy.revision
		WHERE policy.tenant_scope_id=$1`, f.tenant).Scan(&deployment, &activeRevision, &publication); err != nil {
		t.Fatal(err)
	}
	if deployment != state || activeRevision != active || publication != state {
		t.Fatalf("policy deployment=%s active_revision=%d publication=%s, want %s/%d/%s",
			deployment, activeRevision, publication, state, active, state)
	}
}

func (f *redeliveryFixture) sweep(t *testing.T) firewallcontrol.RedeliverySweep {
	t.Helper()
	result, err := f.redeliverer.SweepOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type redeliveryRow struct {
	node              uuid.UUID
	state             string
	delivery          int
	revision          int64
	expected, version int64
	operation         agentv1.FirewallOperation
}

func (f *redeliveryFixture) redeliveries(t *testing.T) []redeliveryRow {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), `SELECT node_id,state,delivery,global_revision,command_bytes FROM firewall_command_outbox
		WHERE tenant_scope_id=$1 AND delivery>0 ORDER BY created_at,id`, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	result, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (redeliveryRow, error) {
		var item redeliveryRow
		var encoded []byte
		if err := row.Scan(&item.node, &item.state, &item.delivery, &item.revision, &encoded); err != nil {
			return item, err
		}
		command := new(agentv1.FirewallCommand)
		if err := proto.Unmarshal(encoded, command); err != nil {
			return item, err
		}
		item.expected, item.version, item.operation = int64(command.ExpectedActivePolicyVersion), int64(command.PolicyVersion), command.Operation
		return item, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// ① A node the tenant owns after the policy went active gets one command of
// the active revision (expecting nothing applied), dispatched and ACKed
// through the real dispatcher; the publication and the policy stay active.
// ③ node1, which applied it, gets nothing; an offline node waits until it
// is online. First registration: the projection writes no redelivery.
func TestRedeliveryReachesNodeOwnedAfterPublication(t *testing.T) {
	f := newRedeliveryFixture(t)
	f.publishActive(t, "192.0.2.0/24")
	if got := f.redeliveries(t); len(got) != 0 {
		t.Fatalf("projection wrote redeliveries: %+v", got)
	}
	if result := f.sweep(t); result.Commands != 0 {
		t.Fatalf("sweep with every node applied created %d commands", result.Commands)
	}
	node2, node3 := uuid.New(), uuid.New()
	f.addNode(t, node2, true)
	f.addNode(t, node3, false)
	if result := f.sweep(t); result.Commands != 1 {
		t.Fatalf("sweep created %d commands, want 1 (node2)", result.Commands)
	}
	got := f.redeliveries(t)
	if len(got) != 1 || got[0].node != node2 || got[0].delivery != 1 || got[0].revision != 1 || got[0].expected != 0 ||
		got[0].version != 1 || got[0].operation != agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY || got[0].state != StatePending {
		t.Fatalf("redeliveries = %+v, want one pending apply of revision 1 to node2 expecting 0", got)
	}
	f.deliver(t)
	f.requirePolicy(t, "active", 1)
	if got := f.redeliveries(t); got[0].state != StateAcked {
		t.Fatalf("redelivery state = %s, want acked", got[0].state)
	}
	var auditCount int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='firewall.policy.redeliver'
		AND actor_kind='system' AND resource_id=$2`, f.tenant, node2.String()).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("redelivery audit events = %d (%v), want 1", auditCount, err)
	}
	if result := f.sweep(t); result.Commands != 0 {
		t.Fatalf("sweep after node2 applied created %d commands", result.Commands)
	}
	f.seed(t, func(exec func(string, ...any)) {
		digest := sha256.Sum256(node3[:])
		exec(`INSERT INTO node_presence(
			node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
			last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
			confirmed_payload_digest,online_since,openresty_state,firewall_state,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
			VALUES($1,'online',1,1,$2,$3,$4,now(),now(),now(),1,1,$2,$3,$4,now(),'running','running',100,50,0,now())`,
			node3, uuid.New(), uuid.New(), digest[:])
	})
	if result := f.sweep(t); result.Commands != 1 {
		t.Fatalf("sweep with node3 online created %d commands, want 1", result.Commands)
	}
}

// ② node1 applied revisions 1 and 2 (active version 2), then was reinstalled
// under the same ID: the new host gets revision 2 expecting 0, and the next
// publication's command expects the new host's version (1), not the old
// host's (2), which the agent would refuse as an active version conflict.
func TestRedeliveryReachesReinstalledNode(t *testing.T) {
	f := newRedeliveryFixture(t)
	f.publishActive(t, "192.0.2.0/24")
	f.publishActive(t, "198.51.100.0/24")
	if result := f.sweep(t); result.Commands != 0 {
		t.Fatalf("sweep before reinstall created %d commands", result.Commands)
	}
	f.reinstall(t, f.node1)
	if result := f.sweep(t); result.Commands != 1 {
		t.Fatalf("sweep after reinstall created %d commands, want 1", result.Commands)
	}
	got := f.redeliveries(t)
	if len(got) != 1 || got[0].node != f.node1 || got[0].revision != 2 || got[0].expected != 0 || got[0].version != 1 {
		t.Fatalf("redeliveries = %+v, want revision 2 to node1 expecting 0", got)
	}
	f.deliver(t)
	f.requirePolicy(t, "active", 2)
	if result := f.sweep(t); result.Commands != 0 {
		t.Fatalf("sweep after the new host applied created %d commands", result.Commands)
	}
	f.publish(t, "203.0.113.0/24")
	if !f.project(t) {
		t.Fatal("revision 3 was not projected")
	}
	var encoded []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT command_bytes FROM firewall_command_outbox
		WHERE tenant_scope_id=$1 AND global_revision=3 AND delivery=0`, f.tenant).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	command := new(agentv1.FirewallCommand)
	if err := proto.Unmarshal(encoded, command); err != nil {
		t.Fatal(err)
	}
	if command.ExpectedActivePolicyVersion != 1 || command.PolicyVersion != 2 {
		t.Fatalf("revision 3 command expects %d -> %d, want 1 -> 2 (the new host's version)",
			command.ExpectedActivePolicyVersion, command.PolicyVersion)
	}
	f.deliver(t)
	f.requirePolicy(t, "active", 3)
}

// ④ A redelivery in flight is not repeated; the next publication waits for
// it (its ACK moves the version the publication's commands expect). Past its
// deadline it fails, the next attempt waits for its backoff.
func TestRedeliveryInFlightIsNotRepeated(t *testing.T) {
	f := newRedeliveryFixture(t)
	f.publishActive(t, "192.0.2.0/24")
	node2 := uuid.New()
	f.addNode(t, node2, true)
	if result := f.sweep(t); result.Commands != 1 {
		t.Fatalf("first sweep created %d commands, want 1", result.Commands)
	}
	if result := f.sweep(t); result.Commands != 0 {
		t.Fatalf("sweep with the redelivery pending created %d commands", result.Commands)
	}
	if _, err := f.dispatcher.DispatchBatch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := f.redeliveries(t); len(got) != 1 || got[0].state != StatePublished {
		t.Fatalf("redeliveries = %+v, want one published", got)
	}
	if result := f.sweep(t); result.Commands != 0 {
		t.Fatalf("sweep with the redelivery published created %d commands", result.Commands)
	}
	f.publish(t, "198.51.100.0/24")
	if f.project(t) {
		t.Fatal("revision 2 was projected while a redelivery was in flight")
	}
	f.deliver(t)
	if !f.project(t) {
		t.Fatal("revision 2 was not projected after the redelivery settled")
	}
	f.deliver(t)
	f.requirePolicy(t, "active", 2)

	// node3's redelivery is never ACKed (published, then the host vanished).
	node3 := uuid.New()
	f.addNode(t, node3, true)
	if result := f.sweep(t); result.Commands != 1 {
		t.Fatalf("sweep for node3 created %d commands, want 1", result.Commands)
	}
	if _, err := f.dispatcher.DispatchBatch(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.offset = 6 * time.Minute // past redeliveryCommandTTL, inside the 10 minute backoff
	if result := f.sweep(t); result.Expired != 1 || result.Commands != 0 {
		t.Fatalf("sweep past the deadline = %+v, want 1 expired and no command (backoff)", result)
	}
	f.offset = 11 * time.Minute
	if result := f.sweep(t); result.Commands != 1 {
		t.Fatalf("sweep after the backoff created %d commands, want 1", result.Commands)
	}
	var states []string
	for _, row := range f.redeliveries(t) {
		if row.node == node3 {
			states = append(states, fmt.Sprintf("%s:%d", row.state, row.delivery))
		}
	}
	if len(states) != 2 || states[0] != StateFailed+":1" || states[1] != StatePending+":2" {
		t.Fatalf("node3 redeliveries = %v, want failed:1 pending:2", states)
	}
}
