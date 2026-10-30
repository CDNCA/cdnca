//go:build integration

package securityactivation

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// TestCountByActivationWaitsForCCV4AndResumesAfterUpgrade (G1-c): both
// target nodes run CC v3 (1.0.34). Activating a CC policy that counts by
// client network
//   - is refused before anything is published, naming both nodes, and the
//     request is recorded as waiting for node capability;
//   - stays waiting while the nodes still declare CC v3;
//   - is started by the activation worker once both nodes' latest sessions
//     declare CC v4 (node upgrade), with CC v4 required, and the wait is
//     marked resumed with that candidate.
func TestCountByActivationWaitsForCCV4AndResumesAfterUpgrade(t *testing.T) {
	fixture := buildActivationFixture(t, true)
	store := newProductionActivationStore(t, fixture)
	ccPolicyID, ccBindingID := uuid.New(), uuid.New()
	policy := securitypolicy.Policy{ID: ccPolicyID, ScopeID: fixture.scopeID, Kind: securitypolicy.KindCC, Name: "cidr",
		Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1, Rules: []securitypolicy.Rule{{
			ID: uuid.New(), Name: "cidr", Priority: 1, Enabled: true, Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
			ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
				WindowSeconds: 10, MaxRequests: 30, ResponseAction: "reject_429"}},
			CountBy: []securitypolicy.CountKey{{Key: securitypolicy.CountKeyClientCIDR, IPv4Prefix: 24, IPv6Prefix: 64}},
		}}}
	if err := securitypolicy.ValidatePublishablePolicy(policy); err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	ruleJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		t.Fatal(err)
	}
	sessions := func(epoch int64, cc uint32, agentVersion string) error {
		return pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			for _, nodeID := range []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID} {
				snapshot, err := proto.Marshal(&agentv1.AgentCapabilities{AgentVersion: agentVersion,
					Features: activationNodeFeaturesWithCC(cc)})
				if err != nil {
					return err
				}
				digest := sha256.Sum256(snapshot)
				if _, err := tx.Exec(t.Context(), `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,
					certificate_sha256,artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
					capabilities_sha256,facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
					VALUES($1,$2,$3,$4,'x25519:test',1,0,$5,$4,'\x01',$4,'gw','gw-1',$6)`,
					nodeID, epoch, uuid.New(), digest[:], snapshot, fixture.now); err != nil {
					return err
				}
			}
			return nil
		})
	}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`UPDATE security_policy_publication_targets SET released_at=$2,release_reason='completed'
				WHERE publication_id=$1 AND released_at IS NULL`, []any{fixture.bundleID, fixture.now}},
			{`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,revision,
				created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'cc','cidr',true,'allow',$5,1,$4,$4,$6,$6)`,
				[]any{ccPolicyID, fixture.scopeID, fixture.tenantID, fixture.actor.UserID, ruleJSON, fixture.now}},
			{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,1,$2,$3,$4)`,
				[]any{ccPolicyID, document, fixture.actor.UserID, fixture.now}},
			{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
				last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'cc',NULL,NULL,NULL,0,$5,$5)`,
				[]any{ccBindingID, fixture.scopeID, fixture.siteID, ccPolicyID, fixture.now}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := sessions(1, 3, "1.0.34"); err != nil {
		t.Fatal(err)
	}

	_, err = store.Start(t.Context(), fixture.actor, StartInput{TenantScopeID: fixture.scopeID, SiteID: fixture.siteID,
		PolicyID: ccPolicyID, PolicyVersion: 1, TargetNodeIDs: []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID},
		CanarySize: 1, IdempotencyKey: "count-by-refused", RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
		Traceparent: "00-11111111111111111111111111111111-2222222222222222-01", ExpiresAt: fixture.now.Add(10 * 60e9)})
	var refusal *edgepublish.TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_CC ||
		refusal.Required != 4 || refusal.Advertised != 3 || len(refusal.OtherNodeIDs) != 1 || !refusal.AutoResume {
		t.Fatalf("count_by release to CC v3 nodes = %v (%+v)", err, refusal)
	}
	var publications int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM security_policy_publications WHERE policy_id=$1`,
		ccPolicyID).Scan(&publications); err != nil || publications != 0 {
		t.Fatalf("refused release persisted %d publications, %v", publications, err)
	}
	waitState := func() (string, int, *uuid.UUID) {
		var status string
		var blocking []uuid.UUID
		var candidate *uuid.UUID
		if err := fixture.pool.QueryRow(t.Context(), `SELECT status,blocking_node_ids,resumed_candidate_id
			FROM security_activation_capability_waits WHERE site_id=$1 AND policy_id=$2`, fixture.siteID, ccPolicyID).
			Scan(&status, &blocking, &candidate); err != nil {
			t.Fatalf("capability wait: %v", err)
		}
		return status, len(blocking), candidate
	}
	if status, blocking, _ := waitState(); status != "waiting" || blocking != 2 {
		t.Fatalf("wait = %s with %d blocking nodes", status, blocking)
	}
	status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindCC)
	if err != nil || status.CapabilityWait == nil || len(status.CapabilityWait.NodeIDs) != 2 ||
		status.CapabilityWait.RequiredCCVersion != 4 || status.CapabilityWait.PolicyVersion != 1 {
		t.Fatalf("status capability wait = %+v, %v", status.CapabilityWait, err)
	}

	worker, err := NewWorker(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatalf("reconcile while nodes run CC v3: %v", err)
	}
	if status, _, _ := waitState(); status != "waiting" {
		t.Fatalf("wait resumed before the upgrade: %s", status)
	}

	if err := sessions(2, 4, "1.0.35"); err != nil {
		t.Fatal(err)
	}
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatalf("reconcile after the upgrade: %v", err)
	}
	waiting, _, candidateID := waitState()
	if waiting != "resumed" || candidateID == nil {
		t.Fatalf("wait after the upgrade = %s, candidate %v", waiting, candidateID)
	}
	candidate, err := store.Get(t.Context(), fixture.actor, *candidateID)
	if err != nil {
		t.Fatal(err)
	}
	cc := uint32(0)
	for _, capability := range candidate.RequiredCapabilities {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC {
			cc = capability.GetApiVersion()
		}
	}
	if cc != 4 || candidate.LastClaimedPolicyVersion != 1 {
		t.Fatalf("resumed candidate requires CC v%d, policy v%d", cc, candidate.LastClaimedPolicyVersion)
	}
	if status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindCC); err != nil || status.CapabilityWait != nil {
		t.Fatalf("status still waiting after resume: %+v, %v", status.CapabilityWait, err)
	}
}
