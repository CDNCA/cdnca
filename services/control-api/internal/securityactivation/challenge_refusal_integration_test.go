//go:build integration

package securityactivation

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// TestChallengeActivationToCCV2NodeIsRefused: one target node declares CC v2
// (1.0.33) and one CC v3. A CC policy with a challenge is refused before
// anything is persisted, naming the CC v2 node, its version and the missing
// feature; there is no compatible variant to publish instead.
func TestChallengeActivationToCCV2NodeIsRefused(t *testing.T) {
	fixture := buildActivationFixture(t, true)
	store := newProductionActivationStore(t, fixture)
	ccPolicyID, ccBindingID := uuid.New(), uuid.New()
	items := map[string]rulecatalog.Item{}
	for _, item := range rulecatalog.CurrentSeed() {
		items[item.SystemKey] = item
	}
	rules, err := securitypolicy.ExpandCCRuleGroup(items, "cc_rule:10001")
	if err != nil {
		t.Fatal(err)
	}
	rules[0].ID = uuid.New()
	policy := securitypolicy.Policy{ID: ccPolicyID, ScopeID: fixture.scopeID, Kind: securitypolicy.KindCC, Name: "pow",
		Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1, Rules: rules}
	document, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	ruleJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		t.Fatal(err)
	}
	session := func(nodeID uuid.UUID, cc uint32, agentVersion string) []any {
		snapshot, err := proto.Marshal(&agentv1.AgentCapabilities{AgentVersion: agentVersion, Features: activationNodeFeaturesWithCC(cc)})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(snapshot)
		return []any{nodeID, uuid.New(), digest[:], snapshot, fixture.now}
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
				created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'cc','pow',true,'allow',$5,1,$4,$4,$6,$6)`,
				[]any{ccPolicyID, fixture.scopeID, fixture.tenantID, fixture.actor.UserID, ruleJSON, fixture.now}},
			{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,1,$2,$3,$4)`,
				[]any{ccPolicyID, document, fixture.actor.UserID, fixture.now}},
			{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
				last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'cc',NULL,NULL,NULL,0,$5,$5)`,
				[]any{ccBindingID, fixture.scopeID, fixture.siteID, ccPolicyID, fixture.now}},
			{`INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,artifact_key_id,
				selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,facts_snapshot,facts_sha256,
				gateway_workload_identity,gateway_instance_id,registered_at) VALUES($1,1,$2,$3,'x25519:test',1,0,$4,$3,'\x01',$3,'gw','gw-1',$5)`,
				session(fixture.canaryNodeID, 2, "1.0.33")},
			{`INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,artifact_key_id,
				selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,facts_snapshot,facts_sha256,
				gateway_workload_identity,gateway_instance_id,registered_at) VALUES($1,1,$2,$3,'x25519:test',1,0,$4,$3,'\x01',$3,'gw','gw-1',$5)`,
				session(fixture.expandNodeID, 3, "1.0.34")},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	start := func(key string) StartInput {
		return StartInput{TenantScopeID: fixture.scopeID, SiteID: fixture.siteID, PolicyID: ccPolicyID, PolicyVersion: 1,
			ExpectedBindingRevision: 0, ExpectedActivePolicyVersion: 0,
			TargetNodeIDs: []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, CanarySize: 1,
			IdempotencyKey: key, RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
			Traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
			ExpiresAt:   fixture.now.Add(10 * 60e9)}
	}

	_, err = store.Start(t.Context(), fixture.actor, start("pow-refused"))
	var refusal *edgepublish.TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID != fixture.canaryNodeID || refusal.AgentVersion != "1.0.33" ||
		refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_CC || refusal.Required != 3 || refusal.Advertised != 2 {
		t.Fatalf("challenge release to a CC v2 node = %v", err)
	}
	var publications int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM security_policy_publications WHERE policy_id=$1`,
		ccPolicyID).Scan(&publications); err != nil || publications != 0 {
		t.Fatalf("refused release persisted %d publications, %v", publications, err)
	}

}
