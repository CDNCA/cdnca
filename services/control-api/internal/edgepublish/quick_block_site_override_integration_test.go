//go:build integration

package edgepublish

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestSiteRuntimeV2QuickBlockSiteOverrideFromDatabase:
// the site's WAF library blocks CN IDC (an IP intelligence rule, which the
// target node cannot run: it does not advertise IP_INTEL). With the site's own
// override turning it off, the release compiles from the database facts with
// the library's user rule only; without the row, it is refused as before.
func TestSiteRuntimeV2QuickBlockSiteOverrideFromDatabase(t *testing.T) {
	fixture := newL4V2ContractFixture(t)
	site := fixture.createSite(t, "quick-block-v2.example.com", 18093, false).Site
	revision := fixture.sourceRevision()
	var tenantID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, fixture.scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	user := securitypolicy.Rule{ID: uuid.MustParse("018f7a5e-0000-7000-8000-00000000b101"), Name: "admin", Priority: 2, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}},
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop}
	block := securitypolicy.QuickBlock{BlockIDCCN: true}
	if err := securitypolicy.NormalizeQuickBlock(&block); err != nil {
		t.Fatal(err)
	}
	policy := securityPolicyForEdgeTest(site.ID, securitypolicy.KindWAF, securitypolicy.ActionAllow, nil)
	policy.ID, policy.ScopeID = uuid.New(), fixture.scopeID
	policy.Rules = securitypolicy.MergeQuickBlockRules(policy.ID, []securitypolicy.Rule{user}, &block)
	policy.QuickBlock = &block
	runtime, err := securitypolicy.CompileRuntimeSnapshot(policy, site.ID)
	if err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(policy)
	rules, _ := json.Marshal(policy.Rules)
	quickBlock, _ := json.Marshal(policy.QuickBlock)
	documentDigest := sha256.Sum256(document)
	bindingID, publicationID := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			// Seeded directly (triggers and foreign keys off): the writers of
			// these facts are not under test.
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,quick_block,revision,
				created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'waf','waf',true,'allow',$5,$6,1,$4,$4,$7,$7)`,
				[]any{policy.ID, fixture.scopeID, tenantID, fixture.userID, rules, quickBlock, now}},
			{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,1,$2,$3,$4)`,
				[]any{policy.ID, document, fixture.userID, now}},
			{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
				last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'waf',1,1,$5,1,$6,$6)`,
				[]any{bindingID, fixture.scopeID, site.ID, policy.ID, publicationID, now}},
			{`INSERT INTO security_policy_publications(id,binding_id,tenant_scope_id,site_id,policy_id,policy_kind,policy_version,
				expected_binding_revision,binding_revision,expected_active_version,rollout_id,idempotency_key,request_digest,plan_request_digest,
				canonical_payload,canonical_payload_sha256,runtime_snapshot_sha256,bundle_bytes,bundle_sha256,signing_key_id,issued_at,expires_at,
				actor_scope_id,actor_user_id,request_id,created_at) VALUES($1,$2,$3,$4,$5,'waf',1,0,1,0,$6,'quick-block-v2',$7,$7,$8,$7,$9,$8,$7,
				'fixture-key',$10,$11,$3,$12,'quick-block-v2',$10)`,
				[]any{publicationID, bindingID, fixture.scopeID, site.ID, policy.ID, uuid.New(), documentDigest[:], document,
					runtime.SHA256[:], now, now.Add(time.Hour), fixture.userID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	seedSiteRuntimeV2Capabilities(t, fixture, "", append(siteRuntimeV2CapabilitiesWithoutSiteRuntime(),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 1}))

	compile := func() (*siteRuntimeV2Document, []*agentv1.Capability, error) {
		t.Helper()
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at)
			VALUES($1,$2,now()) ON CONFLICT DO NOTHING`, fixture.nodeID, fixture.scopeID); err != nil {
			t.Fatal(err)
		}
		canonical, _, _, _, capabilities, _, err := fixture.service.compileSiteRuntimeV2Facts(t.Context(), tx, fixture.scopeID, uuid.New(),
			revision, TargetSnapshot{NodeIDs: []uuid.UUID{fixture.nodeID}}, publishTestClock, nil)
		if err != nil {
			return nil, nil, err
		}
		var runtimeDocument siteRuntimeV2Document
		if err := json.Unmarshal(canonical, &runtimeDocument); err != nil {
			t.Fatal(err)
		}
		return &runtimeDocument, capabilities, nil
	}
	// The library's CN IDC block needs IP intelligence the node lacks.
	var refusal *TargetCapabilityError
	if _, _, err := compile(); !errors.As(err, &refusal) || refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL {
		t.Fatalf("library quick block without node IP intelligence: %v", err)
	}
	// The site's own override turns it off: only the user rule ships.
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO site_quick_block_overrides(scope_id,site_id,override,updated_by_user_id,updated_at)
		VALUES($1,$2,'{"block_idc_cn":false,"block_idc_global":null,"carriers":null,"allowed_crawlers":null}',$3,now())`,
		fixture.scopeID, site.ID, fixture.userID); err != nil {
		t.Fatal(err)
	}
	runtimeDocument, capabilities, err := compile()
	if err != nil {
		t.Fatalf("site override release: %v", err)
	}
	security := runtimeDocument.Sites[0].Listeners[0].Security
	if security == nil || len(security.Policies) != 1 || security.Policies[0].PolicyID != policy.ID.String() ||
		security.Policies[0].PolicyVersion != 1 || len(security.Policies[0].Rules) != 1 ||
		security.Policies[0].Rules[0].RuleID != user.ID.String() {
		t.Fatalf("v2 listener security = %+v", security)
	}
	if siteRuntimeCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL) != 0 {
		t.Fatalf("site override release requires IP intelligence: %v", capabilities)
	}
}
