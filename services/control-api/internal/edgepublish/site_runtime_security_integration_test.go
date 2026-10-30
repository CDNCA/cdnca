//go:build integration

package edgepublish

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestSiteRuntimeV2CompilesManagedWAFAndChallenge: one site with a WAF policy
// that runs the OWASP CRS managed WAF and an active JS challenge binding.
// Site runtime v2 carries both on the listener, requires site runtime v6 and
// ships exactly the synced catalog's CRS rule files the managed WAF loads.
func TestSiteRuntimeV2CompilesManagedWAFAndChallenge(t *testing.T) {
	fixture := newL4V2ContractFixture(t)
	site := fixture.createSite(t, "secure-v2.example.com", 18091, false).Site
	revision := fixture.sourceRevision()
	var tenantID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, fixture.scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	policy := managedWAFPolicyForEdgeTest(site.ID)
	policy.ID, policy.ScopeID = uuid.New(), fixture.scopeID
	runtime, err := securitypolicy.CompileRuntimeSnapshot(policy, site.ID)
	if err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(policy)
	rules, _ := json.Marshal(policy.Rules)
	documentDigest := sha256.Sum256(document)
	var crsItem rulecatalog.Item
	for _, item := range rulecatalog.CurrentSeed() {
		if item.SystemKey == "waf_set:crs_rules" {
			crsItem = item
		}
	}
	crsBody, err := json.Marshal(crsItem.Body)
	if err != nil || crsItem.SystemKey == "" {
		t.Fatalf("CRS catalog item: %v", err)
	}
	bindingID, publicationID, challengePolicyID := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			// Seeded directly (triggers and foreign keys off): the writers of
			// these facts are not under test.
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,revision,
				created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'waf','waf',true,'allow',$5,1,$4,$4,$6,$6)`,
				[]any{policy.ID, fixture.scopeID, tenantID, fixture.userID, rules, now}},
			{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,1,$2,$3,$4)`,
				[]any{policy.ID, document, fixture.userID, now}},
			{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
				last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'waf',1,1,$5,1,$6,$6)`,
				[]any{bindingID, fixture.scopeID, site.ID, policy.ID, publicationID, now}},
			{`INSERT INTO security_policy_publications(id,binding_id,tenant_scope_id,site_id,policy_id,policy_kind,policy_version,
				expected_binding_revision,binding_revision,expected_active_version,rollout_id,idempotency_key,request_digest,plan_request_digest,
				canonical_payload,canonical_payload_sha256,runtime_snapshot_sha256,bundle_bytes,bundle_sha256,signing_key_id,issued_at,expires_at,
				actor_scope_id,actor_user_id,request_id,created_at) VALUES($1,$2,$3,$4,$5,'waf',1,0,1,0,$6,'waf-v2-bundle',$7,$7,$8,$7,$9,$8,$7,
				'fixture-key',$10,$11,$3,$12,'waf-v2-bundle',$10)`,
				[]any{publicationID, bindingID, fixture.scopeID, site.ID, policy.ID, uuid.New(), documentDigest[:], document,
					runtime.SHA256[:], now, now.Add(time.Hour), fixture.userID}},
			{`INSERT INTO challenge_site_bindings_138(tenant_scope_id,tenant_id,site_id,host,active_binding_revision,created_at,updated_at)
				VALUES($1,$2,$3,'secure-v2.example.com',1,$4,$4)`, []any{fixture.scopeID, tenantID, site.ID, now}},
			{`INSERT INTO challenge_site_binding_revisions_138(tenant_scope_id,tenant_id,site_id,host,binding_revision,policy_id,
				policy_revision,secret_rollout_id,secret_config_version_id,secret_revision,state,idempotency_key,request_digest,request_id,
				correlation_id,actor_scope_id,actor_user_id,created_at) VALUES($1,$2,$3,'secure-v2.example.com',1,$4,7,$5,$6,1,'candidate',
				'challenge-v2',decode(repeat('00',32),'hex'),'challenge-v2','challenge-v2',$1,$7,$8)`,
				[]any{fixture.scopeID, tenantID, site.ID, challengePolicyID, uuid.New(), uuid.New(), fixture.userID, now}},
			{`INSERT INTO security_system_rules(system_key,kind,name,sort,hidden,revision,body,status,delivery_id,first_seen_at,updated_at)
				VALUES('waf_set:crs_rules','waf_rule_set','OWASP CRS',101,true,1,$1,'active',$2,$3,$3)`, []any{crsBody, uuid.New(), now}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	SeedCRSProfilePacks(t, fixture.pool)

	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	seedSiteRuntimeV2Capabilities(t, fixture, "", append(siteRuntimeV2CapabilitiesWithoutSiteRuntime(),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: edgeconfig.WAFAdaptiveAPIVersion}))
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at)
		VALUES($1,$2,now()) ON CONFLICT DO NOTHING`, fixture.nodeID, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	canonical, _, bundle, _, capabilities, _, err := fixture.service.compileSiteRuntimeV2Facts(t.Context(), tx, fixture.scopeID, uuid.New(),
		revision, TargetSnapshot{NodeIDs: []uuid.UUID{fixture.nodeID}}, publishTestClock, nil)
	if err != nil {
		t.Fatalf("site runtime v2: %v", err)
	}
	var runtimeDocument siteRuntimeV2Document
	if err := json.Unmarshal(canonical, &runtimeDocument); err != nil {
		t.Fatal(err)
	}
	security := runtimeDocument.Sites[0].Listeners[0].Security
	if security == nil || security.ManagedWAF == nil || security.Challenge == nil {
		t.Fatalf("v2 listener security = %+v", security)
	}
	if *security.Challenge != (edgeconfig.ListenerChallenge{TenantID: tenantID.String(), PolicyID: challengePolicyID.String(),
		PolicyVersion: 7}) {
		t.Fatalf("v2 challenge %+v (tenant %s, policy %s)", security.Challenge, tenantID, challengePolicyID)
	}
	_, compiled, err := compileSiteFact(fixture.scopeID, siteRuntimeSecurityTestFact(site.ID), 18091, nil,
		[]securityBindingFact{securityBindingForEdgeTest(t, policy, site.ID, 1)}, nil)
	if err != nil || compiled.ManagedWAF == nil {
		t.Fatalf("managed WAF policy: %v", err)
	}
	canonicalManaged, _ := edgeconfig.CanonicalListenerManagedWAF(*compiled.ManagedWAF)
	got, _ := json.Marshal(security.ManagedWAF)
	want, _ := json.Marshal(canonicalManaged)
	if string(got) != string(want) {
		t.Fatalf("v2 managed WAF differs from the policy\n%s\n%s", got, want)
	}
	if siteRuntimeCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME) != edgeconfig.DynamicRoutingSiteRuntimeVersion ||
		!slices.Contains(runtimeDocument.RequiredCapabilities, siteRuntimeV2Capability{Name: "site_runtime", APIVersion: 6}) {
		t.Fatalf("v2 capabilities = %v, document %v", capabilities, runtimeDocument.RequiredCapabilities)
	}
	// The pinned CRS files of the synced catalog and the selected profile
	// pack, as the release carries them.
	inputs, err := loadCRSInputs(t.Context(), tx)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := edgeconfig.ListenerCRSProfiles(siteRuntimeSecurityListeners(runtimeDocument))
	if err != nil || len(refs) != 1 {
		t.Fatalf("selected CRS profiles = %v, %v", refs, err)
	}
	var selected []edgeconfig.CRSProfile
	for _, profile := range inputs.Profiles {
		if profile.Profile.Ref == refs[0] {
			selected = append(selected, profile.Profile)
		}
	}
	pinned, err := edgeconfig.ListenerCRSReleaseFiles(siteRuntimeSecurityListeners(runtimeDocument), inputs.RuleText, selected)
	if err != nil || len(pinned) == 0 {
		t.Fatalf("pinned CRS files: %d, %v", len(pinned), err)
	}
	crs := len(pinned)
	for path, content := range pinned {
		if string(bundle.Files[path]) != string(content) {
			t.Fatalf("v2 bundle CRS file %s differs from the catalog", path)
		}
	}
	packs := 0
	for path := range bundle.Files {
		if _, pack := edgeconfig.ListenerCRSProfileDigest(path); pack {
			packs++ // the selected CRS profile pack (PA-12)
			continue
		}
		if strings.HasPrefix(path, "security/modsecurity/") && !strings.HasPrefix(path, edgeconfig.ListenerCRSReleasePath("")) {
			t.Fatalf("v2 bundle carries node-rendered file %s", path)
		}
		if strings.HasPrefix(path, edgeconfig.ListenerCRSReleasePath("")) {
			crs--
		}
	}
	if packs != 1 {
		t.Fatalf("v2 bundle carries %d CRS profile packs", packs)
	}
	if crs != 0 {
		t.Fatalf("v2 bundle CRS file count differs from the catalog by %d", crs)
	}
}
