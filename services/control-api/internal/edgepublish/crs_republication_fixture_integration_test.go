//go:build integration

package edgepublish

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BindManagedWAF binds a WAF policy running the OWASP CRS managed WAF (the
// SQL injection set) to the scope's site, as a published security activation
// leaves it, and installs the synced catalog's CRS rule text when the
// catalog has none. It advances the scope's source revision.
func (scope *SystemRepublishScope) BindManagedWAF(t *testing.T) {
	t.Helper()
	policy := managedWAFPolicyForEdgeTest(scope.SiteID)
	policy.ID, policy.ScopeID = uuid.New(), scope.ScopeID
	runtime, err := securitypolicy.CompileRuntimeSnapshot(policy, scope.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(policy)
	rules, _ := json.Marshal(policy.Rules)
	documentDigest := sha256.Sum256(document)
	crsBody, err := json.Marshal(CRSRuleCatalogItem(t).Body)
	if err != nil {
		t.Fatal(err)
	}
	bindingID, publicationID := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		var tenantID uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, scope.ScopeID).Scan(&tenantID); err != nil {
			return err
		}
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,revision,
				created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'waf','waf',true,'allow',$5,1,$4,$4,$6,$6)`,
				[]any{policy.ID, scope.ScopeID, tenantID, scope.UserID, rules, now}},
			{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,1,$2,$3,$4)`,
				[]any{policy.ID, document, scope.UserID, now}},
			{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
				last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'waf',1,1,$5,1,$6,$6)`,
				[]any{bindingID, scope.ScopeID, scope.SiteID, policy.ID, publicationID, now}},
			{`INSERT INTO security_policy_publications(id,binding_id,tenant_scope_id,site_id,policy_id,policy_kind,policy_version,
				expected_binding_revision,binding_revision,expected_active_version,rollout_id,idempotency_key,request_digest,plan_request_digest,
				canonical_payload,canonical_payload_sha256,runtime_snapshot_sha256,bundle_bytes,bundle_sha256,signing_key_id,issued_at,expires_at,
				actor_scope_id,actor_user_id,request_id,created_at) VALUES($1,$2,$3,$4,$5,'waf',1,0,1,0,$6,'waf-crs-bundle',$7,$7,$8,$7,$9,$8,$7,
				'fixture-key',$10,$11,$3,$12,'waf-crs-bundle',$10)`,
				[]any{publicationID, bindingID, scope.ScopeID, scope.SiteID, policy.ID, uuid.New(), documentDigest[:], document,
					runtime.SHA256[:], now, now.Add(time.Hour), scope.UserID}},
			{`INSERT INTO security_system_rules(system_key,kind,name,sort,hidden,revision,body,status,delivery_id,first_seen_at,updated_at)
				VALUES($1,'waf_rule_set','OWASP CRS',101,true,1,$2,'active',$3,$4,$4) ON CONFLICT (system_key) DO NOTHING`,
				[]any{CRSRuleCatalogKey, crsBody, uuid.New(), now}},
			{`SELECT advance_edge_configuration_scope_revision($1)`, []any{scope.ScopeID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	SeedCRSProfilePacks(t, scope.Pool)
}

// SeedCRSProfilePacks stores the system/crs-* packs (libs/rulepack goldens)
// as downloaded catalog artifacts, once.
func SeedCRSProfilePacks(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for packID, profile := range crsProfilesForEdgeTest(t) {
		entry, err := artifactcatalog.CRSProfilePackEntry(packID, profile.Profile.Ref.Version, 1, profile.Content, "")
		if err != nil {
			t.Fatal(err)
		}
		// As artifactsynctest.SeedDownloaded (not importable here: import cycle).
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,requires_feature,
				resident,encryption,status,delivery_id,first_seen_at,updated_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,'',true,'none','active',$8,now(),now()) ON CONFLICT (artifact_id) DO NOTHING`,
				[]any{entry.ArtifactID, entry.Kind, entry.Version, int64(entry.Revision), entry.SHA256, entry.Size, entry.MediaType, uuid.New()}},
			{`INSERT INTO artifact_objects(sha256,size,content,stored_at) VALUES($1,$2,$3,now()) ON CONFLICT (sha256) DO NOTHING`,
				[]any{entry.SHA256, entry.Size, profile.Content}},
			{`INSERT INTO local_artifacts(artifact_id,current_revision,current_sha256,current_version,downloaded_at,updated_at)
				VALUES($1,$2,$3,$4,now(),now()) ON CONFLICT (artifact_id) DO NOTHING`,
				[]any{entry.ArtifactID, int64(entry.Revision), entry.SHA256, entry.Version}},
		} {
			if _, err := pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				t.Fatalf("seed CRS profile pack %s: %v", entry.ArtifactID, err)
			}
		}
	}
}

// CRSRuleCatalogItem is the current seed's CRS rule text item.
func CRSRuleCatalogItem(t *testing.T) rulecatalog.Item {
	t.Helper()
	for _, item := range rulecatalog.CurrentSeed() {
		if item.SystemKey == CRSRuleCatalogKey {
			return item
		}
	}
	t.Fatal("seed has no CRS rule text")
	return rulecatalog.Item{}
}

// GrantCRSModule records a new session of nodeID declaring the OWASP CRS
// engine module (WAF_CRS_MODULE v1) besides tcp/udp v6, and that the node
// applied the system/crs-* profile packs from its node artifact set (the
// managed WAF's sites read their pack from the node object store; the
// release is held for a node without it, validateRulePackTargets). WAF v3,
// which a site runtime v2 release requires for the managed WAF, already
// comes with systemRepublishFeatures; declaring it twice makes the node
// ineligible (validateSiteRuntimeV2TargetCapabilities refuses duplicate
// capabilities).
func (scope *SystemRepublishScope) GrantCRSModule(t *testing.T, nodeID uuid.UUID) {
	t.Helper()
	scope.DeclareCRSModule(t, nodeID)
	for packID, profile := range crsProfilesForEdgeTest(t) {
		if _, err := scope.Pool.Exec(t.Context(), `INSERT INTO node_artifact_applied_items(
			node_id,artifact_id,version,item_revision,media_type,sha256,set_revision,applied_at) VALUES($1,$2,$3,1,$4,$5,1,now())
			ON CONFLICT DO NOTHING`, nodeID, "rule_pack/"+packID, profile.Profile.Ref.Version, artifactset.MediaTypeRulePack,
			profile.Profile.Ref.SHA256); err != nil {
			t.Fatalf("applied CRS profile pack %s: %v", packID, err)
		}
	}
}

// DeclareCRSModule is GrantCRSModule before the node applied the CRS
// profile packs: a new node whose node artifact set is still arriving (O2).
func (scope *SystemRepublishScope) DeclareCRSModule(t *testing.T, nodeID uuid.UUID) {
	t.Helper()
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeID, "1.0.35-crs", append(systemRepublishFeatures(6),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE, ApiVersion: 1}))
}

// PublishedCRSFile is the hex SHA-256 of CRS rule file name among the scope
// files of the release the latest publication delivered to nodeID ("" when
// it carries none).
func (scope *SystemRepublishScope) PublishedCRSFile(t *testing.T, nodeID uuid.UUID, name string) string {
	t.Helper()
	var result PublishResult
	if err := scope.Pool.QueryRow(t.Context(), `SELECT rollout_id,config_version_id FROM edge_config_publications
		WHERE configuration_scope_id=$1 ORDER BY source_revision DESC LIMIT 1`, scope.ScopeID).Scan(&result.RolloutID, &result.ConfigVersionID); err != nil {
		t.Fatalf("latest publication rollout: %v", err)
	}
	release := receivedV2Release(t, scope.fixture, result, nodeID, scope.fixture.nodeKeys[nodeID])
	for _, file := range release.Scope.Files {
		if file.Path == edgeconfig.ListenerCRSReleasePath(name) {
			digest := sha256.Sum256(release.Objects[file.SHA256])
			return hex.EncodeToString(digest[:])
		}
	}
	return ""
}

// CatalogCRSFile is the hex SHA-256 the synced catalog pins for CRS rule file name.
func (scope *SystemRepublishScope) CatalogCRSFile(t *testing.T, name string) string {
	t.Helper()
	var digest string
	if err := scope.Pool.QueryRow(t.Context(), `SELECT file->>'sha256' FROM security_system_rules,
		jsonb_array_elements(body#>'{waf_rule_set,bundle,files}') file
		WHERE system_key=$1 AND file->>'name'=$2`, CRSRuleCatalogKey, name).Scan(&digest); err != nil {
		t.Fatalf("catalog CRS file %s: %v", name, err)
	}
	return strings.ToLower(digest)
}
