package securitypublication

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// testdata/stored-1.0.33-challenge.source.json is a runtime snapshot as release
// 1.0.33 stored a challenge policy (no proof-of-work parameters).
func readEdge133Fixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// TestStoredEdge133ChallengeSnapshotIsRefused: the 1.0.35 baseline does not
// read challenge policies stored by 1.0.33; their runtime snapshot is invalid
// and a policy built from it does not compile.
func TestStoredEdge133ChallengeSnapshotIsRefused(t *testing.T) {
	source := readEdge133Fixture(t, "stored-1.0.33-challenge.source.json")
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	var snapshot securitypolicy.RuntimeSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if err := securitypolicy.ValidateRuntimeSnapshot(snapshot); err == nil {
		t.Fatal("stored 1.0.33 runtime snapshot accepted")
	}
	rules := make([]securitypolicy.Rule, len(snapshot.Rules))
	for index, rule := range snapshot.Rules {
		rules[index] = securitypolicy.Rule{ID: rule.ID, Name: "stored", Priority: rule.Priority, Enabled: rule.Enabled,
			Conditions: rule.Conditions, Action: rule.Action, Flow: rule.Flow, ActionConfig: rule.ActionConfig}
	}
	policy := securitypolicy.Policy{ID: snapshot.PolicyID, ScopeID: snapshot.TenantScopeID, Kind: snapshot.Kind,
		Name: "stored", Enabled: snapshot.Enabled, DefaultAction: snapshot.DefaultAction, Revision: snapshot.PolicyVersion, Rules: rules}
	if _, err := securitypolicy.CompileRuntimeSnapshot(policy, snapshot.SiteID); err == nil {
		t.Fatal("stored 1.0.33 challenge policy compiled")
	}
}

// TestChallengeCompilesWithProofOfWorkFields: a challenge compiles to a CC v3
// policy that carries every proof-of-work field.
func TestChallengeCompilesWithProofOfWorkFields(t *testing.T) {
	policy := securitypolicy.Policy{ID: uuid.New(), ScopeID: testTenantScopeID, Kind: securitypolicy.KindCC, Name: "challenge",
		Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1, Rules: []securitypolicy.Rule{{
			ID: uuid.New(), Name: "challenge", Priority: 1, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
			Action:     securitypolicy.ActionChallenge, Flow: securitypolicy.FlowStop,
			ActionConfig: securitypolicy.ActionConfig{Challenge: &securitypolicy.ChallengeConfig{Type: "js",
				FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 21600, BanSeconds: 360, PowBits: 16,
				ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400}},
		}}}
	compiled, err := securitypolicy.CompileRuntimeSnapshot(policy, uuid.MustParse("018f1000-0000-7000-8000-000000000002"))
	if err != nil {
		t.Fatal(err)
	}
	site := baseSite()
	site.ID = "018f1000-0000-7000-8000-000000000002"
	result, err := CompileSiteSecurityBindings(site, testTenantScopeID, uuid.MustParse(site.ID), []ActiveBinding{{
		BindingID: uuid.New(), BindingRevision: 1, PublicationID: uuid.New(),
		RuntimeSnapshotSHA256: compiled.SHA256, Snapshot: compiled.Snapshot}})
	if err != nil {
		t.Fatal(err)
	}
	if !edgeconfig.CCV2PolicyNeedsProofOfWork(result.Site.CCV2.Policy) {
		t.Fatal("challenge compiled without proof of work")
	}
	encoded, err := edgeconfig.CanonicalCCV2Policy(result.Site.CCV2.Policy)
	if err != nil || !bytes.Contains(encoded, []byte(`"pow_bits":16`)) || !bytes.Contains(encoded, []byte(`"challenge_seconds":120`)) {
		t.Fatalf("compiled policy = %s, %v", encoded, err)
	}
}
