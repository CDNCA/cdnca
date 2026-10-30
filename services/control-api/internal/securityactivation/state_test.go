package securityactivation

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func TestDefaultConfigRequiresWAFV1AndCCV2(t *testing.T) {
	config := DefaultConfig()
	if config.RequiredWAFAPIVersion != 1 || config.RequiredCCAPIVersion != 2 {
		t.Fatalf("default API versions = WAF %d, CC %d, want WAF 1 and CC 2",
			config.RequiredWAFAPIVersion, config.RequiredCCAPIVersion)
	}
	if err := config.validate(); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	for _, version := range []uint32{0, 1, 3} {
		invalid := config
		invalid.RequiredCCAPIVersion = version
		if err := invalid.validate(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("CC API version %d error = %v, want ErrInvalidInput", version, err)
		}
	}
	invalid := config
	invalid.RequiredWAFAPIVersion = 2
	if err := invalid.validate(); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("WAF API version 2 error = %v, want ErrInvalidInput", err)
	}
}

func TestReconcileDecisionRequiresCompleteOrderedHealthyPhases(t *testing.T) {
	tests := []struct {
		name    string
		status  CandidateStatus
		expired bool
		canary  phaseFacts
		expand  phaseFacts
		want    reconcileAction
	}{
		{name: "claimed waits", status: StatusClaimed, want: actionWait},
		{name: "canary waits for every receipt", status: StatusCanary, canary: phaseFacts{total: 2, healthy: 1}, want: actionWait},
		{name: "canary failure is terminal", status: StatusCanary, canary: phaseFacts{total: 2, healthy: 1, failed: 1}, want: actionFail},
		{name: "cancelled is terminal", status: StatusCanary, canary: phaseFacts{total: 2, healthy: 1, cancelled: 1}, want: actionCancel},
		{name: "canary expands only when complete", status: StatusCanary, canary: phaseFacts{total: 2, healthy: 2}, expand: phaseFacts{total: 2}, want: actionExpand},
		{name: "all targets in canary promote when healthy", status: StatusCanary, canary: phaseFacts{total: 2, healthy: 2}, want: actionPromote},
		{name: "expansion partial success waits", status: StatusExpanding, canary: phaseFacts{total: 1, healthy: 1}, expand: phaseFacts{total: 2, healthy: 1}, want: actionWait},
		{name: "expansion failure blocks promotion", status: StatusExpanding, canary: phaseFacts{total: 1, healthy: 1}, expand: phaseFacts{total: 2, healthy: 1, failed: 1}, want: actionFail},
		{name: "all frozen targets healthy promotes", status: StatusExpanding, canary: phaseFacts{total: 1, healthy: 1}, expand: phaseFacts{total: 2, healthy: 2}, want: actionPromote},
		{name: "expired never promotes", status: StatusExpanding, expired: true, canary: phaseFacts{total: 1, healthy: 1}, expand: phaseFacts{total: 2, healthy: 2}, want: actionExpire},
		{name: "duplicate healthy cannot inflate total", status: StatusExpanding, canary: phaseFacts{total: 1, healthy: 2}, expand: phaseFacts{total: 1, healthy: 1}, want: actionFail},
		{name: "failed remains terminal after late healthy", status: StatusFailed, canary: phaseFacts{total: 1, healthy: 1}, expand: phaseFacts{total: 1, healthy: 1}, want: actionNone},
		{name: "promoted remains terminal", status: StatusPromoted, want: actionNone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := decideReconcile(test.status, test.expired, test.canary, test.expand)
			if got != test.want {
				t.Fatalf("decideReconcile() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPromotionCASRequiresExactCandidateIdentity(t *testing.T) {
	valid := PromotionCAS{
		TenantScopeID: uuid.New(), BindingID: uuid.New(), BindingRevision: 4,
		LastBundleID: uuid.New(), LastClaimedPolicyVersion: 9, ExpectedActivePolicyVersion: 7,
		CandidateSourceRevision: 12, CandidateConfigVersionID: uuid.New(),
		CandidateArtifactSHA256: sha256.Sum256([]byte("artifact")),
		TargetSnapshotSHA256:    sha256.Sum256([]byte("targets")),
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid promotion CAS rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*PromotionCAS)
	}{
		{name: "scope", mutate: func(value *PromotionCAS) { value.TenantScopeID = uuid.Nil }},
		{name: "binding", mutate: func(value *PromotionCAS) { value.BindingID = uuid.Nil }},
		{name: "binding revision", mutate: func(value *PromotionCAS) { value.BindingRevision = 0 }},
		{name: "bundle", mutate: func(value *PromotionCAS) { value.LastBundleID = uuid.Nil }},
		{name: "claimed version", mutate: func(value *PromotionCAS) { value.LastClaimedPolicyVersion = 0 }},
		{name: "source revision", mutate: func(value *PromotionCAS) { value.CandidateSourceRevision = 0 }},
		{name: "config", mutate: func(value *PromotionCAS) { value.CandidateConfigVersionID = uuid.Nil }},
		{name: "artifact", mutate: func(value *PromotionCAS) { value.CandidateArtifactSHA256 = [32]byte{} }},
		{name: "targets", mutate: func(value *PromotionCAS) { value.TargetSnapshotSHA256 = [32]byte{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.mutate(&value)
			if err := value.validate(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("validate error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestCanonicalTargetSnapshotDigestIsOrderIndependentAndScoped(t *testing.T) {
	scopeID, siteID := uuid.New(), uuid.New()
	first, second := uuid.New(), uuid.New()
	left, nodes, err := canonicalTargetSnapshot(scopeID, siteID, []uuid.UUID{second, first})
	if err != nil {
		t.Fatal(err)
	}
	right, _, err := canonicalTargetSnapshot(scopeID, siteID, []uuid.UUID{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if left != right || len(nodes) != 2 || string(nodes[0][:]) > string(nodes[1][:]) {
		t.Fatal("target snapshot was not canonical")
	}
	other, _, err := canonicalTargetSnapshot(scopeID, uuid.New(), []uuid.UUID{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if other == left {
		t.Fatal("site identity did not affect target snapshot digest")
	}
	if _, _, err := canonicalTargetSnapshot(scopeID, siteID, []uuid.UUID{first, first}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate target error = %v", err)
	}
}

func TestRollbackCopiesOldSemanticsIntoNewMonotonicVersion(t *testing.T) {
	old := securitypolicy.Policy{
		ID: uuid.New(), ScopeID: uuid.New(), Kind: securitypolicy.KindWAF, Revision: 3,
		Name: "old", Enabled: true, DefaultAction: securitypolicy.ActionAllow,
		Rules: []securitypolicy.Rule{{ID: uuid.New(), Name: "block", Priority: 1, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/private"}}},
			Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop}},
	}
	rolled, err := cloneRollbackPolicy(old, 8)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Revision != 8 || rolled.Revision <= old.Revision || rolled.ID != old.ID || rolled.Kind != old.Kind || len(rolled.Rules) != 1 {
		t.Fatalf("rollback policy = %+v", rolled)
	}
	rolled.Rules[0].Conditions[0].Values[0] = "/changed"
	if old.Rules[0].Conditions[0].Values[0] != "/private" {
		t.Fatal("rollback clone aliases historical semantics")
	}
	if _, err := cloneRollbackPolicy(old, old.Revision); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-monotonic rollback error = %v", err)
	}
}
