package cccoord

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeFactCanonicalizesOnlyBoundedHostCIDR(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 123456789, time.UTC)
	input := Fact{
		MessageID: "batch-1", EventID: "event-1", TenantScopeID: uuid.New(), SiteID: uuid.New(),
		NodeID: uuid.New(), ConfigVersionID: uuid.New(), RuleID: uuid.New(), ClientCIDR: "2001:0db8::1",
		Host: "edge.example.test", Path: "/login", Method: "POST", ListenerPort: 443,
		Protocol: "https", RequestClass: RequestClassStandard,
		Action: "block", StatusCode: 429, OccurredAt: now,
	}
	got, err := normalizeFact(input)
	if err != nil || got.ClientCIDR != "2001:db8::1/128" || got.OccurredAt.Nanosecond() != 123456000 {
		t.Fatalf("normalizeFact() = (%+v, %v)", got, err)
	}
	for _, invalid := range []string{"0.0.0.0/0", "::/0", "224.0.0.0/4", "fe80::/10", "invalid"} {
		candidate := input
		candidate.ClientCIDR = invalid
		if _, err := normalizeFact(candidate); err == nil {
			t.Fatalf("invalid client CIDR %q accepted", invalid)
		}
	}
}

func TestNormalizeSettingsRequiresSourceCCAndStrictNodeSet(t *testing.T) {
	tenant, site, source := uuid.New(), uuid.New(), uuid.New()
	nodeA, nodeB := uuid.New(), uuid.New()
	input := Settings{
		ID: uuid.New(), TenantScopeID: tenant, SiteID: site, SourceCCPolicyID: source,
		SourcePolicyVersion: 1, ActorScopeID: tenant, ActorUserID: uuid.New(), Revision: 1,
		TargetNodeIDs: []uuid.UUID{nodeB, nodeA}, HitThreshold: 20, NodeThreshold: 2,
		WindowSeconds: 60, BlockSeconds: 300, ReleaseHoldSecond: 600, FactTTLSeconds: 600,
		MaxFactsPerMessage: 1000, MaxActiveStates: 100000, MaxClaims: 64, MaxAttempts: 8, Enabled: true,
	}
	got, err := normalizeSettings(input)
	if err != nil || len(got.TargetNodeIDs) != 2 || got.TargetNodeIDs[0].String() > got.TargetNodeIDs[1].String() {
		t.Fatalf("normalizeSettings() = (%+v, %v)", got, err)
	}
	input.TargetNodeIDs = []uuid.UUID{nodeA, nodeA}
	if _, err := normalizeSettings(input); err == nil {
		t.Fatal("duplicate target nodes accepted")
	}
}

func TestExcludedRequestClassesNeverBecomeAutomaticActions(t *testing.T) {
	for _, class := range []string{RequestClassWebSocket, RequestClassSSE, RequestClassTaskStream,
		RequestClassImport, RequestClassACME, RequestClassHealth} {
		if automaticEligible(class) {
			t.Fatalf("request class %q became eligible for automatic cross-node mitigation", class)
		}
	}
	if !automaticEligible(RequestClassStandard) {
		t.Fatal("standard request class is not eligible")
	}
}

func TestDefaultConfigBoundsCrossNodeAndDurableState(t *testing.T) {
	config := DefaultConfig()
	if err := config.validate(); err != nil || config.NodeThreshold < 2 || config.FactTTL < config.Window ||
		config.ReleaseHold < config.BlockTTL || config.MaxActiveStates < 1 || config.MaxAttempts > 16 {
		t.Fatalf("DefaultConfig() = %+v, err=%v", config, err)
	}
}
