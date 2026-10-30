package entitlementguard

import (
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

func TestCommunityModulesExcludeCommercial(t *testing.T) {
	codes := communityModuleCodes()
	for _, excluded := range communityExcludedModules {
		if slices.Contains(codes, excluded) {
			t.Fatalf("community grants commercial module %s", excluded)
		}
	}
	for _, code := range []string{"pack.crs", "pack.cc.advanced", "pack.selfwaf", "module.payment.alipay", "module.billing.bridge"} {
		if slices.Contains(codes, code) || communityGrants(code) {
			t.Fatalf("community grants %s", code)
		}
	}
	if slices.Contains(codes, entitlement.ModuleEscalate) || communityGrants(entitlement.ModuleEscalate) {
		t.Fatalf("community grants %s", entitlement.ModuleEscalate)
	}
	for _, free := range []string{"module.sms.aliyun", "module.ipintel.dnspup"} {
		if !slices.Contains(codes, free) {
			t.Fatalf("community misses %s: %v", free, codes)
		}
	}
	if !communityGrants(FeatureSitesManage) || !communityGrants(FeatureNodesManage) || communityGrants("module.aggregated_edge") {
		t.Fatal("community feature grants are wrong")
	}
	if features := communityFeatures(); !features[FeatureSitesManage] || features[entitlement.ModuleAutoDefense] {
		t.Fatalf("community features %v", features)
	}
}

// Edge and ACME publication accept a decision only with a lease serial and
// outside grace: the built-in community entitlement must satisfy both.
func TestCommunityDecisionLooksLikeAValidLease(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	guard := NewGuard(nil, func() time.Time { return now }, nil)
	decision, err := guard.communityFeatureDecision(t.Context(), nil, FeatureCheck{Feature: FeatureSitesManage})
	if err != nil {
		t.Fatal(err)
	}
	if decision.LeaseSerial != CommunityLeaseSerial || !decision.EvaluatedAt.Equal(now) ||
		!decision.EvaluatedAt.Before(decision.ExpiresAt) || decision.NotBefore.After(now) {
		t.Fatalf("community decision = %+v", decision)
	}
}
