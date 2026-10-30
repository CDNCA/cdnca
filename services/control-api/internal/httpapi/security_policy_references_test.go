package httpapi

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/ccreference"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func TestProjectCCMatchersUsesStableRowsAndPreservesConditions(t *testing.T) {
	policyID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	ruleID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	scopeID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	createdAt := time.Date(2026, 8, 22, 1, 2, 3, 0, time.UTC)
	policy := securitypolicy.Policy{
		ID: policyID, ScopeID: scopeID, Name: "登录保护", Enabled: true, CreatedAt: createdAt,
		Rules: []securitypolicy.Rule{{
			ID: ruleID, Name: "阻止登录", Priority: 10, Enabled: true,
			Conditions: []securitypolicy.Condition{
				{Field: "path", Operator: "prefix", Values: []string{"/login"}},
				{Field: "country", Operator: "equals", Values: []string{"CN"}},
			},
		}},
	}

	first := projectCCReferences([]securitypolicy.Policy{policy}, ccReferenceMatcher)
	second := projectCCReferences([]securitypolicy.Policy{policy}, ccReferenceMatcher)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("matcher rows = %d/%d, want two", len(first), len(second))
	}
	if first[0].ID != second[0].ID || first[0].PolicyID != policyID || first[0].RuleID != ruleID {
		t.Fatalf("matcher identity is not stable: %#v %#v", first[0], second[0])
	}
	byField := map[string]ccReference{}
	for _, item := range first {
		byField[item.Field] = item
	}
	pathItem := byField["path"]
	if pathItem.Name != "阻止登录 · path" || pathItem.Operator != "prefix" || pathItem.Status != "enabled" {
		t.Fatalf("matcher projection = %#v", pathItem)
	}
	if !pathItem.CreatedAt.Equal(createdAt) || pathItem.SystemRule {
		t.Fatalf("matcher metadata = %#v", pathItem)
	}
}

func TestProjectCCFiltersOnlyProjectsRealFilterActions(t *testing.T) {
	policy := securitypolicy.Policy{
		ID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), ScopeID: uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		Name: "CC", Enabled: true, Rules: []securitypolicy.Rule{
			{ID: uuid.MustParse("66666666-6666-4666-8666-666666666666"), Name: "限速", Enabled: true, Action: securitypolicy.ActionRateLimit,
				ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{WindowSeconds: 10, MaxRequests: 20}}},
			{ID: uuid.MustParse("77777777-7777-4777-8777-777777777777"), Name: "放行", Enabled: true, Action: securitypolicy.ActionAllow},
			{ID: uuid.MustParse("88888888-8888-4888-8888-888888888888"), Name: "挑战", Enabled: false, Action: securitypolicy.ActionChallenge,
				ActionConfig: securitypolicy.ActionConfig{Challenge: &securitypolicy.ChallengeConfig{Type: "slider"}}},
		},
	}

	items := projectCCReferences([]securitypolicy.Policy{policy}, ccReferenceFilter)
	if len(items) != 2 {
		t.Fatalf("filter rows = %d, want two", len(items))
	}
	types := map[string]ccReference{}
	for _, item := range items {
		types[item.Type] = item
	}
	if types["slider"].Status != "disabled" || types["req_rate"].Status != "enabled" {
		t.Fatalf("filter projection = %#v", types)
	}
}

func TestMapCCReferenceRedactsOwnerForTenantScope(t *testing.T) {
	item := ccreference.Item{
		ID:       uuid.New(),
		ScopeID:  uuid.New(),
		Name:     "匹配器",
		Owner:    &ccreference.OwnerReference{ID: uuid.New(), DisplayName: "租户管理员"},
		Revision: 1,
	}
	if owner := mapCCReferenceForScope(item, "tenant").Owner; owner != nil {
		t.Fatalf("tenant owner = %#v, want redacted", owner)
	}
	if owner := mapCCReferenceForScope(item, "platform").Owner; owner == nil || owner.ID != item.Owner.ID {
		t.Fatalf("platform owner = %#v, want preserved", owner)
	}
}

func TestMapCCReferenceRedactsSystemRulePayloadForTenantScope(t *testing.T) {
	item := ccreference.Item{
		ID:          uuid.New(),
		ScopeID:     uuid.New(),
		Name:        "5秒盾",
		Description: "内部策略",
		SystemRule:  true,
		PolicyID:    uuid.New(),
		RuleID:      uuid.New(),
		Field:       "path",
		Operator:    "prefix",
		Key:         "x-secret",
		Values:      []string{"/admin"},
		Parameters:  json.RawMessage(`{"max_requests":5}`),
		Revision:    3,
		UpdatedAt:   time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
	}
	tenant := mapCCReferenceForScope(item, "tenant")
	if tenant.Name != item.Name || !tenant.SystemRule || tenant.Version != item.Revision {
		t.Fatalf("system metadata changed: %#v", tenant)
	}
	if tenant.Description != "" || tenant.PolicyID != uuid.Nil || tenant.RuleID != uuid.Nil || tenant.Field != "" || tenant.Operator != "" || tenant.Key != "" || tenant.Values != nil || tenant.Parameters != nil || !tenant.UpdatedAt.IsZero() {
		t.Fatalf("system payload leaked to tenant: %#v", tenant)
	}
	platform := mapCCReferenceForScope(item, "platform")
	if platform.Field != item.Field || platform.Parameters == nil || platform.PolicyID != item.PolicyID {
		t.Fatalf("platform payload unexpectedly redacted: %#v", platform)
	}
}
