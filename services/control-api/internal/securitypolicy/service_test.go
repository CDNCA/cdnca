package securitypolicy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeFieldsRejectsUnsafeAndInvalidConditions(t *testing.T) {
	tests := []struct {
		name      string
		condition Condition
	}{
		{name: "arbitrary field", condition: Condition{Field: "nginx", Operator: "equals", Values: []string{"return 200;"}}},
		{name: "invalid regex", condition: Condition{Field: "path", Operator: "regex", Values: []string{"(unclosed"}}},
		{name: "unknown detector", condition: Condition{Field: "args", Operator: "detect", Values: []string{"rce"}}},
		{name: "invalid cidr", condition: Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"10.0.0.999/24"}}},
		{name: "invalid header", condition: Condition{Field: "header", Operator: "equals", Key: "bad header", Values: []string{"x"}}},
		{name: "multi numeric comparison", condition: Condition{Field: "port", Operator: "number_eq", Values: []string{"80", "443"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := validFields(test.condition)
			if err := normalizeFields(&fields, true); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalizeFields error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestNormalizeRateLimitPreservesLegacyFixedWindowDefault(t *testing.T) {
	fields := validFields(Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}})
	fields.Rules[0].Action = ActionRateLimit
	fields.Rules[0].ActionConfig.RateLimit = &RateLimitConfig{WindowSeconds: 60, MaxRequests: 120}
	if err := normalizeFields(&fields, true); err != nil {
		t.Fatalf("normalizeFields legacy fixed window: %v", err)
	}
	encoded, err := json.Marshal(fields.Rules[0].ActionConfig.RateLimit)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"window_seconds":60,"max_requests":120}`; got != want {
		t.Fatalf("legacy rate limit wire = %s, want %s", got, want)
	}
}

func TestNormalizeRateLimitExpertAlgorithmsAndBounds(t *testing.T) {
	validAdaptive := func() *AdaptiveRateLimitConfig {
		return &AdaptiveRateLimitConfig{
			Profile: "expert", Enforcement: "auto", AutoApproved: true,
			MinSamples: 8, MaxSamples: 64, SampleFreshnessSeconds: 30,
			EWMAAlphaPermille: 250, MADMultiplierMilli: 2500,
			MinRatePerSecond: 10, MaxRatePerSecond: 1000, MinBurst: 20, MaxBurst: 2000,
			MaxStepPermille: 100, HysteresisPermille: 50, CooldownSeconds: 10, MaxGroups: 1000,
		}
	}
	tests := []struct {
		name   string
		config RateLimitConfig
		valid  bool
	}{
		{name: "leaky bucket", valid: true, config: RateLimitConfig{Algorithm: "leaky_bucket", RatePerSecond: 100, Burst: 200, ResponseAction: "reject_429"}},
		{name: "temporary ban", valid: true, config: RateLimitConfig{Algorithm: "leaky_bucket", RatePerSecond: 100, Burst: 200, ResponseAction: "temporary_ban", BanSeconds: 60}},
		{name: "adaptive expert auto", valid: true, config: RateLimitConfig{Algorithm: "adaptive", RatePerSecond: 100, Burst: 200, ResponseAction: "reject_429", Adaptive: validAdaptive()}},
		{name: "adaptive simple safe defaults", valid: true, config: RateLimitConfig{Algorithm: "adaptive", RatePerSecond: 100, Burst: 200, ResponseAction: "reject_429", Adaptive: &AdaptiveRateLimitConfig{Profile: "simple", Enforcement: "shadow"}}},
		{name: "mixed fixed and leaky", config: RateLimitConfig{Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 100, RatePerSecond: 2, Burst: 3}},
		{name: "ban without temporary action", config: RateLimitConfig{Algorithm: "leaky_bucket", RatePerSecond: 2, Burst: 3, ResponseAction: "reject_429", BanSeconds: 30}},
		{name: "auto without approval", config: func() RateLimitConfig {
			value := validAdaptive()
			value.AutoApproved = false
			return RateLimitConfig{Algorithm: "adaptive", RatePerSecond: 100, Burst: 200, ResponseAction: "reject_429", Adaptive: value}
		}()},
		{name: "shadow with approval", config: func() RateLimitConfig {
			value := validAdaptive()
			value.Enforcement = "shadow"
			return RateLimitConfig{Algorithm: "adaptive", RatePerSecond: 100, Burst: 200, ResponseAction: "reject_429", Adaptive: value}
		}()},
		{name: "simple with expert knobs", config: RateLimitConfig{Algorithm: "adaptive", RatePerSecond: 100, Burst: 200, ResponseAction: "reject_429", Adaptive: &AdaptiveRateLimitConfig{Profile: "simple", Enforcement: "shadow", MinSamples: 3}}},
		{name: "unsafe step", config: func() RateLimitConfig {
			value := validAdaptive()
			value.MaxStepPermille = 1001
			return RateLimitConfig{Algorithm: "adaptive", RatePerSecond: 100, Burst: 200, ResponseAction: "reject_429", Adaptive: value}
		}()},
		{name: "inverted rate bounds", config: func() RateLimitConfig {
			value := validAdaptive()
			value.MinRatePerSecond = 1001
			return RateLimitConfig{Algorithm: "adaptive", RatePerSecond: 100, Burst: 200, ResponseAction: "reject_429", Adaptive: value}
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := validFields(Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}})
			fields.Rules[0].Action = ActionRateLimit
			fields.Rules[0].ActionConfig.RateLimit = &test.config
			err := normalizeFields(&fields, true)
			if test.valid && err != nil {
				t.Fatalf("normalizeFields: %v", err)
			}
			if !test.valid && !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalizeFields error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestNormalizeFieldsCanonicalizesValues(t *testing.T) {
	fields := validFields(Condition{
		Field: "client_ip", Operator: "ip_in_cidr",
		Values: []string{"2001:db8:0:0::1/64", "10.0.0.18/24"},
	})
	if err := normalizeFields(&fields, true); err != nil {
		t.Fatalf("normalizeFields: %v", err)
	}
	values := fields.Rules[0].Conditions[0].Values
	if values[0] != "10.0.0.0/24" || values[1] != "2001:db8::/64" {
		t.Fatalf("normalized CIDRs = %v", values)
	}
}

func TestNormalizeFieldsRuleIDsAndStableOrder(t *testing.T) {
	first := uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	second := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	fields := validFields(Condition{Field: "method", Operator: "equals", Values: []string{"get"}})
	fields.Rules = append(fields.Rules, fields.Rules[0])
	fields.Rules[0].ID = first
	fields.Rules[1].ID = second
	fields.Rules[0].Name = "second by ID"
	fields.Rules[1].Name = "first by ID"
	if err := normalizeFields(&fields, false); err != nil {
		t.Fatalf("normalizeFields: %v", err)
	}
	if fields.Rules[0].ID != second || fields.Rules[1].ID != first {
		t.Fatalf("rule order = %v, %v", fields.Rules[0].ID, fields.Rules[1].ID)
	}
	if err := normalizeFields(&fields, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("create with caller IDs error = %v, want ErrInvalidInput", err)
	}
}

func TestNormalizeACLMatchesPublishedEdgeContract(t *testing.T) {
	valid := PolicyFields{
		Kind: KindACL, Name: "acl", Enabled: true, DefaultAction: ActionAllow,
		Rules: []Rule{
			{Name: "allow office", Priority: 10, Enabled: true, Action: ActionAllow, Flow: FlowContinue,
				Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.0.9/16"}}}},
			{Name: "deny narrow", Priority: 20, Enabled: true, Action: ActionBlock, Flow: FlowStop,
				Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.9/24"}}}},
		},
	}
	if err := normalizeFields(&valid, true); err != nil {
		t.Fatalf("normalizeFields valid ACL: %v", err)
	}
	if err := validateACLFields(valid.Rules); err != nil {
		t.Fatalf("validateACLFields valid ACL: %v", err)
	}
	if got := valid.Rules[0].Conditions[0].Values[0]; got != "192.0.0.0/16" {
		t.Fatalf("canonical ACL CIDR = %q", got)
	}
	allowID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	blockID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	valid.Rules[0].ID, valid.Rules[1].ID = allowID, blockID
	policy := Policy{
		ID:      uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		ScopeID: uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		Kind:    KindACL, Enabled: true, DefaultAction: valid.DefaultAction, Rules: valid.Rules, Revision: 7,
	}
	decision, err := evaluate(policy, RequestFacts{ClientIP: "192.0.2.9"})
	if err != nil {
		t.Fatalf("evaluate narrow ACL: %v", err)
	}
	if decision.Action != ActionBlock || decision.UsedDefault || decision.TerminalRuleID == nil ||
		*decision.TerminalRuleID != blockID || len(decision.MatchedRuleIDs) != 2 ||
		decision.MatchedRuleIDs[0] != allowID || decision.MatchedRuleIDs[1] != blockID {
		t.Fatalf("narrow ACL preview = %#v", decision)
	}
	decision, err = evaluate(policy, RequestFacts{ClientIP: "192.0.99.9"})
	if err != nil {
		t.Fatalf("evaluate broad ACL: %v", err)
	}
	if decision.Action != ActionAllow || decision.UsedDefault || decision.TerminalRuleID != nil ||
		!reflect.DeepEqual(decision.MatchedRuleIDs, []uuid.UUID{allowID}) {
		t.Fatalf("broad ACL preview = %#v", decision)
	}

	tests := map[string]func(*PolicyFields){
		"unsupported action": func(fields *PolicyFields) { fields.Rules[0].Action = ActionLog },
		"unsupported field": func(fields *PolicyFields) {
			fields.Rules[0].Conditions[0] = Condition{Field: "path", Operator: "prefix", Values: []string{"/admin"}}
		},
		"negative CIDR": func(fields *PolicyFields) { fields.Rules[0].Conditions[0].Operator = "ip_not_in_cidr" },
		"multiple CIDRs": func(fields *PolicyFields) {
			fields.Rules[0].Conditions[0].Values = []string{"192.0.2.0/24", "198.51.100.0/24"}
		},
		"multiple conditions": func(fields *PolicyFields) {
			fields.Rules[0].Conditions = append(fields.Rules[0].Conditions,
				Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"198.51.100.0/24"}})
		},
		"duplicate CIDR": func(fields *PolicyFields) {
			fields.Rules[1].Conditions[0].Values = []string{"192.0.0.0/16"}
		},
		"terminal broad shadow": func(fields *PolicyFields) { fields.Rules[0].Flow = FlowStop },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fields := valid
			fields.Rules = cloneRules(valid.Rules)
			mutate(&fields)
			if err := normalizeFields(&fields, false); err != nil {
				t.Fatalf("normalizeFields prerequisite: %v", err)
			}
			if err := validateACLFields(fields.Rules); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("validateACLFields error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestServiceRejectsUnpublishableACLBeforePersistence(t *testing.T) {
	actor := Actor{
		UserID:  uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		ScopeID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), ScopeKind: "tenant",
	}
	fields := PolicyFields{
		Kind: KindACL, Name: "duplicate", Enabled: true, DefaultAction: ActionAllow,
		Rules: []Rule{
			{Name: "first", Priority: 10, Enabled: true, Action: ActionAllow, Flow: FlowContinue,
				Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}}}},
			{Name: "duplicate", Priority: 20, Enabled: true, Action: ActionBlock, Flow: FlowStop,
				Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.9/24"}}}},
		},
	}
	service := NewService(nil)
	if _, err := service.Create(context.Background(), actor, CreateRequest{
		Fields: fields, IdempotencyKey: "acl-create", RequestID: "acl-create",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Create error = %v, want ErrInvalidInput", err)
	}
	for index := range fields.Rules {
		fields.Rules[index].ID = uuid.MustParse([]string{
			"33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444",
		}[index])
	}
	if _, err := service.Update(context.Background(), actor, UpdateRequest{
		ID: uuid.MustParse("55555555-5555-4555-8555-555555555555"), ExpectedRevision: 1,
		Fields: fields, IdempotencyKey: "acl-update", RequestID: "acl-update",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Update error = %v, want ErrInvalidInput", err)
	}
}

func TestLicensedWAFMetadataIsProtectedAndRedacted(t *testing.T) {
	metadata := LicensedWAFMetadata{
		LibraryID: "baseline-cn", Revision: 7, Name: "基础防护规则库", Description: "平台签名下发",
	}
	description, err := encodeLicensedWAFMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{
		Kind: KindWAF, Name: licensedWAFStorageName(metadata.LibraryID), Description: description,
		Rules: []Rule{{Name: "SQL 注入", Priority: 10, Enabled: true}},
	}
	redact(&policy, Actor{ScopeKind: "tenant"})
	if policy.Origin != "system" || !policy.Protected || policy.Name != metadata.Name ||
		policy.Description != metadata.Description || policy.Rules != nil {
		t.Fatalf("redacted licensed policy = %#v", policy)
	}
}

func TestPublicCreateRejectsLicensedWAFMarkerBeforePersistence(t *testing.T) {
	actor := Actor{
		UserID:  uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		ScopeID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), ScopeKind: "tenant",
	}
	fields := validFields(Condition{Field: "path", Operator: "prefix", Values: []string{"/"}})
	fields.Kind = KindWAF
	fields.Name = "@system/baseline-cn"
	service := NewService(nil)
	if _, err := service.Create(context.Background(), actor, CreateRequest{Fields: fields}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Create error = %v, want ErrPermissionDenied", err)
	}
}

func TestLicensedWAFDefinitionValidation(t *testing.T) {
	definition := LicensedWAFDefinition{
		LibraryID: "baseline-cn", Revision: 1, Name: "基础防护规则库", Enabled: true,
		DefaultAction: ActionAllow,
		Rules: []Rule{{ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"),
			Name: "路径穿越", Priority: 10, Enabled: true, Action: ActionBlock, Flow: FlowStop,
			Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/../"}}}}},
	}
	if !validLicensedWAFDefinition(definition) {
		t.Fatal("valid licensed WAF definition was rejected")
	}
	// ge-waf: path suffix is an inspect clause now; an unknown operator is not.
	definition.Rules[0].Conditions[0].Operator = "suffix"
	if !validLicensedWAFDefinition(definition) {
		t.Fatal("path suffix licensed WAF condition was rejected")
	}
	definition.Rules[0].Conditions[0].Operator = "ip_in_cidr"
	if validLicensedWAFDefinition(definition) {
		t.Fatal("unsupported licensed WAF condition was accepted")
	}
	definition.Rules[0].Conditions[0].Operator = "prefix"
	definition.LibraryID = "00000000-0000-4000-8000-000000000001"
	if !validLicensedWAFDefinition(definition) {
		t.Fatal("canonical UUID licensed WAF definition was rejected")
	}
}

func validFields(condition Condition) PolicyFields {
	return PolicyFields{
		Kind: KindCC, Name: "policy", Enabled: true, DefaultAction: ActionAllow,
		Rules: []Rule{{
			Name: "rule", Priority: 100, Enabled: true, Conditions: []Condition{condition},
			Action: ActionBlock, Flow: FlowStop,
		}},
	}
}
