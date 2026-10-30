package edgepublish

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypublication"
	"github.com/google/uuid"
)

func TestAutomaticClaimReferenceIsOpaqueAndMinimal(t *testing.T) {
	typeOf := reflect.TypeOf(AutomaticClaimReference{})
	want := []string{"RequestID", "LeaseToken", "StateSequence"}
	if typeOf.NumField() != len(want) {
		t.Fatalf("AutomaticClaimReference fields=%d want=%d", typeOf.NumField(), len(want))
	}
	for index, name := range want {
		if typeOf.Field(index).Name != name {
			t.Fatalf("AutomaticClaimReference field[%d]=%s want=%s", index, typeOf.Field(index).Name, name)
		}
	}
}

func TestNormalizeAutomaticPublishRequestUsesDatabaseClockAndDurableActor(t *testing.T) {
	databaseNow := time.Date(2026, 8, 7, 12, 0, 0, 123000, time.UTC)
	request := PublishRequest{
		Actor:                Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeKindTenant},
		ConfigurationScopeID: uuid.New(), ExpectedSourceRevision: 7,
		NodeIDs: []uuid.UUID{uuid.New()}, MaxAttempts: 3,
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2,
		},
		Deadline: databaseNow.Add(time.Minute), IdempotencyKey: "automatic-publish",
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
	if _, err := normalizeAutomaticPublishRequest(request, databaseNow); err != nil {
		t.Fatalf("normalizeAutomaticPublishRequest() error=%v", err)
	}
	request.Deadline = databaseNow
	if _, err := normalizeAutomaticPublishRequest(request, databaseNow); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expired automatic deadline error=%v", err)
	}
}

func TestNormalizePublishRequestCanonicalizesNodesAndDigest(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	first := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	second := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	request := PublishRequest{
		Actor:                Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeKindPlatform},
		ConfigurationScopeID: uuid.New(), ExpectedSourceRevision: 7,
		NodeIDs: []uuid.UUID{second, first},
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2,
		},
		Deadline:       now.Add(time.Hour).In(time.FixedZone("test", 8*60*60)),
		MaxAttempts:    3,
		IdempotencyKey: "publish-1", RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
	normalized, err := normalizePublishRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = "a"
	if _, err := normalizePublishRequest(request, now); err != nil {
		t.Fatalf("1-byte idempotency key rejected: %v", err)
	}
	request.IdempotencyKey = strings.Repeat("a", 128)
	if _, err := normalizePublishRequest(request, now); err != nil {
		t.Fatalf("128-byte idempotency key rejected: %v", err)
	}
	if len(normalized.NodeIDs) != 2 || normalized.NodeIDs[0] != first || normalized.NodeIDs[1] != second {
		t.Fatalf("canonical nodes = %v", normalized.NodeIDs)
	}
	digest, err := publicationRequestDigest(normalized)
	if err != nil {
		t.Fatal(err)
	}
	reordered := request
	reordered.NodeIDs = []uuid.UUID{first, second}
	canonicalAgain, err := normalizePublishRequest(reordered, now)
	if err != nil {
		t.Fatal(err)
	}
	digestAgain, err := publicationRequestDigest(canonicalAgain)
	if err != nil {
		t.Fatal(err)
	}
	if digest != digestAgain {
		t.Fatal("equivalent node sets produced different request digests")
	}
}

func TestNormalizePublishRequestRejectsUnsafeInput(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	valid := PublishRequest{
		Actor:                Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeKindPlatform},
		ConfigurationScopeID: uuid.New(), ExpectedSourceRevision: 1, NodeIDs: []uuid.UUID{uuid.New()},
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2,
		},
		Deadline: now.Add(time.Hour), IdempotencyKey: "publish-1",
		MaxAttempts: 3,
		RequestID:   uuid.NewString(), CorrelationID: uuid.NewString(),
	}
	cases := []struct {
		name   string
		mutate func(*PublishRequest)
	}{
		{name: "nil scope", mutate: func(request *PublishRequest) { request.ConfigurationScopeID = uuid.Nil }},
		{name: "missing source revision", mutate: func(request *PublishRequest) { request.ExpectedSourceRevision = 0 }},
		{name: "nil node", mutate: func(request *PublishRequest) { request.NodeIDs = []uuid.UUID{uuid.Nil} }},
		{name: "duplicate node", mutate: func(request *PublishRequest) {
			nodeID := uuid.New()
			request.NodeIDs = []uuid.UUID{nodeID, nodeID}
		}},
		{name: "mixed target modes", mutate: func(request *PublishRequest) {
			request.TargetSnapshot = &TargetSnapshotReference{ID: uuid.New(), Revision: 1, SHA256: [32]byte{1}}
		}},
		{name: "expired deadline", mutate: func(request *PublishRequest) { request.Deadline = now }},
		{name: "sub-millisecond timeout", mutate: func(request *PublishRequest) { request.HealthCheck.ObservationWindow += time.Nanosecond }},
		{name: "non-canonical request ID", mutate: func(request *PublishRequest) { request.RequestID = "not-a-uuid" }},
		{name: "malformed traceparent", mutate: func(request *PublishRequest) { request.Traceparent = "not-a-traceparent" }},
		{name: "empty key", mutate: func(request *PublishRequest) { request.IdempotencyKey = "" }},
		{name: "unsafe key", mutate: func(request *PublishRequest) { request.IdempotencyKey = "../publish" }},
		{name: "non-ASCII key", mutate: func(request *PublishRequest) { request.IdempotencyKey = "\xc3\xa9" }},
		{name: "129-byte key", mutate: func(request *PublishRequest) { request.IdempotencyKey = strings.Repeat("a", 129) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := normalizePublishRequest(request, now); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestNormalizeRollbackRequestCanonicalizesAndRejectsUnsafeInput(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	first := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	second := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	valid := RollbackRequest{
		Actor:                Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeKindPlatform},
		ConfigurationScopeID: uuid.New(), PublicationID: uuid.New(), NodeIDs: []uuid.UUID{second, first},
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2,
		},
		Deadline: now.Add(time.Hour), MaxAttempts: 3, IdempotencyKey: "rollback-1",
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
	normalized, err := normalizeRollbackRequest(valid, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.NodeIDs) != 2 || normalized.NodeIDs[0] != first || normalized.NodeIDs[1] != second {
		t.Fatalf("canonical nodes=%v", normalized.NodeIDs)
	}

	cases := []struct {
		name   string
		mutate func(*RollbackRequest)
	}{
		{name: "nil publication", mutate: func(request *RollbackRequest) { request.PublicationID = uuid.Nil }},
		{name: "tenant actor", mutate: func(request *RollbackRequest) { request.Actor.ScopeKind = ScopeKindTenant }},
		{name: "duplicate node", mutate: func(request *RollbackRequest) {
			nodeID := uuid.New()
			request.NodeIDs = []uuid.UUID{nodeID, nodeID}
		}},
		{name: "mixed target modes", mutate: func(request *RollbackRequest) {
			request.TargetSnapshot = &TargetSnapshotReference{ID: uuid.New(), Revision: 1, SHA256: [32]byte{1}}
		}},
		{name: "expired deadline", mutate: func(request *RollbackRequest) { request.Deadline = now }},
		{name: "unsafe key", mutate: func(request *RollbackRequest) { request.IdempotencyKey = "../rollback" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := normalizeRollbackRequest(request, now); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCompileSiteFactBindsImmutableWAFAndACL(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	fact := siteFact{
		id: uuid.MustParse("11111111-1111-4111-8111-111111111111"), revision: 7,
		domain: "cdn.example.com", balance: string(edgeconfig.BalanceRoundRobin), failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}},
	}
	wafPolicy := securityPolicyForEdgeTest(fact.id, securitypolicy.KindWAF, securitypolicy.ActionAllow, []securitypolicy.Rule{
		{
			ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Name: "observe",
			Priority: 10, Enabled: true, Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowContinue,
			Conditions: []securitypolicy.Condition{{Field: "method", Operator: "equals", Values: []string{"GET"}}},
		},
		{
			ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Name: "block",
			Priority: 20, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{
				{Field: "path", Operator: "prefix", Values: []string{"/admin"}},
				{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}},
			},
		},
	})
	aclPolicy := securityPolicyForEdgeTest(fact.id, securitypolicy.KindACL, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), Name: "deny-list",
		Priority: 10, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
		Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"198.51.100.0/24"}}},
	}})
	bindings := []securityBindingFact{
		securityBindingForEdgeTest(t, wafPolicy, fact.id, 4),
		securityBindingForEdgeTest(t, aclPolicy, fact.id, 9),
	}

	snapshot, site, err := compileSiteFact(scopeID, fact, 80, nil, bindings, nil)
	if err != nil {
		t.Fatalf("compileSiteFact(, nil) error = %v", err)
	}
	if len(site.SecurityPolicies) != 2 || len(snapshot.SecurityPolicies) != 2 || len(snapshot.SecurityBindings) != 2 {
		t.Fatalf("compiled security policies site=%#v snapshot=%#v", site.SecurityPolicies, snapshot.SecurityPolicies)
	}
	if got := snapshot.SecurityPolicies[0]; got.Kind != edgeconfig.SecurityACL || got.BindingRevision != 9 ||
		got.DefaultAction != edgeconfig.WAFAllow || len(got.Rules) != 1 || got.Rules[0].Action != edgeconfig.WAFBlock ||
		got.Rules[0].Control != edgeconfig.WAFStop || got.Rules[0].Match.SourceCIDR != "198.51.100.0/24" {
		t.Fatalf("compiled ACL = %#v", got)
	}
	if got := snapshot.SecurityPolicies[1]; got.Kind != edgeconfig.SecurityWAF || got.BindingRevision != 4 ||
		got.DefaultAction != edgeconfig.WAFAllow || len(got.Rules) != 2 || got.Rules[0].Action != edgeconfig.WAFAllow ||
		got.Rules[0].Control != edgeconfig.WAFContinue || got.Rules[1].Action != edgeconfig.WAFBlock ||
		got.Rules[1].Control != edgeconfig.WAFStop {
		t.Fatalf("compiled WAF = %#v", got)
	}
	for _, policy := range snapshot.SecurityPolicies {
		if policy.RuntimeSHA256 == "" || policy.PolicyID == "" || policy.PolicyVersion != 1 {
			t.Fatalf("security binding metadata missing: %#v", policy)
		}
	}
	if site.ACL.DefaultAction != edgeconfig.ACLAllow || len(site.ACL.Rules) != 0 || len(site.WAF.Rules) != 0 {
		t.Fatalf("edge security site = ACL %#v WAF %#v", site.ACL, site.WAF)
	}
	if snapshot.SecurityBindings[0].Kind != securitypolicy.KindACL || snapshot.SecurityBindings[1].Kind != securitypolicy.KindWAF ||
		snapshot.SecurityBindings[0].PublicationID == "" || snapshot.SecurityBindings[1].RuntimeSHA256 == "" {
		t.Fatalf("canonical security binding identities = %#v", snapshot.SecurityBindings)
	}
	nginx := renderSiteSecurityForTest(t, scopeID.String(), site)
	for _, expected := range []string{"cdnca-security kind=acl", "cdnca-security kind=waf", "198.51.100.0/24", "192.0.2.0/24"} {
		if !strings.Contains(nginx, expected) {
			t.Errorf("compiled security config is missing %q", expected)
		}
	}
	if strings.Contains(nginx, "-- WAF rule ") || strings.Contains(nginx, "deny 198.51.100.0/24;") {
		t.Fatalf("compiled security config mixed legacy and provenance policies:\n%s", nginx)
	}
}

func TestCompileSiteFactRejectsSecurityThatCannotBeExpressedSafely(t *testing.T) {
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteFact{
		id: siteID, revision: 1, domain: "cdn.example.com", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}},
	}
	tests := []struct {
		name   string
		kind   string
		action string
		field  string
	}{
		{name: "CC unsupported client negation", kind: securitypolicy.KindCC, action: securitypolicy.ActionRateLimit, field: "client_ip"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := "value"
			if test.field == "client_ip" {
				value = "192.0.2.1"
			}
			condition := securitypolicy.Condition{Field: test.field, Operator: "equals", Values: []string{value}}
			if test.kind == securitypolicy.KindCC {
				condition.Operator = "not_equals"
			}
			config := securitypolicy.ActionConfig{}
			switch test.action {
			case securitypolicy.ActionRateLimit:
				config.RateLimit = &securitypolicy.RateLimitConfig{WindowSeconds: 60, MaxRequests: 10}
			case securitypolicy.ActionChallenge:
				config.Challenge = &securitypolicy.ChallengeConfig{Type: "captcha", FailureWindowSeconds: 60, MaxFailures: 5,
					PassSeconds: 21600, BanSeconds: 360, PowBits: 12, ChallengeSeconds: 120, BindIPv4Prefix: 24,
					BindIPv6Prefix: 64, KeyRotateSeconds: 86400}
			}
			policy := securityPolicyForEdgeTest(siteID, test.kind, securitypolicy.ActionAllow, []securitypolicy.Rule{{
				ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Name: "unsupported",
				Priority: 1, Enabled: true, Conditions: []securitypolicy.Condition{condition},
				Action: test.action, Flow: securitypolicy.FlowStop, ActionConfig: config,
			}})
			binding := securityBindingForEdgeTest(t, policy, siteID, 1)
			if _, _, err := compileSiteFact(binding.policy.ScopeID, fact, 80, nil, []securityBindingFact{binding}, nil); !errors.Is(err, ErrUnsupportedSecurityPolicy) {
				t.Fatalf("compileSiteFact(, nil) error = %v, want ErrUnsupportedSecurityPolicy", err)
			}
		})
	}
}

// Since the native runtime computes $cdnca_ja4 (CAPABILITY_NAME_JA4), a WAF
// JA4 rule (what ja4block publishes) compiles to the node condition instead
// of being refused as unauthoritative.
func TestCompileSiteFactCompilesJA4WAFRule(t *testing.T) {
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteFact{id: siteID, revision: 7, domain: "ja4.example.test", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
	policy := securityPolicyForEdgeTest(siteID, securitypolicy.KindWAF, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Name: "JA4 block", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "ja4", Operator: "equals", Values: []string{"t13d1516h2_8daaf6152771_e5627efa2ab1"}}},
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
	}})
	binding := securityBindingForEdgeTest(t, policy, siteID, 1)
	_, site, err := compileSiteFact(binding.policy.ScopeID, fact, 80, nil, []securityBindingFact{binding}, nil)
	if err != nil {
		t.Fatalf("compileSiteFact(ja4, nil) = %v", err)
	}
	if !edgeconfig.SecurityPoliciesUseJA4(site.SecurityPolicies) {
		t.Fatalf("compiled site lost the JA4 rule: %+v", site.SecurityPolicies)
	}
}

func securityPolicyForEdgeTest(siteID uuid.UUID, kind, defaultAction string, rules []securitypolicy.Rule) securitypolicy.Policy {
	return securitypolicy.Policy{
		ID: uuid.NewSHA1(siteID, []byte(kind)), ScopeID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		Kind: kind, Name: kind, Enabled: true, DefaultAction: defaultAction, Rules: rules, Revision: 1,
	}
}

func securityBindingForEdgeTest(t *testing.T, policy securitypolicy.Policy, siteID uuid.UUID, revision int64) securityBindingFact {
	t.Helper()
	compiled, err := securitypolicy.CompileRuntimeSnapshot(policy, siteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot() error = %v", err)
	}
	binding := securityBindingFact{
		siteID: siteID, bindingID: uuid.New(), publicationID: uuid.New(), bindingRevision: revision, policy: policy,
		runtimeSHA256: sha256.Sum256(compiled.CanonicalJSON),
	}
	if securitypolicy.PolicyManagedWAF(policy) != nil {
		binding.crs = crsInputsForEdgeTest(t)
	}
	return binding
}

// crsInputsForEdgeTest is the compiler seed CRS rule text and the
// system/crs-* packs libs/rulepack generates (what a control plane that
// downloaded them compiles against).
func crsInputsForEdgeTest(t *testing.T) *securitypublication.CRSInputs {
	t.Helper()
	rules, err := securitypolicy.EdgeCRSRuleText(*rulecatalog.CRSRulesBundle())
	if err != nil {
		t.Fatal(err)
	}
	return &securitypublication.CRSInputs{Profiles: crsProfilesForEdgeTest(t), RuleText: rules}
}

func crsProfilesForEdgeTest(t *testing.T) securitypolicy.CRSProfiles {
	t.Helper()
	paths, err := filepath.Glob("../../../../libs/rulepack/testdata/crs-profiles/crs-*.json")
	if err != nil || len(paths) != 4 {
		t.Fatalf("CRS profile goldens: %v %v", paths, err)
	}
	profiles := securitypolicy.CRSProfiles{}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		_, profile, err := rulepack.LoadCRSProfile(content, hex.EncodeToString(sum[:]))
		if err != nil {
			t.Fatal(err)
		}
		profiles[profile.Ref.PackID] = securitypolicy.CRSProfile{Profile: profile, Content: content}
	}
	return profiles
}
