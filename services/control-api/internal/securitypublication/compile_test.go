package securitypublication

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

var (
	testTenantScopeID = uuid.MustParse("018f1000-0000-7000-8000-000000000001")
	testSiteID        = uuid.MustParse("018f1000-0000-7000-8000-000000000002")
)

func TestCompileSiteSecurityBindingsAppliesCanonicalWAFAndACL(t *testing.T) {
	acl := activeBinding(t, securitypolicy.Policy{
		ID: uuid.MustParse("018f1000-0000-7000-8000-000000000010"), ScopeID: testTenantScopeID,
		Kind: securitypolicy.KindACL, Name: "acl", Enabled: true,
		DefaultAction: securitypolicy.ActionBlock, Revision: 3,
		Rules: []securitypolicy.Rule{{
			ID: uuid.MustParse("018f1000-0000-7000-8000-000000000011"), Name: "office",
			Priority: 10, Enabled: true, Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{
				Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.129/24"},
			}},
		}},
	})
	waf := activeBinding(t, securitypolicy.Policy{
		ID: uuid.MustParse("018f1000-0000-7000-8000-000000000020"), ScopeID: testTenantScopeID,
		Kind: securitypolicy.KindWAF, Name: "waf", Enabled: true,
		DefaultAction: securitypolicy.ActionAllow, Revision: 5,
		Rules: []securitypolicy.Rule{
			{
				ID: uuid.MustParse("018f1000-0000-7000-8000-000000000021"), Name: "observe",
				Priority: 10, Enabled: true, Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowContinue,
				Conditions: []securitypolicy.Condition{
					{Field: "method", Operator: "equals", Values: []string{"GET"}},
					{Field: "header", Operator: "equals", Key: "x-mode", Values: []string{"observe"}},
				},
			},
			{
				ID: uuid.MustParse("018f1000-0000-7000-8000-000000000022"), Name: "block",
				Priority: 20, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
				Conditions: []securitypolicy.Condition{
					{Field: "path", Operator: "prefix", Values: []string{"/admin"}},
					{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"198.51.100.0/24"}},
				},
			},
		},
	})
	bindings := []ActiveBinding{waf, acl}
	originalSite, originalBindings := baseSite(), cloneBindings(bindings)

	compiled, err := CompileSiteSecurityBindings(originalSite, testTenantScopeID, testSiteID, bindings)
	if err != nil {
		t.Fatalf("CompileSiteSecurityBindings: %v", err)
	}
	if !reflect.DeepEqual(bindings, originalBindings) {
		t.Fatal("CompileSiteSecurityBindings mutated active bindings")
	}
	if !reflect.DeepEqual(originalSite, baseSite()) {
		t.Fatal("CompileSiteSecurityBindings mutated the input site")
	}
	if compiled.Site.ACL.DefaultAction != edgeconfig.ACLAllow || len(compiled.Site.ACL.Rules) != 0 ||
		len(compiled.Site.WAF.Rules) != 0 || len(compiled.Site.SecurityPolicies) != 2 {
		t.Fatalf("bound security leaked into legacy fields: %#v", compiled.Site)
	}
	if got, want := compiled.Site.SecurityPolicies[0], (edgeconfig.SecurityPolicy{
		Kind: edgeconfig.SecurityACL, PolicyID: acl.Snapshot.PolicyID.String(),
		PolicyVersion: acl.Snapshot.PolicyVersion, BindingRevision: acl.BindingRevision,
		RuntimeSHA256: fmt.Sprintf("%x", acl.RuntimeSnapshotSHA256[:]), Enabled: true,
		DefaultAction: edgeconfig.WAFBlock,
		Rules: []edgeconfig.WAFRule{{
			RuleID: acl.Snapshot.Rules[0].ID.String(), Match: edgeconfig.WAFMatch{SourceCIDR: "192.0.2.0/24"},
			Action: edgeconfig.WAFAllow, Control: edgeconfig.WAFStop,
		}},
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled ACL = %#v, want %#v", got, want)
	}
	if got, want := compiled.Site.SecurityPolicies[1], (edgeconfig.SecurityPolicy{
		Kind: edgeconfig.SecurityWAF, PolicyID: waf.Snapshot.PolicyID.String(),
		PolicyVersion: waf.Snapshot.PolicyVersion, BindingRevision: waf.BindingRevision,
		RuntimeSHA256: fmt.Sprintf("%x", waf.RuntimeSnapshotSHA256[:]), Enabled: true,
		DefaultAction: edgeconfig.WAFAllow, Rules: []edgeconfig.WAFRule{
			{
				RuleID: waf.Snapshot.Rules[0].ID.String(),
				Match: edgeconfig.WAFMatch{
					Method: "GET", Header: &edgeconfig.WAFHeaderMatch{
						Name: "x-mode", Kind: edgeconfig.WAFHeaderExact, Value: "observe",
					},
				},
				Action: edgeconfig.WAFAllow, Control: edgeconfig.WAFContinue,
			},
			{
				RuleID: waf.Snapshot.Rules[1].ID.String(),
				Match: edgeconfig.WAFMatch{
					Path:       &edgeconfig.WAFPathMatch{Kind: edgeconfig.WAFPathPrefix, Value: "/admin"},
					SourceCIDR: "198.51.100.0/24",
				},
				Action: edgeconfig.WAFDeny, Control: edgeconfig.WAFStop,
			},
		}}); !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled WAF = %#v, want %#v", got, want)
	}
	if len(compiled.Bindings) != 2 || compiled.Bindings[0].Kind != securitypolicy.KindACL ||
		compiled.Bindings[1].Kind != securitypolicy.KindWAF ||
		compiled.Bindings[0].PublicationID != acl.PublicationID ||
		compiled.Bindings[1].RuntimeSnapshotSHA256 != waf.RuntimeSnapshotSHA256 {
		t.Fatalf("compiled binding identities = %#v", compiled.Bindings)
	}

	nginx := renderSiteSecurityForTest(t, testTenantScopeID.String(), compiled.Site)
	for _, fragment := range []string{
		"cdnca-security kind=acl", "cdnca-security kind=waf",
		`cdnca_header_exact("x-mode", "observe")`, `uri == "/admin"`,
	} {
		if !strings.Contains(nginx, fragment) {
			t.Errorf("compiled edge config is missing %q", fragment)
		}
	}
}

func TestCompileSiteSecurityBindingsUsesOnlyDefaultForDisabledPolicies(t *testing.T) {
	acl := policyForTest(securitypolicy.KindACL)
	acl.Enabled = false
	acl.DefaultAction = securitypolicy.ActionBlock
	acl.Rules[0].Action = securitypolicy.ActionAllow
	acl.Rules[0].Flow = securitypolicy.FlowStop
	acl.Rules[0].Conditions = []securitypolicy.Condition{{
		Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"},
	}}
	waf := policyForTest(securitypolicy.KindWAF)
	waf.Enabled = false
	waf.Rules[0].Action = securitypolicy.ActionBlock
	waf.Rules[0].Flow = securitypolicy.FlowStop

	compiled, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID,
		[]ActiveBinding{activeBinding(t, acl), activeBinding(t, waf)})
	if err != nil {
		t.Fatalf("CompileSiteSecurityBindings: %v", err)
	}
	if len(compiled.Site.SecurityPolicies) != 2 ||
		compiled.Site.SecurityPolicies[0].DefaultAction != edgeconfig.WAFBlock ||
		len(compiled.Site.SecurityPolicies[0].Rules) != 0 || len(compiled.Site.SecurityPolicies[1].Rules) != 0 {
		t.Fatalf("disabled policy output = %#v", compiled.Site.SecurityPolicies)
	}
}

func TestCompileSiteSecurityBindingsRejectsBrokenIdentity(t *testing.T) {
	valid := activeBinding(t, policyForTest(securitypolicy.KindWAF))
	tests := map[string]func(*edgeconfig.Site, *[]ActiveBinding, *uuid.UUID, *uuid.UUID){
		"missing target scope": func(_ *edgeconfig.Site, _ *[]ActiveBinding, scope, _ *uuid.UUID) { *scope = uuid.Nil },
		"missing target site":  func(_ *edgeconfig.Site, _ *[]ActiveBinding, _, site *uuid.UUID) { *site = uuid.Nil },
		"site identity mismatch": func(site *edgeconfig.Site, _ *[]ActiveBinding, _, _ *uuid.UUID) {
			site.ID = uuid.NewString()
		},
		"missing publication": func(_ *edgeconfig.Site, bindings *[]ActiveBinding, _, _ *uuid.UUID) {
			(*bindings)[0].PublicationID = uuid.Nil
		},
		"scope mismatch": func(_ *edgeconfig.Site, bindings *[]ActiveBinding, _, _ *uuid.UUID) {
			(*bindings)[0].Snapshot.TenantScopeID = uuid.New()
			refreshDigest(&(*bindings)[0])
		},
		"site mismatch": func(_ *edgeconfig.Site, bindings *[]ActiveBinding, _, _ *uuid.UUID) {
			(*bindings)[0].Snapshot.SiteID = uuid.New()
			refreshDigest(&(*bindings)[0])
		},
		"digest mismatch": func(_ *edgeconfig.Site, bindings *[]ActiveBinding, _, _ *uuid.UUID) {
			(*bindings)[0].RuntimeSnapshotSHA256[0] ^= 0xff
		},
		"duplicate kind": func(_ *edgeconfig.Site, bindings *[]ActiveBinding, _, _ *uuid.UUID) {
			*bindings = append(*bindings, (*bindings)[0])
			(*bindings)[1].PublicationID = uuid.New()
		},
		"prepopulated WAF": func(site *edgeconfig.Site, _ *[]ActiveBinding, _, _ *uuid.UUID) {
			site.WAF.Rules = []edgeconfig.WAFRule{{
				Match: edgeconfig.WAFMatch{Method: "GET"}, Action: edgeconfig.WAFDeny, Control: edgeconfig.WAFStop,
			}}
		},
		"prepopulated restrictive ACL": func(site *edgeconfig.Site, _ *[]ActiveBinding, _, _ *uuid.UUID) {
			site.ACL = edgeconfig.ACLPolicy{DefaultAction: edgeconfig.ACLDeny}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			site, bindings, scopeID, siteID := baseSite(), []ActiveBinding{valid}, testTenantScopeID, testSiteID
			mutate(&site, &bindings, &scopeID, &siteID)
			if _, err := CompileSiteSecurityBindings(site, scopeID, siteID, bindings); !errors.Is(err, ErrInvalidBinding) {
				t.Fatalf("CompileSiteSecurityBindings error = %v, want ErrInvalidBinding", err)
			}
		})
	}
}

func TestCompileSiteSecurityBindingsFailsClosedForUnsupportedRuntimeSemantics(t *testing.T) {
	tests := map[string]securitypolicy.Policy{
		"WAF host condition": mutatePolicy(policyForTest(securitypolicy.KindWAF), func(policy *securitypolicy.Policy) {
			policy.Rules[0].Conditions = []securitypolicy.Condition{{Field: "host", Operator: "equals", Values: []string{"example.test"}}}
		}),
		"WAF multiple values": mutatePolicy(policyForTest(securitypolicy.KindWAF), func(policy *securitypolicy.Policy) {
			policy.Rules[0].Conditions[0].Operator = "in"
			policy.Rules[0].Conditions[0].Values = []string{"GET", "POST"}
		}),
		"WAF duplicate field": mutatePolicy(policyForTest(securitypolicy.KindWAF), func(policy *securitypolicy.Policy) {
			policy.Rules[0].Conditions = []securitypolicy.Condition{
				{Field: "header", Operator: "equals", Key: "x-a", Values: []string{"a"}},
				{Field: "header", Operator: "equals", Key: "x-b", Values: []string{"b"}},
			}
		}),
		"WAF unsafe edge path": mutatePolicy(policyForTest(securitypolicy.KindWAF), func(policy *securitypolicy.Policy) {
			policy.Rules[0].Conditions = []securitypolicy.Condition{{Field: "path", Operator: "equals", Values: []string{"/%2e%2e/admin"}}}
		}),
		"WAF unsupported edge header": mutatePolicy(policyForTest(securitypolicy.KindWAF), func(policy *securitypolicy.Policy) {
			policy.Rules[0].Conditions = []securitypolicy.Condition{{Field: "header", Operator: "equals", Key: "x_mode", Values: []string{"block"}}}
		}),
		"WAF terminal shadow": mutatePolicy(policyForTest(securitypolicy.KindWAF), func(policy *securitypolicy.Policy) {
			policy.Rules = []securitypolicy.Rule{
				{
					ID: uuid.New(), Name: "all get", Priority: 1, Enabled: true,
					Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowStop,
					Conditions: []securitypolicy.Condition{{Field: "method", Operator: "equals", Values: []string{"GET"}}},
				},
				{
					ID: uuid.New(), Name: "blocked get", Priority: 2, Enabled: true,
					Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
					Conditions: []securitypolicy.Condition{
						{Field: "method", Operator: "equals", Values: []string{"GET"}},
						{Field: "path", Operator: "equals", Values: []string{"/blocked"}},
					},
				},
			}
		}),
		"ACL address equals": mutatePolicy(policyForTest(securitypolicy.KindACL), func(policy *securitypolicy.Policy) {
			policy.Rules[0].Flow = securitypolicy.FlowStop
			policy.Rules[0].Conditions = []securitypolicy.Condition{{Field: "client_ip", Operator: "equals", Values: []string{"192.0.2.1"}}}
		}),
		"ACL rate limit": mutatePolicy(policyForTest(securitypolicy.KindACL), func(policy *securitypolicy.Policy) {
			policy.Rules[0].Flow = securitypolicy.FlowStop
			policy.Rules[0].Action = securitypolicy.ActionRateLimit
			policy.Rules[0].ActionConfig.RateLimit = &securitypolicy.RateLimitConfig{WindowSeconds: 60, MaxRequests: 100}
			policy.Rules[0].Conditions = []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}}}
		}),
		"ACL shadow": mutatePolicy(policyForTest(securitypolicy.KindACL), func(policy *securitypolicy.Policy) {
			policy.Rules = []securitypolicy.Rule{
				{
					ID: uuid.New(), Name: "broad", Priority: 1, Enabled: true,
					Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowStop,
					Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.0.0/16"}}},
				},
				{
					ID: uuid.New(), Name: "narrow", Priority: 2, Enabled: true,
					Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
					Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}}},
				},
			}
		}),
	}
	for name, policy := range tests {
		t.Run(name, func(t *testing.T) {
			binding := activeBinding(t, policy)
			if _, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID,
				[]ActiveBinding{binding}); !errors.Is(err, ErrUnsupportedRuntime) {
				t.Fatalf("CompileSiteSecurityBindings error = %v, want ErrUnsupportedRuntime", err)
			}
		})
	}
}

func TestCompileSiteSecurityBindingsSupportsCanonicalWAFPort(t *testing.T) {
	for _, port := range []string{"1", "65535"} {
		t.Run(port, func(t *testing.T) {
			policy := policyForTest(securitypolicy.KindWAF)
			policy.Rules[0].Conditions = []securitypolicy.Condition{
				{Field: "method", Operator: "equals", Values: []string{"GET"}},
				{Field: "path", Operator: "prefix", Values: []string{"/admin"}},
				{Field: "header", Operator: "equals", Key: "x-mode", Values: []string{"strict"}},
				{Field: "port", Operator: "number_eq", Values: []string{port}},
			}
			binding := activeBinding(t, policy)

			first, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{binding})
			if err != nil {
				t.Fatalf("CompileSiteSecurityBindings(first): %v", err)
			}
			second, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{binding})
			if err != nil {
				t.Fatalf("CompileSiteSecurityBindings(second): %v", err)
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatal("CompileSiteSecurityBindings produced nondeterministic output")
			}
			if got := first.Site.SecurityPolicies[0].Rules[0].Match; got.Port == 0 ||
				got.Method != "GET" || got.Path == nil || got.Path.Kind != edgeconfig.WAFPathPrefix || got.Path.Value != "/admin" ||
				got.Header == nil || got.Header.Name != "x-mode" || got.Header.Value != "strict" {
				t.Fatalf("compiled match = %#v", got)
			} else if fmt.Sprint(got.Port) != port {
				t.Fatalf("compiled port = %d, want %s", got.Port, port)
			}
			if first.Site.ListenPort != baseSite().ListenPort || first.Site.SecurityPolicies[0].Rules[0].Match.Port == first.Site.ListenPort {
				t.Fatalf("WAF match port was confused with site listen port: match=%d listen=%d",
					first.Site.SecurityPolicies[0].Rules[0].Match.Port, first.Site.ListenPort)
			}

			firstNginx := renderSiteSecurityForTest(t, testTenantScopeID.String(), first.Site)
			if secondNginx := renderSiteSecurityForTest(t, testTenantScopeID.String(), second.Site); firstNginx != secondNginx {
				t.Fatal("compiled WAF port changed the rendered security")
			}
			if fragment := "tonumber(ngx.var.server_port) == " + port; !strings.Contains(firstNginx, fragment) {
				t.Fatalf("compiled edge config is missing %q", fragment)
			}
		})
	}
}

func TestEdgeWAFMatchRejectsNoncanonicalPort(t *testing.T) {
	tests := map[string]securitypolicy.Condition{
		"zero":              {Field: "port", Operator: "number_eq", Values: []string{"0"}},
		"above uint16":      {Field: "port", Operator: "number_eq", Values: []string{"65536"}},
		"plus sign":         {Field: "port", Operator: "number_eq", Values: []string{"+1"}},
		"minus sign":        {Field: "port", Operator: "number_eq", Values: []string{"-1"}},
		"leading zero":      {Field: "port", Operator: "number_eq", Values: []string{"01"}},
		"decimal point":     {Field: "port", Operator: "number_eq", Values: []string{"1.0"}},
		"hexadecimal":       {Field: "port", Operator: "number_eq", Values: []string{"0x1"}},
		"surrounding space": {Field: "port", Operator: "number_eq", Values: []string{" 1"}},
		"wrong operator":    {Field: "port", Operator: "equals", Values: []string{"443"}},
		"nonempty key":      {Field: "port", Operator: "number_eq", Key: "access_port", Values: []string{"443"}},
		"access port alias": {Field: "access_port", Operator: "number_eq", Values: []string{"443"}},
	}
	for name, condition := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := edgeWAFMatch([]securitypolicy.Condition{condition}); !errors.Is(err, ErrUnsupportedRuntime) {
				t.Fatalf("edgeWAFMatch error = %v, want ErrUnsupportedRuntime", err)
			}
		})
	}
}

func TestWAFPortMatchLimitsAndShadowing(t *testing.T) {
	t.Run("port participates in field uniqueness", func(t *testing.T) {
		_, err := edgeWAFMatch([]securitypolicy.Condition{
			{Field: "port", Operator: "number_eq", Values: []string{"443"}},
			{Field: "port", Operator: "number_eq", Values: []string{"8443"}},
		})
		if !errors.Is(err, ErrUnsupportedRuntime) {
			t.Fatalf("edgeWAFMatch error = %v, want ErrUnsupportedRuntime", err)
		}
	})

	t.Run("nine conditions rejected", func(t *testing.T) {
		conditions := []securitypolicy.Condition{
			{Field: "port", Operator: "number_eq", Values: []string{"443"}},
			{Field: "method", Operator: "equals", Values: []string{"GET"}},
			{Field: "path", Operator: "equals", Values: []string{"/admin"}},
			{Field: "header", Operator: "equals", Key: "x-mode", Values: []string{"strict"}},
			{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}},
			{Field: "args", Operator: "contains", Key: "a", Values: []string{"1"}},
			{Field: "args", Operator: "contains", Key: "b", Values: []string{"2"}},
			{Field: "query", Operator: "not_contains", Values: []string{"ok"}},
		}
		match, err := edgeWAFMatch(conditions)
		if err != nil || len(match.Inspect) != 3 {
			t.Fatalf("eight conditions: %+v, %v", match, err)
		}
		_, err = edgeWAFMatch(append(conditions, securitypolicy.Condition{Field: "cookie", Operator: "contains", Values: []string{"x"}}))
		if !errors.Is(err, ErrUnsupportedRuntime) {
			t.Fatalf("edgeWAFMatch error = %v, want ErrUnsupportedRuntime", err)
		}
	})

	t.Run("same-port terminal rule shadows narrower rule", func(t *testing.T) {
		policy := policyForTest(securitypolicy.KindWAF)
		policy.Rules = []securitypolicy.Rule{
			{
				ID: uuid.New(), Name: "all port traffic", Priority: 1, Enabled: true,
				Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowStop,
				Conditions: []securitypolicy.Condition{{Field: "port", Operator: "number_eq", Values: []string{"443"}}},
			},
			{
				ID: uuid.New(), Name: "narrow port path", Priority: 2, Enabled: true,
				Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
				Conditions: []securitypolicy.Condition{
					{Field: "port", Operator: "number_eq", Values: []string{"443"}},
					{Field: "path", Operator: "equals", Values: []string{"/admin"}},
				},
			},
		}
		if _, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID,
			[]ActiveBinding{activeBinding(t, policy)}); !errors.Is(err, ErrUnsupportedRuntime) {
			t.Fatalf("CompileSiteSecurityBindings error = %v, want ErrUnsupportedRuntime", err)
		}
	})

	t.Run("different port does not shadow", func(t *testing.T) {
		policy := policyForTest(securitypolicy.KindWAF)
		policy.Rules = []securitypolicy.Rule{
			{
				ID: uuid.New(), Name: "first port", Priority: 1, Enabled: true,
				Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowStop,
				Conditions: []securitypolicy.Condition{{Field: "port", Operator: "number_eq", Values: []string{"443"}}},
			},
			{
				ID: uuid.New(), Name: "other port path", Priority: 2, Enabled: true,
				Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
				Conditions: []securitypolicy.Condition{
					{Field: "port", Operator: "number_eq", Values: []string{"8443"}},
					{Field: "path", Operator: "equals", Values: []string{"/admin"}},
				},
			},
		}
		compiled, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID,
			[]ActiveBinding{activeBinding(t, policy)})
		if err != nil {
			t.Fatalf("CompileSiteSecurityBindings: %v", err)
		}
		if got := compiled.Site.SecurityPolicies[0].Rules; len(got) != 2 || got[0].Match.Port != 443 || got[1].Match.Port != 8443 {
			t.Fatalf("compiled rules = %#v", got)
		}
	})
}

func activeBinding(t *testing.T, policy securitypolicy.Policy) ActiveBinding {
	t.Helper()
	compiled, err := securitypolicy.CompileRuntimeSnapshot(policy, testSiteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot: %v", err)
	}
	return ActiveBinding{
		BindingID: uuid.New(), PublicationID: uuid.New(), BindingRevision: 1,
		RuntimeSnapshotSHA256: compiled.SHA256, Snapshot: compiled.Snapshot,
	}
}

func policyForTest(kind string) securitypolicy.Policy {
	return securitypolicy.Policy{
		ID: uuid.New(), ScopeID: testTenantScopeID, Kind: kind, Name: kind, Enabled: true,
		DefaultAction: securitypolicy.ActionAllow, Revision: 1,
		Rules: []securitypolicy.Rule{{
			ID: uuid.New(), Name: "rule", Priority: 1, Enabled: true,
			Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{Field: "method", Operator: "equals", Values: []string{"GET"}}},
		}},
	}
}

func baseSite() edgeconfig.Site {
	return edgeconfig.Site{
		ID: testSiteID.String(), Domain: "security.example.test", ListenPort: 8080,
		Protocol: edgeconfig.ProtocolHTTP,
		Origins:  []edgeconfig.Origin{{Host: "127.0.0.1", Port: 9000, Weight: 1}},
		Balance:  edgeconfig.BalanceRoundRobin, FailoverTries: 1,
		ConnectTimeout: 250 * time.Millisecond, ReadTimeout: 2 * time.Second,
		ACL: edgeconfig.ACLPolicy{DefaultAction: edgeconfig.ACLAllow},
	}
}

func mutatePolicy(policy securitypolicy.Policy, mutate func(*securitypolicy.Policy)) securitypolicy.Policy {
	policy.Rules = append([]securitypolicy.Rule(nil), policy.Rules...)
	for index := range policy.Rules {
		policy.Rules[index].Conditions = append([]securitypolicy.Condition(nil), policy.Rules[index].Conditions...)
		for conditionIndex := range policy.Rules[index].Conditions {
			policy.Rules[index].Conditions[conditionIndex].Values = append([]string(nil), policy.Rules[index].Conditions[conditionIndex].Values...)
		}
	}
	mutate(&policy)
	return policy
}

func cloneBindings(bindings []ActiveBinding) []ActiveBinding {
	result := make([]ActiveBinding, len(bindings))
	copy(result, bindings)
	for index := range result {
		result[index].Snapshot.Rules = append([]securitypolicy.RuntimeRule(nil), bindings[index].Snapshot.Rules...)
		for ruleIndex := range result[index].Snapshot.Rules {
			result[index].Snapshot.Rules[ruleIndex].Conditions = append([]securitypolicy.Condition(nil), bindings[index].Snapshot.Rules[ruleIndex].Conditions...)
			for conditionIndex := range result[index].Snapshot.Rules[ruleIndex].Conditions {
				result[index].Snapshot.Rules[ruleIndex].Conditions[conditionIndex].Values = append([]string(nil),
					bindings[index].Snapshot.Rules[ruleIndex].Conditions[conditionIndex].Values...)
			}
		}
	}
	return result
}

func refreshDigest(binding *ActiveBinding) {
	encoded, _ := json.Marshal(binding.Snapshot)
	binding.RuntimeSnapshotSHA256 = sha256.Sum256(encoded)
}
