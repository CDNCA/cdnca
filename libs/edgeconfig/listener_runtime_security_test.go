package edgeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	listenerTestScope   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	listenerTestTenant  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	listenerTestVersion = "018f1000-0000-7000-8000-000000000090"
	listenerTestSite    = "11111111-1111-4111-8111-111111111111"
	listenerTestPolicy  = "55555555-5555-4555-8555-555555555555"
)

// headerWAFPolicy is a bound WAF policy with one header condition, so the
// rendered Lua reads the request headers (and their overflow).
func headerWAFPolicy() SecurityPolicy {
	return SecurityPolicy{Kind: SecurityWAF, PolicyID: "22222222-2222-4222-8222-222222222222", PolicyVersion: 3,
		BindingRevision: 1, RuntimeSHA256: strings.Repeat("a", 64), Enabled: true, DefaultAction: WAFAllow,
		Rules: []WAFRule{{RuleID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
			Match:  WAFMatch{Header: &WAFHeaderMatch{Name: "x-bad", Kind: WAFHeaderExact, Value: "1"}},
			Action: WAFBlock, Control: WAFStop}}}
}

func listenerTestListener(port uint16, security ListenerSecurity) SecurityListener {
	return SecurityListener{SiteID: listenerTestSite, Domain: "waf.example.test", Port: port, Protocol: ProtocolHTTP, Security: security}
}

func listenerTestChallenge() *ListenerChallenge {
	return &ListenerChallenge{TenantID: listenerTestTenant, PolicyID: listenerTestPolicy, PolicyVersion: 7}
}

func listenerTestManagedWAF() *ManagedWAF {
	value := *managedWAFTestSite().ManagedWAF
	normalized, err := CanonicalListenerManagedWAF(value)
	if err != nil {
		panic(err)
	}
	return normalized
}

func TestListenerSecurityCarriesManagedWAFAndChallengeAsJSON(t *testing.T) {
	security := ListenerSecurity{Policies: []SecurityPolicy{headerWAFPolicy()}, ManagedWAF: listenerTestManagedWAF(),
		Challenge: listenerTestChallenge()}
	raw, err := json.Marshal(security)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"managed_waf":{"policy_id":"22222222-2222-4222-8222-222222222222"`,
		`"challenge":{"tenant_id":"` + listenerTestTenant + `","policy_id":"` + listenerTestPolicy + `","policy_version":7}`} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("security JSON lacks %s\n%s", want, raw)
		}
	}
	// A signed document never carries an explicit null (control-api rejects them).
	if bytes.Contains(raw, []byte("null")) {
		t.Fatalf("canonical managed WAF marshals a null\n%s", raw)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decoded ListenerSecurity
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(decoded)
	if !bytes.Equal(raw, again) {
		t.Fatalf("round trip changed the document\n%s\n%s", raw, again)
	}
	if ListenerSecuritySiteRuntimeVersion(&decoded) != ListenerRuntimeSecuritySiteRuntimeVersion ||
		ListenerSecuritySiteRuntimeVersion(&ListenerSecurity{Policies: decoded.Policies}) != 4 {
		t.Fatal("site runtime version does not follow managed WAF / challenge")
	}
}

func TestRenderSecurityFragmentsValidatesListenerChallengeAndManagedWAF(t *testing.T) {
	valid := ListenerSecurity{Policies: []SecurityPolicy{headerWAFPolicy()}, ManagedWAF: listenerTestManagedWAF(),
		Challenge: listenerTestChallenge()}
	if _, err := RenderSecurityFragments(listenerTestScope, listenerTestVersion,
		[]SecurityListener{listenerTestListener(8080, valid), listenerTestListener(8081, valid)}); err != nil {
		t.Fatalf("valid listeners rejected: %v", err)
	}
	cases := map[string]func(*ListenerSecurity, *ListenerSecurity){
		"challenge tenant":     func(first, _ *ListenerSecurity) { first.Challenge.TenantID = "tenant" },
		"challenge policy":     func(first, _ *ListenerSecurity) { first.Challenge.PolicyID = "x" },
		"challenge version 0":  func(first, _ *ListenerSecurity) { first.Challenge.PolicyVersion = 0 },
		"challenge unsafe":     func(first, _ *ListenerSecurity) { first.Challenge.PolicyVersion = 1 << 53 },
		"challenge per port":   func(_, second *ListenerSecurity) { second.Challenge.PolicyVersion = 8 },
		"challenge one port":   func(_, second *ListenerSecurity) { second.Challenge = nil },
		"managed WAF invalid":  func(first, _ *ListenerSecurity) { first.ManagedWAF.Exclusions = []int{12} },
		"managed WAF per port": func(_, second *ListenerSecurity) { second.ManagedWAF.Exclusions = []int{942100} },
		"managed WAF one port": func(_, second *ListenerSecurity) { second.ManagedWAF = nil },
		"managed WAF noncanonical": func(first, _ *ListenerSecurity) {
			first.ManagedWAF.Exclusions = []int{942100, 941100}
		},
		"managed WAF profile": func(first, _ *ListenerSecurity) { first.ManagedWAF.Profile.Version = "1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			first, second := cloneListenerSecurityForTest(valid), cloneListenerSecurityForTest(valid)
			mutate(&first, &second)
			_, err := RenderSecurityFragments(listenerTestScope, listenerTestVersion,
				[]SecurityListener{listenerTestListener(8080, first), listenerTestListener(8081, second)})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestRenderSecurityFragmentsHeaderOverflowFollowsManagedWAFInspectionLimit(t *testing.T) {
	render := func(managed *ManagedWAF) string {
		fragments, err := RenderSecurityFragments(listenerTestScope, listenerTestVersion, []SecurityListener{
			listenerTestListener(8080, ListenerSecurity{Policies: []SecurityPolicy{headerWAFPolicy()}, ManagedWAF: managed})})
		if err != nil {
			t.Fatal(err)
		}
		return fragments.Location[0]
	}
	if got := render(nil); !strings.Contains(got, headerOverflowNoMatchLua) {
		t.Fatalf("default overflow is not log-and-no-match\n%s", got)
	}
	logged := listenerTestManagedWAF()
	if got := render(logged); !strings.Contains(got, headerOverflowNoMatchLua) {
		t.Fatalf("inspection_limit_action=log overflow is not log-and-no-match\n%s", got)
	}
	blocked := listenerTestManagedWAF()
	blocked.InspectionLimitAction = ManagedWAFInspectionBlock
	if got := render(blocked); !strings.Contains(got, "if header_error == \"truncated\" then\n          return ngx.exit(403)") {
		t.Fatalf("inspection_limit_action=block overflow does not return 403\n%s", got)
	}
}

func cloneListenerSecurityForTest(value ListenerSecurity) ListenerSecurity {
	raw, _ := json.Marshal(value)
	var result ListenerSecurity
	_ = json.Unmarshal(raw, &result)
	return result
}
