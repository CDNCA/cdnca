package edgeconfig

import (
	"errors"
	"fmt"
	"testing"
)

const (
	testJA4Chrome  = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	testJA4Curl    = "t13d3112h2_e8f1e7e78f70_6bebaf5329ac"
	testJA4NoSigAl = "t13d1516h2_8daaf6152771_6d807ffa2a79"
)

func ja4SecurityPolicy(values ...string) SecurityPolicy {
	return SecurityPolicy{
		Kind: SecurityWAF, PolicyID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		PolicyVersion: 2, BindingRevision: 4,
		RuntimeSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Enabled:       true, DefaultAction: WAFAllow,
		Rules: []WAFRule{{
			RuleID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
			Match:  WAFMatch{JA4: values}, Action: WAFBlock, Control: WAFStop,
		}},
	}
}

func TestJA4PatternMatchesModuleOutput(t *testing.T) {
	for _, value := range []string{testJA4Chrome, testJA4NoSigAl, "t12i120000_d34a8e72043a_000000000000",
		"q13d0310h3_55b375c5d22e_cd85d2d88918", "t00i990000_78cd3e4e4f62_000000000000", "t13i1514ad_8daaf6152771_e5627efa2ab1"} {
		if !ValidJA4(value) {
			t.Errorf("ValidJA4(%q) = false", value)
		}
	}
	for _, value := range []string{"", "forged-ja4", "__unknown__", "t13d1516h2_8daaf6152771", "t13d1516h2_8DAAF6152771_e5627efa2ab1",
		"x13d1516h2_8daaf6152771_e5627efa2ab1", "t13d1516h2_8daaf6152771_e5627efa2ab1\n", "t14d1516h2_8daaf6152771_e5627efa2ab1",
		"t13d1516h-_8daaf6152771_e5627efa2ab1"} {
		if ValidJA4(value) {
			t.Errorf("ValidJA4(%q) = true", value)
		}
	}
}

func TestBoundSecurityJA4RejectsInvalidSets(t *testing.T) {
	tooMany := make([]string, MaxWAFJA4Values+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("t13d1516h2_8daaf6152771_%012x", index)
	}
	for name, values := range map[string][]string{
		"empty":     {},
		"duplicate": {testJA4Chrome, testJA4Chrome},
		"malformed": {"forged-ja4"},
		"injection": {`t13d1516h2_8daaf6152771_e5627efa2ab1" or true or "`},
		"too many":  tooMany,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeSecurityPolicies([]SecurityPolicy{ja4SecurityPolicy(values...)}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestLegacySiteWAFRefusesJA4(t *testing.T) {
	_, err := normalizeWAF(WAFPolicy{Rules: []WAFRule{{Match: WAFMatch{JA4: []string{testJA4Chrome}}, Action: WAFDeny, Control: WAFStop}}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("legacy WAF with JA4 err = %v, want ErrInvalidConfig", err)
	}
}

func TestWAFJA4Covers(t *testing.T) {
	if !WAFJA4Covers(nil, []string{testJA4Chrome}) || !WAFJA4Covers(nil, nil) ||
		WAFJA4Covers([]string{testJA4Chrome}, nil) ||
		!WAFJA4Covers([]string{testJA4Chrome, testJA4Curl}, []string{testJA4Curl}) ||
		WAFJA4Covers([]string{testJA4Chrome}, []string{testJA4Chrome, testJA4Curl}) {
		t.Fatal("WAFJA4Covers is not subset coverage")
	}
}

// fix-ja4rule ②: NotJA4 matches a request whose fingerprint is none of the
// set; a request without a fingerprint never matches (CAPABILITY_NAME_WAF_JA4_NEGATION).
func TestBoundSecurityNotJA4(t *testing.T) {
	policy := ja4SecurityPolicy()
	policy.Rules[0].Match = WAFMatch{NotJA4: []string{testJA4Curl, testJA4Chrome}}
	normalized, err := normalizeSecurityPolicies([]SecurityPolicy{policy})
	if err != nil {
		t.Fatal(err)
	}
	if got := normalized[0].Rules[0].Match.NotJA4; len(got) != 2 || got[0] != testJA4Chrome {
		t.Fatalf("NotJA4 not canonical: %v", got)
	}
	if got := RenderWAFNotJA4Condition([]string{testJA4Chrome}); got != `(ngx.var.cdnca_ja4 or "") ~= "" and ngx.var.cdnca_ja4 ~= "`+testJA4Chrome+`"` {
		t.Fatalf("render = %s", got)
	}
	if !SecurityPoliciesUseJA4(normalized) || !SecurityPoliciesUseJA4Negation(normalized) {
		t.Fatal("NotJA4 must need JA4 and WAF_JA4_NEGATION")
	}
	if SecurityPoliciesUseJA4Negation([]SecurityPolicy{ja4SecurityPolicy(testJA4Chrome)}) {
		t.Fatal("JA4 in set must not need WAF_JA4_NEGATION")
	}
	plan, err := CompileSecurityRulePlan(normalized, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if condition := plan.Segments[0].Rules[0].Conditions[0]; condition.Op != RuleOpJA4NotIn || len(condition.Values) != 2 {
		t.Fatalf("plan condition = %+v", condition)
	}
	for name, values := range map[string][]string{"empty": {}, "malformed": {"forged-ja4"}, "duplicate": {testJA4Chrome, testJA4Chrome}} {
		policy.Rules[0].Match = WAFMatch{NotJA4: values}
		if _, err := normalizeSecurityPolicies([]SecurityPolicy{policy}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A JA4 set and its negation in one rule is a contradiction the editor never builds.
	policy.Rules[0].Match = WAFMatch{JA4: []string{testJA4Chrome}, NotJA4: []string{testJA4Curl}}
	if _, err := normalizeSecurityPolicies([]SecurityPolicy{policy}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("both: err = %v", err)
	}
	if _, err := normalizeWAF(WAFPolicy{Rules: []WAFRule{{Match: WAFMatch{NotJA4: []string{testJA4Chrome}}, Action: WAFDeny, Control: WAFStop}}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("legacy WAF with NotJA4 err = %v", err)
	}
}
