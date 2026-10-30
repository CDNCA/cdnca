package analyticslog

import (
	"strings"
	"testing"
)

// retest-n4: a managed WAF block row's CRS rule ID shows as
// "OWASP CRS #<id>" with the embedded CRS text's msg.
func TestCRSRuleNameFromEmbeddedCRS(t *testing.T) {
	name := crsRuleName("942100")
	if name != "OWASP CRS #942100 · SQL Injection Attack Detected via libinjection" {
		t.Fatalf("942100 named %q", name)
	}
	if name := crsRuleName("941100"); !strings.HasPrefix(name, "OWASP CRS #941100 · ") || !strings.Contains(name, "XSS") {
		t.Fatalf("941100 named %q", name)
	}
	for _, id := range []string{"", "managed-waf-30100", "30100", "94210", "9421000", "e3b0c442-98fc-1c14-9afb-4c8996fb9242"} {
		if name := crsRuleName(id); name != "" {
			t.Errorf("%q named %q", id, name)
		}
	}
}

func TestEventNamesRuleFallsBackToCRS(t *testing.T) {
	policy := "6f1b0e2a-7c55-4a39-9c6e-8f1a3a1c2d01"
	names := EventNames{Rules: map[string]map[string]string{policy: {"942100": "my rule"}}}
	if got := names.rule(policy, "942100"); got != "my rule" {
		t.Fatalf("policy rule name %q", got)
	}
	if got := names.rule("", "941100"); !strings.HasPrefix(got, "OWASP CRS #941100") {
		t.Fatalf("CRS rule without a policy %q", got)
	}
	if got := names.rule(policy, "932160"); !strings.HasPrefix(got, "OWASP CRS #932160") {
		t.Fatalf("CRS rule with a policy %q", got)
	}
	// fix-wafname: a set decision without a CRS rule is named, not shown raw.
	if got := names.rule("", "managed-waf-30100"); got != "托管 WAF · 规则集判定" {
		t.Fatalf("decision rule named %q", got)
	}
}

func TestParseCRSMessagesBoundAndChain(t *testing.T) {
	files := map[string][]byte{"rules/A.conf": []byte("SecRule ARGS \"@rx a\" \\\n    \"id:911100,\\\n    phase:2,\\\n    msg:'Method  is not\\' allowed',\\\n    chain\"\n" +
		"    SecRule ARGS \"@rx b\" \"t:none,msg:'link'\"\nSecAction \"id:900990,nolog\"\n"),
		"rules/B.data": []byte("id:999999 msg:'x'")}
	messages := parseCRSMessages(files)
	if messages["911100"] != `Method is not\' allowed` || messages["900990"] != "" || messages["999999"] != "" {
		t.Fatalf("messages %#v", messages)
	}
	long := crsRuleName("942100")
	if len(long) > 128 {
		t.Fatalf("name %d bytes", len(long))
	}
}
