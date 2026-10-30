package ccv2

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// The fixtures are written by control-api
// (securitypublication.TestCompileCCV2V6MatchesAgentParityFixture): IP lists
// from a range, a netmask and an exclusion, header / UA / Referer matches, a
// single address kept as source_cidr, trusted crawlers and a pass cookie
// domain (CC API v6).
func TestCompileSourceReproducesControlV6(t *testing.T) {
	source, err := os.ReadFile("testdata/v6.source.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/v6.compiled.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := CompileSource(source, countByBinding)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("edge compile differs from control compile:\n got %s\nwant %s", got, want)
	}
	policy, err := edgeconfig.DecodeCCV2Policy(got)
	if err != nil || edgeconfig.CCV2PolicyAPIVersion(policy) != 6 {
		t.Fatalf("decode: %v (CC v%d)", err, edgeconfig.CCV2PolicyAPIVersion(policy))
	}
}

func TestCompileSourceRejectsNonCanonicalV6(t *testing.T) {
	raw, err := os.ReadFile("testdata/v6.source.json")
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	replace := func(old, replacement string) string { return strings.Replace(valid, old, replacement, 1) }
	cases := map[string]string{
		"unsorted conditions": replace(`{"field":"client_ip","operator":"ip_in_cidr","values":["10.0.0.0/24","192.0.2.0/25"]},{"field":"client_ip","operator":"ip_not_in_cidr","values":["10.0.0.7/32"]}`,
			`{"field":"client_ip","operator":"ip_not_in_cidr","values":["10.0.0.7/32"]},{"field":"client_ip","operator":"ip_in_cidr","values":["10.0.0.0/24","192.0.2.0/25"]}`),
		"ip equals list":     replace(`"operator":"equals","values":["203.0.113.9"]`, `"operator":"equals","values":["203.0.113.8","203.0.113.9"]`),
		"ip unknown op":      replace(`"operator":"ip_not_in_cidr"`, `"operator":"ip_out"`),
		"header without key": replace(`{"field":"header","operator":"prefix","key":"x-client","values":["bot-"]}`, `{"field":"header","operator":"prefix","values":["bot-"]}`),
		"ua with key":        replace(`{"field":"user_agent","operator":"regex","values":["(?i)python"]}`, `{"field":"user_agent","operator":"regex","key":"x","values":["(?i)python"]}`),
		"header suffix":      replace(`"operator":"prefix","key":"x-client"`, `"operator":"suffix","key":"x-client"`),
		"bad regex":          replace(`"(?i)python"`, `"(python"`),
		"crawler unsorted": replace(`"trusted_crawlers":[{"name":"baidu","user_agent_tokens":["Baiduspider"],"rdns_suffixes":["baidu.com","baidu.jp"]},{"name":"google","user_agent_tokens":["Googlebot"],"networks":["66.249.64.0/19"],"rdns_suffixes":["google.com","googlebot.com"]}]`,
			`"trusted_crawlers":[{"name":"google","user_agent_tokens":["Googlebot"],"networks":["66.249.64.0/19"],"rdns_suffixes":["google.com","googlebot.com"]},{"name":"baidu","user_agent_tokens":["Baiduspider"],"rdns_suffixes":["baidu.com","baidu.jp"]}]`),
		"crawler no verification": replace(`,"rdns_suffixes":["baidu.com","baidu.jp"]`, ``),
		"crawler no token":        replace(`"user_agent_tokens":["Baiduspider"]`, `"user_agent_tokens":[]`),
		"domain upper":            replace(`"challenge_cookie_domain":"example.test"`, `"challenge_cookie_domain":"Example.test"`),
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if source == valid {
				t.Fatal("mutation did not apply")
			}
			if _, err := CompileSource([]byte(source), countByBinding); !errors.Is(err, ErrInvalidSource) {
				t.Fatalf("error = %v, want ErrInvalidSource", err)
			}
		})
	}
}

// TestCompileSourceDisabledDropsV6Settings mirrors the control side: a
// disabled policy compiles without crawlers or cookie domain.
func TestCompileSourceDisabledDropsV6Settings(t *testing.T) {
	raw, err := os.ReadFile("testdata/v6.source.json")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(raw), `"enabled":true,"default_action"`, `"enabled":false,"default_action"`, 1)
	got, err := CompileSource([]byte(source), countByBinding)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "trusted_crawlers") || strings.Contains(string(got), "challenge_cookie_domain") {
		t.Fatalf("disabled policy kept v6 settings: %s", got)
	}
}
