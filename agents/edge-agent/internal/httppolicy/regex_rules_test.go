package httppolicy

import (
	"encoding/json"
	"errors"
	"testing"
)

// The node accepts regex rules and preserve_path as control
// publishes them and refuses what control would refuse.
func TestCompileJSONRegexAndPreservePath(t *testing.T) {
	base := func() Policy {
		policy := validPolicy(1)
		site := &policy.Sites[0]
		site.RedirectAllowedHosts = []string{"example.test"}
		site.Rewrites = []RewriteRule{{RuleID: "rx", Priority: 1, MatchKind: MatchRegex,
			MatchPath: `^/item/([0-9]+)$`, TargetPath: "/items/$1"}}
		site.Redirects = []RedirectRule{
			{RuleID: "rd", Priority: 2, MatchKind: MatchRegex, MatchPath: `^/u/(\w+)$`, Status: 301, TargetURL: "https://example.test/users/$1"},
			{RuleID: "keep", Priority: 3, MatchKind: MatchPrefix, MatchPath: "/docs/", Status: 302, TargetURL: "https://example.test/manual/", PreservePath: true},
		}
		return policy
	}
	artifact := compilePolicy(t, base())
	var compiled Policy
	if err := json.Unmarshal(artifact.Canonical, &compiled); err != nil || !compiled.Sites[0].Redirects[1].PreservePath {
		t.Fatalf("preserve_path lost: %v %s", err, artifact.Canonical)
	}
	for name, mutate := range map[string]func(*SitePolicy){
		"unanchored":         func(site *SitePolicy) { site.Rewrites[0].MatchPath = `/item` },
		"backreference":      func(site *SitePolicy) { site.Rewrites[0].MatchPath = `^/(a)\1` },
		"missing group":      func(site *SitePolicy) { site.Rewrites[0].TargetPath = "/items/$2" },
		"redirect group":     func(site *SitePolicy) { site.Redirects[0].TargetURL = "https://example.test/$2" },
		"regex keeps path":   func(site *SitePolicy) { site.Redirects[0].PreservePath = true },
		"keep without slash": func(site *SitePolicy) { site.Redirects[1].TargetURL = "https://example.test/manual" },
	} {
		policy := base()
		mutate(&policy.Sites[0])
		raw, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CompileJSON(raw); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("%s: err = %v, want ErrInvalidPolicy", name, err)
		}
	}
}
