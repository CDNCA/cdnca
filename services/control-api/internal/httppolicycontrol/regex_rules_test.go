package httppolicycontrol

import (
	"errors"
	"testing"
)

// Regex rewrites/redirects with capture groups, and prefix
// redirects that keep the path after the prefix (preserve_path).
func TestNormalizeConfigRegexAndPreservePath(t *testing.T) {
	config := validTestConfig()
	config.Rewrites = append(config.Rewrites, RewriteRule{RuleID: "rx-rewrite", Priority: 30, MatchKind: MatchRegex,
		MatchPath: `^/item/([0-9]+)/(\w+)$`, TargetPath: "/items/$2/$1"})
	config.Redirects = append(config.Redirects,
		RedirectRule{RuleID: "rx-redirect", Priority: 40, MatchKind: MatchRegex, MatchPath: `^/u/([a-z]+)$`,
			Status: 301, TargetURL: "https://redirect.example.test/users/$1"},
		RedirectRule{RuleID: "keep-path", Priority: 50, MatchKind: MatchPrefix, MatchPath: "/docs/",
			Status: 302, TargetURL: "https://redirect.example.test/manual/", PreservePath: true})
	if _, err := normalizeConfig(config); err != nil {
		t.Fatalf("valid regex and preserve_path config rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"unanchored regex":       func(c *Config) { c.Rewrites[1].MatchPath = `/item/([0-9]+)` },
		"regex not RE2":          func(c *Config) { c.Rewrites[1].MatchPath = `^/(a)\1` },
		"lookahead":              func(c *Config) { c.Rewrites[1].MatchPath = `^/(?=a)` },
		"invalid regex":          func(c *Config) { c.Rewrites[1].MatchPath = `^/(` },
		"too many groups":        func(c *Config) { c.Rewrites[1].MatchPath = `^/(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)` },
		"unknown group":          func(c *Config) { c.Rewrites[1].TargetPath = "/items/$3" },
		"group zero":             func(c *Config) { c.Rewrites[1].TargetPath = "/items/$0" },
		"bare dollar":            func(c *Config) { c.Rewrites[1].TargetPath = "/items/$" },
		"regex target traversal": func(c *Config) { c.Rewrites[1].TargetPath = "/a/../$1" },
		"regex target query":     func(c *Config) { c.Rewrites[1].TargetPath = "/a?$1" },
		"redirect group unknown": func(c *Config) { c.Redirects[1].TargetURL = "https://redirect.example.test/users/$2" },
		"redirect host by group": func(c *Config) { c.Redirects[1].TargetURL = "https://$1.example.test/users" },
		"regex preserve_path":    func(c *Config) { c.Redirects[1].PreservePath = true },
		"exact preserve_path":    func(c *Config) { c.Redirects[0].PreservePath = true },
		"preserve_path file":     func(c *Config) { c.Redirects[2].TargetURL = "https://redirect.example.test/manual" },
		"regex same priority":    func(c *Config) { c.Redirects[1].Priority = c.Rewrites[0].Priority },
	} {
		input := validTestConfig()
		input.Rewrites = append(input.Rewrites, config.Rewrites[1])
		input.Redirects = append(input.Redirects, config.Redirects[1], config.Redirects[2])
		mutate(&input)
		if _, err := normalizeConfig(input); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
}
