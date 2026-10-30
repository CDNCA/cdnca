package httppolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Header variables / allow_duplicate and rule conditions.
// The tests/httppolicy-extras policy compiles; with HTTPPOLICY_EXTRAS_OUT
// the canonical site entry (the node's http_policy object bytes) is written
// there for the real OpenResty run.
func TestCompileHeaderVariablesAndConditions(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "tests", "httppolicy-extras", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var site json.RawMessage = raw
	wrapped, _ := json.Marshal(map[string]any{"schema_version": SchemaVersion, "policy_version": 7, "sites": []json.RawMessage{site}})
	artifact, err := CompileJSON(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	var compiled Policy
	if err := json.Unmarshal(artifact.Canonical, &compiled); err != nil {
		t.Fatal(err)
	}
	entry, _ := json.Marshal(compiled.Sites[0])
	if out := os.Getenv("HTTPPOLICY_EXTRAS_OUT"); out != "" {
		if err := os.WriteFile(out, entry, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(string(entry), `"allow_duplicate":true`) || !strings.Contains(string(entry), `"conditions":[{"source":"header","name":"x-beta"`) {
		t.Fatalf("canonical entry lost fields: %s", entry)
	}
	for name, mutate := range map[string]func(*SitePolicy){
		"unknown variable": func(s *SitePolicy) { s.RequestHeaders[0].Values = []string{"$nope"} },
		"dangling dollar":  func(s *SitePolicy) { s.RequestHeaders[0].Values = []string{"a$"} },
		"duplicate on set": func(s *SitePolicy) { s.RequestHeaders[0].AllowDuplicate = true },
		"condition source": func(s *SitePolicy) { s.Rewrites[0].Conditions[0].Source = "body" },
		"header without name": func(s *SitePolicy) {
			s.Rewrites[0].Conditions[0].Source, s.Rewrites[0].Conditions[0].Name = "header", ""
		},
		"nested repeat pattern": func(s *SitePolicy) { s.Rewrites[0].Conditions[0].Pattern = "(a+)+" },
		"empty conditions":      func(s *SitePolicy) { s.Redirects[0].Conditions = []edgeconfig.RuleCondition{} },
	} {
		candidate := compiled.Sites[0]
		candidate.RequestHeaders = append([]HeaderAction(nil), candidate.RequestHeaders...)
		candidate.Rewrites = append([]RewriteRule(nil), candidate.Rewrites...)
		candidate.Rewrites[0].Conditions = append([]edgeconfig.RuleCondition(nil), candidate.Rewrites[0].Conditions...)
		candidate.Redirects = append([]RedirectRule(nil), candidate.Redirects...)
		mutate(&candidate)
		if _, err := normalizeSite(candidate); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
