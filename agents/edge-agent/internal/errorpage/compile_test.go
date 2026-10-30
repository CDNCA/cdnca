package errorpage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCompileDeterministicSelectionAndInheritance(t *testing.T) {
	global := testRule("global-origin", CategoryOriginResponse, StatusMatch{Ranges: []StatusRange{{From: 400, To: 599}}}, "text/plain", "global origin\n")
	exact := testRule("site-404", CategoryOriginResponse, StatusMatch{Codes: []int{404}}, "text/html", "<!doctype html><title>missing</title><h1>site missing</h1>\n")
	rangeRule := testRule("site-4xx", CategoryOriginResponse, StatusMatch{Ranges: []StatusRange{{From: 400, To: 499}}}, "application/json", "{\"error\":\"site-4xx\"}\n")
	noHost := testRule("no-host", CategoryNoHost, StatusMatch{Codes: []int{400}}, "text/plain", "host required\n")
	unknown := testRule("unknown-site", CategoryUnknownSite, StatusMatch{Codes: []int{404}}, "text/plain", "site unavailable\n")

	first := Policy{
		Schema: SchemaV1, Version: "error-v1", Revision: 17,
		Global: Scope{Rules: []Rule{global, noHost, unknown}},
		Sites:  []SiteScope{{SiteKey: "site-a", Rules: []Rule{rangeRule, exact}}},
	}
	second := first
	second.Global.Rules = []Rule{unknown, global, noHost}
	second.Sites = []SiteScope{{SiteKey: "site-a", Rules: []Rule{exact, rangeRule}}}

	artifactA, err := Compile(first, "")
	if err != nil {
		t.Fatal(err)
	}
	artifactB, err := Compile(second, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(artifactA.CanonicalJSON, artifactB.CanonicalJSON) || !bytes.Equal(artifactA.RuntimeLua, artifactB.RuntimeLua) || artifactA.Digest != artifactB.Digest {
		t.Fatal("semantically identical policies did not compile deterministically")
	}

	assertLookup(t, artifactA, "site-a", CategoryOriginResponse, 404, "text/html", "site missing")
	assertLookup(t, artifactA, "site-a", CategoryOriginResponse, 403, "application/json", "site-4xx")
	assertLookup(t, artifactA, "site-a", CategoryOriginResponse, 503, "text/plain", "global origin")
	assertLookup(t, artifactA, "other-site", CategoryOriginResponse, 404, "text/plain", "global origin")
	assertLookup(t, artifactA, "", CategoryNoHost, 400, "text/plain", "host required")
	if _, found := artifactA.Lookup("site-a", CategoryEdgeConnect, 502); found {
		t.Fatal("unexpected mapping found")
	}
	if artifactA.ResourceCount != 5 || artifactA.BindingCount != 302 {
		t.Fatalf("resources=%d bindings=%d", artifactA.ResourceCount, artifactA.BindingCount)
	}
	if bytes.Contains(artifactA.RuntimeLua, []byte("site missing")) {
		t.Fatal("runtime Lua contains an unencoded user body")
	}
}

func TestCompileRejectsAmbiguousAndInvalidSelectors(t *testing.T) {
	valid := testRule("one", CategoryEdgeRoute, StatusMatch{Codes: []int{404}}, "text/plain", "one\n")
	tests := []struct {
		name  string
		rules []Rule
	}{
		{"empty", []Rule{{ID: "empty", Category: CategoryEdgeRoute, Resource: valid.Resource}}},
		{"invalid-category-status", []Rule{testRule("bad", CategoryEdgeConnect, StatusMatch{Codes: []int{500}}, "text/plain", "bad\n")}},
		{"descending-range", []Rule{testRule("bad", CategoryOriginResponse, StatusMatch{Ranges: []StatusRange{{From: 500, To: 400}}}, "text/plain", "bad\n")}},
		{"equal-precedence", []Rule{valid, testRule("two", CategoryEdgeRoute, StatusMatch{Codes: []int{404}}, "text/plain", "two\n")}},
		{"duplicate-id", []Rule{valid, valid}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(Policy{Schema: SchemaV1, Version: "v1", Revision: 1, Global: Scope{Rules: test.rules}}, "")
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("expected invalid policy, got %v", err)
			}
		})
	}

	siteGlobalOnly := Policy{
		Schema: SchemaV1, Version: "v1", Revision: 1,
		Global: Scope{Rules: []Rule{valid}},
		Sites: []SiteScope{{SiteKey: "site-a", Rules: []Rule{
			testRule("no-host", CategoryNoHost, StatusMatch{Codes: []int{400}}, "text/plain", "bad\n"),
		}}},
	}
	if _, err := Compile(siteGlobalOnly, ""); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("site-scoped no_host accepted: %v", err)
	}
}

func TestCompileRejectsUnsafeStaticBodies(t *testing.T) {
	tests := []struct {
		name string
		mime string
		body string
	}{
		{"script", "text/html", "<script>alert(1)</script>"},
		{"event-handler", "text/html", "<p onclick=\"x()\">x</p>"},
		{"style-import", "text/html", "<style>@import url(https://example.test/x.css)</style>"},
		{"external-url", "text/html", "<a href=\"https://example.test\">x</a>"},
		{"ssi", "text/html", "<!--#include virtual=\"/secret\" -->"},
		{"template", "text/plain", "request={{request_uri}}"},
		{"json", "application/json", "{not-json}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(testRule("bad", CategoryEdgeRoute, StatusMatch{Codes: []int{404}}, test.mime, test.body))
			if _, err := Compile(policy, ""); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("unsafe body accepted: %v", err)
			}
		})
	}

	invalidUTF8 := string([]byte{0xff, 0xfe})
	if _, err := Compile(testPolicy(testRule("bad", CategoryEdgeRoute, StatusMatch{Codes: []int{404}}, "text/plain", invalidUTF8)), ""); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid UTF-8 accepted: %v", err)
	}
}

func TestCompileValidatesOwnerOnlyFileResources(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("file-backed error page\n")
	writeResource := func(name string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	goodPath := writeResource("good.txt", 0o400)
	resource := fileResource("good.txt", "text/plain", body)
	policy := testPolicy(Rule{ID: "file", Category: CategoryEdgeRoute, Match: StatusMatch{Codes: []int{404}}, Resource: resource})
	artifact, err := Compile(policy, root)
	if err != nil {
		t.Fatal(err)
	}
	assertLookup(t, artifact, "", CategoryEdgeRoute, 404, "text/plain", "file-backed")

	badMode := writeResource("bad-mode.txt", 0o600)
	symlink := filepath.Join(root, "symlink.txt")
	if err := os.Symlink(goodPath, symlink); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(root, "hardlink.txt")
	if err := os.Link(goodPath, hardlink); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing.txt")

	tests := []struct {
		name string
		file string
	}{
		{"permission", filepath.Base(badMode)},
		{"symlink", filepath.Base(symlink)},
		{"hardlink", filepath.Base(hardlink)},
		{"missing", filepath.Base(missing)},
		{"traversal", "../outside.txt"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := policy
			candidate.Global.Rules = slices.Clone(policy.Global.Rules)
			candidate.Global.Rules[0].Resource.File = test.file
			_, err := Compile(candidate, root)
			if err == nil {
				t.Fatal("unsafe file accepted")
			}
		})
	}

	tampered := policy
	tampered.Global.Rules = slices.Clone(policy.Global.Rules)
	tampered.Global.Rules[0].Resource.SHA256 = strings.Repeat("0", 64)
	if _, err := Compile(tampered, root); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("digest tampering accepted: %v", err)
	}
}

func TestCompileRejectsOversizedResource(t *testing.T) {
	body := strings.Repeat("x", MaxResourceBytes+1)
	policy := testPolicy(testRule("large", CategoryEdgeRoute, StatusMatch{Codes: []int{404}}, "text/plain", body))
	if _, err := Compile(policy, ""); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("oversized body accepted: %v", err)
	}
}

func testPolicy(rules ...Rule) Policy {
	return Policy{Schema: SchemaV1, Version: "test-v1", Revision: 1, Global: Scope{Rules: rules}}
}

func testRule(id string, category Category, match StatusMatch, mimeType, body string) Rule {
	inline := body
	digest := sha256.Sum256([]byte(body))
	return Rule{
		ID: id, Category: category, Match: match,
		Resource: Resource{
			MIMEType: mimeType, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), Inline: &inline,
		},
	}
}

func fileResource(name, mimeType string, body []byte) Resource {
	digest := sha256.Sum256(body)
	return Resource{MIMEType: mimeType, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), File: name}
}

func assertLookup(t *testing.T, artifact Artifact, siteKey string, category Category, status int, mimeType, contains string) {
	t.Helper()
	resource, found := artifact.Lookup(siteKey, category, status)
	if !found {
		t.Fatalf("mapping not found: site=%q category=%s status=%d", siteKey, category, status)
	}
	if resource.MIMEType != mimeType || !strings.Contains(string(resource.Body), contains) || resource.Size != int64(len(resource.Body)) {
		t.Fatalf("unexpected resource: %+v body=%q", resource, resource.Body)
	}
}
