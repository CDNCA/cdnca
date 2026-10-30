package httppolicycontrol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeConfigCanonicalizesEdgeV1Semantics(t *testing.T) {
	input := validTestConfig()
	input.RequestHeaders = []HeaderAction{
		{Kind: HeaderSet, Name: "X-Zeta", Values: []string{"one", "two"}},
		{Kind: HeaderDelete, Name: "X-Alpha", Values: []string{}},
	}
	input.RedirectAllowedHosts = []string{"[2001:db8::1]:8443", "redirect.example.test"}
	input.CORS.AllowedMethods = []string{"post", "GET"}
	input.CORS.AllowedHeaders = []string{"X-Trace", "Content-Type"}

	got, err := normalizeConfig(input)
	if err != nil {
		t.Fatalf("normalizeConfig() error = %v", err)
	}
	if got.RequestHeaders[0].Name != "x-alpha" || got.RequestHeaders[1].Name != "x-zeta" {
		t.Fatalf("request header order = %#v", got.RequestHeaders)
	}
	if got.RequestHeaders[1].Values[0] != "one" || got.RequestHeaders[1].Values[1] != "two" {
		t.Fatalf("multi-value order changed: %#v", got.RequestHeaders[1].Values)
	}
	if got.ResponseHeaders[0].Values == nil || len(got.ResponseHeaders[0].Values) != 0 {
		t.Fatalf("delete values must remain an empty array: %#v", got.ResponseHeaders[0].Values)
	}
	if strings.Join(got.CORS.AllowedMethods, ",") != "GET,POST" ||
		strings.Join(got.CORS.AllowedHeaders, ",") != "content-type,x-trace" {
		t.Fatalf("CORS tokens not canonical: %#v", got.CORS)
	}
	if got.RedirectAllowedHosts[0] != "[2001:db8::1]:8443" {
		t.Fatalf("IPv6 authority = %q", got.RedirectAllowedHosts[0])
	}
	if got.Redirects[0].TargetURL != "https://redirect.example.test/moved" {
		t.Fatalf("redirect target = %q", got.Redirects[0].TargetURL)
	}
}

func TestNormalizeConfigRejectsDangerousInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "zero upload", mutate: func(value *Config) { value.MaxUploadBytes = 0 }},
		{name: "upload over edge maximum", mutate: func(value *Config) { value.MaxUploadBytes = MaxUploadBytes + 1 }},
		{name: "nil request actions", mutate: func(value *Config) { value.RequestHeaders = nil }},
		{name: "nil response actions", mutate: func(value *Config) { value.ResponseHeaders = nil }},
		{name: "nil rewrites", mutate: func(value *Config) { value.Rewrites = nil }},
		{name: "nil redirects", mutate: func(value *Config) { value.Redirects = nil }},
		{name: "nil allowlist", mutate: func(value *Config) { value.RedirectAllowedHosts = nil }},
		{name: "illegal header token", mutate: requestHeader("X Bad", HeaderSet, []string{"value"})},
		{name: "request action overflow", mutate: func(value *Config) {
			value.RequestHeaders = make([]HeaderAction, MaxHeaderActions+1)
		}},
		{name: "header value count overflow", mutate: requestHeader("X-Test", HeaderSet, make([]string, MaxHeaderValues+1))},
		{name: "header value size overflow", mutate: requestHeader("X-Test", HeaderSet, []string{strings.Repeat("x", MaxHeaderBytes+1)})},
		{name: "framing request header", mutate: requestHeader("Content-Length", HeaderSet, []string{"1"})},
		{name: "hop by hop request header", mutate: requestHeader("Connection", HeaderSet, []string{"close"})},
		{name: "forwarded identity", mutate: requestHeader("X-Forwarded-For", HeaderSet, []string{"192.0.2.1"})},
		{name: "real IP identity", mutate: requestHeader("X-Real-IP", HeaderSet, []string{"192.0.2.1"})},
		{name: "internal reserved header", mutate: requestHeader("X-CDNCA-Actor", HeaderSet, []string{"admin"})},
		{name: "request origin ownership", mutate: requestHeader("Origin", HeaderSet, []string{"https://evil.test"})},
		{name: "response location ownership", mutate: responseHeader("Location", HeaderSet, []string{"https://evil.test"})},
		{name: "response CORS ownership", mutate: responseHeader("Access-Control-Allow-Origin", HeaderSet, []string{"*"})},
		{name: "response vary ownership", mutate: responseHeader("Vary", HeaderSet, []string{"Origin"})},
		// header_filter slots after the HTTP policy own these (docs/edge/dynroute-filters.md §2).
		{name: "response HSTS ownership", mutate: responseHeader("Strict-Transport-Security", HeaderSet, []string{"max-age=0"})},
		{name: "response Alt-Svc ownership", mutate: responseHeader("Alt-Svc", HeaderSet, []string{"clear"})},
		{name: "response cache status ownership", mutate: responseHeader("X-CDN-Cache", HeaderSet, []string{"HIT"})},
		{name: "response cdnca internal header", mutate: responseHeader("X-Cdnca-Site", HeaderSet, []string{"x"})},
		{name: "request cdnca internal header", mutate: requestHeader("X-Cdnca-Actor", HeaderSet, []string{"admin"})},
		{name: "CRLF", mutate: requestHeader("X-Test", HeaderSet, []string{"good\r\nInjected: bad"})},
		{name: "control value", mutate: requestHeader("X-Test", HeaderSet, []string{"bad\x7f"})},
		{name: "non ASCII value", mutate: requestHeader("X-Test", HeaderSet, []string{"caf\u00e9"})},
		{name: "delete with nil values", mutate: requestHeader("X-Test", HeaderDelete, nil)},
		{name: "duplicate case insensitive header", mutate: func(value *Config) {
			value.RequestHeaders = []HeaderAction{
				{Kind: HeaderSet, Name: "X-Test", Values: []string{"a"}},
				{Kind: HeaderAdd, Name: "x-test", Values: []string{"b"}},
			}
		}},
		{name: "path traversal", mutate: rewriteMatch("/a/../secret")},
		{name: "encoded traversal", mutate: rewriteMatch("/%2e%2e/secret")},
		{name: "double encoded traversal", mutate: rewriteMatch("/%252e%252e/secret")},
		{name: "backslash path", mutate: rewriteMatch("/a\\secret")},
		{name: "query in path", mutate: rewriteMatch("/a?x=1")},
		{name: "double slash", mutate: rewriteMatch("/a//b")},
		{name: "noncanonical exact trailing slash", mutate: rewriteMatch("/legacy/")},
		{name: "self rewrite", mutate: func(value *Config) { value.Rewrites[0].TargetPath = value.Rewrites[0].MatchPath }},
		{name: "rewrite loop", mutate: func(value *Config) {
			value.Rewrites = []RewriteRule{
				{RuleID: "a", Priority: 1, MatchKind: MatchPrefix, MatchPath: "/a/", TargetPath: "/b/"},
				{RuleID: "b", Priority: 2, MatchKind: MatchPrefix, MatchPath: "/b/", TargetPath: "/a/"},
			}
		}},
		{name: "rewrite hop overflow", mutate: func(value *Config) {
			value.Rewrites = make([]RewriteRule, MaxRewriteHops+1)
			for index := range value.Rewrites {
				value.Rewrites[index] = RewriteRule{
					RuleID: fmt.Sprintf("r%02d", index), Priority: uint32(index), MatchKind: MatchExact,
					MatchPath: fmt.Sprintf("/p%d", index), TargetPath: fmt.Sprintf("/p%d", index+1),
				}
			}
		}},
		{name: "same priority overlap", mutate: func(value *Config) {
			value.Rewrites = []RewriteRule{
				{RuleID: "a", Priority: 1, MatchKind: MatchPrefix, MatchPath: "/a/", TargetPath: "/b/"},
				{RuleID: "b", Priority: 1, MatchKind: MatchExact, MatchPath: "/a/x", TargetPath: "/c"},
			}
		}},
		{name: "cross kind duplicate rule ID", mutate: func(value *Config) { value.Redirects[0].RuleID = value.Rewrites[0].RuleID }},
		{name: "rewrite list overflow", mutate: func(value *Config) { value.Rewrites = make([]RewriteRule, MaxRules+1) }},
		{name: "redirect list overflow", mutate: func(value *Config) { value.Redirects = make([]RedirectRule, MaxRules+1) }},
		{name: "authority list overflow", mutate: func(value *Config) { value.RedirectAllowedHosts = make([]string, MaxOrigins+1) }},
		{name: "open redirect host", mutate: func(value *Config) { value.Redirects[0].TargetURL = "https://evil.test/moved" }},
		{name: "authority hostname label overflow", mutate: func(value *Config) {
			value.RedirectAllowedHosts = []string{strings.Repeat("a", 64) + ".test"}
		}},
		{name: "authority port overflow", mutate: func(value *Config) {
			value.RedirectAllowedHosts = []string{"redirect.example.test:70000"}
		}},
		{name: "malformed IPv6 authority", mutate: func(value *Config) {
			value.RedirectAllowedHosts = []string{"[::::]"}
		}},
		{name: "redirect userinfo", mutate: func(value *Config) { value.Redirects[0].TargetURL = "https://user@redirect.example.test/moved" }},
		{name: "redirect query", mutate: func(value *Config) { value.Redirects[0].TargetURL = "https://redirect.example.test/moved?next=evil" }},
		{name: "redirect fragment", mutate: func(value *Config) { value.Redirects[0].TargetURL = "https://redirect.example.test/moved#x" }},
		{name: "redirect encoded path", mutate: func(value *Config) { value.Redirects[0].TargetURL = "https://redirect.example.test/%2e%2e/x" }},
		{name: "redirect path traversal", mutate: func(value *Config) { value.Redirects[0].TargetURL = "https://redirect.example.test/a/../x" }},
		{name: "redirect unsupported scheme", mutate: func(value *Config) { value.Redirects[0].TargetURL = "javascript://redirect.example.test/moved" }},
		{name: "redirect dynamic authority", mutate: func(value *Config) { value.Redirects[0].TargetURL = "https://${host}/moved" }},
		{name: "CORS credentials wildcard origin", mutate: func(value *Config) {
			value.CORS.AllowCredentials = true
			value.CORS.AllowedOrigins = []string{"*"}
		}},
		{name: "CORS credentials wildcard header", mutate: func(value *Config) {
			value.CORS.AllowCredentials = true
			value.CORS.AllowedHeaders = []string{"*"}
		}},
		{name: "CORS origin path", mutate: func(value *Config) { value.CORS.AllowedOrigins = []string{"https://app.example.test/path"} }},
		{name: "CORS hostname label overflow", mutate: func(value *Config) {
			value.CORS.AllowedOrigins = []string{"https://" + strings.Repeat("a", 64) + ".test"}
		}},
		{name: "CORS empty methods", mutate: func(value *Config) { value.CORS.AllowedMethods = []string{} }},
		{name: "CORS illegal method token", mutate: func(value *Config) { value.CORS.AllowedMethods = []string{"GET BAD"} }},
		{name: "CORS max age", mutate: func(value *Config) { value.CORS.MaxAgeSeconds = 86401 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validTestConfig()
			test.mutate(&input)
			if _, err := normalizeConfig(input); !errors.Is(err, ErrValidation) {
				t.Fatalf("normalizeConfig() error = %v, want ErrValidation", err)
			}
		})
	}
}

func TestCanonicalSnapshotIsDeterministicAndBounded(t *testing.T) {
	firstID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	secondID := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	first := Policy{SiteID: firstID, Enabled: true}
	second := Policy{SiteID: secondID, Enabled: true}
	applyConfig(&first, mustNormalizeConfig(t, validTestConfig()))
	applyConfig(&second, mustNormalizeConfig(t, validTestConfig()))

	snapshotA, canonicalA, digestA, err := canonicalSnapshot(9, []Policy{second, first})
	if err != nil {
		t.Fatal(err)
	}
	snapshotB, canonicalB, digestB, err := canonicalSnapshot(9, []Policy{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if string(canonicalA) != string(canonicalB) || digestA != digestB ||
		snapshotA.Sites[0].SiteID != firstID.String() || snapshotB.Sites[0].SiteID != firstID.String() {
		t.Fatalf("snapshot not deterministic: %s != %s", canonicalA, canonicalB)
	}
	if canonicalA[len(canonicalA)-1] != '\n' || len(hex.EncodeToString(digestA[:])) != 64 {
		t.Fatalf("canonical framing or digest invalid")
	}
	if _, _, _, err := canonicalSnapshot(0, []Policy{first}); !errors.Is(err, ErrConflict) {
		t.Fatalf("zero version error = %v", err)
	}
	if _, _, _, err := canonicalSnapshot(1, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("empty sites error = %v", err)
	}

	invalid := first
	invalid.MaxUploadBytes = 0
	for name, policies := range map[string][]Policy{
		"invalid config":  {invalid},
		"duplicate site":  {first, first},
		"disabled policy": {func() Policy { value := first; value.Enabled = false; return value }()},
		"deleted policy":  {func() Policy { value := first; value.Enabled = true; value.Deleted = true; return value }()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := canonicalSnapshot(1, policies); !errors.Is(err, ErrConflict) {
				t.Fatalf("canonicalSnapshot() error = %v, want ErrConflict", err)
			}
		})
	}
}

func TestCanonicalSnapshotPreservesEmptyRequiredArrays(t *testing.T) {
	config := validTestConfig()
	config.RequestHeaders = []HeaderAction{}
	config.ResponseHeaders = []HeaderAction{}
	config.Rewrites = []RewriteRule{}
	config.RedirectAllowedHosts = []string{}
	config.Redirects = []RedirectRule{}
	policy := Policy{SiteID: uuid.MustParse("00000000-0000-0000-0000-000000000003"), Enabled: true}
	applyConfig(&policy, mustNormalizeConfig(t, config))

	snapshot, canonical, _, err := canonicalSnapshot(1, []Policy{policy})
	if err != nil {
		t.Fatalf("canonicalSnapshot() error = %v", err)
	}
	site := snapshot.Sites[0]
	if site.RequestHeaders == nil || site.ResponseHeaders == nil || site.Rewrites == nil ||
		site.RedirectAllowedHosts == nil || site.Redirects == nil {
		t.Fatalf("snapshot required arrays contain nil: %#v", site)
	}
	encoded := string(canonical)
	for _, field := range []string{
		"request_headers", "response_headers", "rewrites", "redirect_allowed_hosts", "redirects",
	} {
		if strings.Contains(encoded, fmt.Sprintf("%q:null", field)) ||
			!strings.Contains(encoded, fmt.Sprintf("%q:[]", field)) {
			t.Fatalf("canonical snapshot field %s is not an empty array: %s", field, canonical)
		}
	}
}

func validTestConfig() Config {
	return Config{
		MaxUploadBytes: 16,
		RequestHeaders: []HeaderAction{
			{Kind: HeaderSet, Name: "X-Origin-Request", Values: []string{"one", "two"}},
		},
		ResponseHeaders: []HeaderAction{
			{Kind: HeaderDelete, Name: "X-Powered-By", Values: []string{}},
		},
		Rewrites: []RewriteRule{
			{RuleID: "rewrite-v1", Priority: 10, MatchKind: MatchExact, MatchPath: "/legacy", TargetPath: "/v1", PreserveQuery: true, PreserveCookie: true},
		},
		RedirectAllowedHosts: []string{"redirect.example.test"},
		Redirects: []RedirectRule{
			{RuleID: "redirect-gone", Priority: 20, MatchKind: MatchExact, MatchPath: "/gone", Status: 308, TargetURL: "https://redirect.example.test/moved", PreserveQuery: true},
		},
		CORS: &CORSPolicy{
			AllowedOrigins: []string{"https://app.example.test"}, AllowedMethods: []string{"GET", "POST"},
			AllowedHeaders: []string{"content-type", "x-trace"}, ExposedHeaders: []string{"x-request-id"},
			AllowCredentials: true, MaxAgeSeconds: 600,
		},
	}
}

func mustNormalizeConfig(t *testing.T, input Config) Config {
	t.Helper()
	result, err := normalizeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func requestHeader(name, kind string, values []string) func(*Config) {
	return func(value *Config) { value.RequestHeaders = []HeaderAction{{Kind: kind, Name: name, Values: values}} }
}

func responseHeader(name, kind string, values []string) func(*Config) {
	return func(value *Config) { value.ResponseHeaders = []HeaderAction{{Kind: kind, Name: name, Values: values}} }
}

func rewriteMatch(path string) func(*Config) {
	return func(value *Config) { value.Rewrites[0].MatchPath = path }
}
