package httppolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCompileJSONCanonicalizesSemanticSetsAndPreservesHeaderValueOrder(t *testing.T) {
	policy := validPolicy(1)
	policy.Sites[0].RequestHeaders = []HeaderAction{
		{Kind: HeaderDelete, Name: "X-Delete", Values: []string{}},
		{Kind: HeaderAdd, Name: "x-Multi", Values: []string{"edge-a", "edge-b"}},
	}
	policy.Sites[0].RedirectAllowedHosts = []string{"[2001:DB8::1]:8443", "EXAMPLE.test", "127.0.0.1:8080"}
	policy.Sites[0].Redirects = []RedirectRule{
		{RuleID: "v6", Priority: 2, MatchKind: MatchExact, MatchPath: "/v6", Status: 308, TargetURL: "https://[2001:DB8::1]:8443/next", PreserveQuery: true},
		{RuleID: "v4", Priority: 1, MatchKind: MatchExact, MatchPath: "/v4", Status: 307, TargetURL: "http://127.0.0.1:8080/next"},
	}
	policy.Sites[0].CORS.AllowedOrigins = []string{"https://B.example.test", "https://a.example.test"}
	policy.Sites[0].CORS.AllowedMethods = []string{"post", "GET"}

	first := compilePolicy(t, policy)
	policy.Sites[0].RequestHeaders[0], policy.Sites[0].RequestHeaders[1] = policy.Sites[0].RequestHeaders[1], policy.Sites[0].RequestHeaders[0]
	policy.Sites[0].RedirectAllowedHosts[0], policy.Sites[0].RedirectAllowedHosts[2] = policy.Sites[0].RedirectAllowedHosts[2], policy.Sites[0].RedirectAllowedHosts[0]
	policy.Sites[0].Redirects[0], policy.Sites[0].Redirects[1] = policy.Sites[0].Redirects[1], policy.Sites[0].Redirects[0]
	policy.Sites[0].CORS.AllowedOrigins[0], policy.Sites[0].CORS.AllowedOrigins[1] = policy.Sites[0].CORS.AllowedOrigins[1], policy.Sites[0].CORS.AllowedOrigins[0]
	second := compilePolicy(t, policy)
	if first.Digest != second.Digest || !bytes.Equal(first.Canonical, second.Canonical) {
		t.Fatal("unordered policy sets did not produce identical canonical output")
	}

	var canonical Policy
	if err := json.Unmarshal(first.Canonical, &canonical); err != nil {
		t.Fatal(err)
	}
	site := canonical.Sites[0]
	if site.RequestHeaders[0].Kind != HeaderDelete || site.RequestHeaders[0].Values == nil || len(site.RequestHeaders[0].Values) != 0 {
		t.Fatalf("delete values must remain an empty JSON array: %+v", site.RequestHeaders[0])
	}
	if site.RequestHeaders[1].Name != "x-multi" || strings.Join(site.RequestHeaders[1].Values, ",") != "edge-a,edge-b" {
		t.Fatalf("header case or value order changed: %+v", site.RequestHeaders)
	}
	if got := strings.Join(site.RedirectAllowedHosts, ","); got != "127.0.0.1:8080,[2001:db8::1]:8443,example.test" {
		t.Fatalf("authority canonicalization=%q", got)
	}
	if site.Redirects[0].RuleID != "v4" || site.Redirects[1].TargetURL != "https://[2001:db8::1]:8443/next" {
		t.Fatalf("redirect canonicalization=%+v", site.Redirects)
	}
	if got := strings.Join(site.CORS.AllowedMethods, ","); got != "GET,POST" {
		t.Fatalf("CORS methods=%q", got)
	}
}

func TestCompileJSONRejectsUnsafePolicies(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{"schema", func(value *Policy) { value.SchemaVersion = "cdnca.edge.http-policy/v2" }},
		{"version-zero", func(value *Policy) { value.PolicyVersion = 0 }},
		{"zero-upload", func(value *Policy) { value.Sites[0].MaxUploadBytes = 0 }},
		{"crlf", func(value *Policy) {
			value.Sites[0].RequestHeaders = []HeaderAction{{Kind: HeaderSet, Name: "x-test", Values: []string{"ok\r\nInjected: yes"}}}
		}},
		{"control", func(value *Policy) {
			value.Sites[0].ResponseHeaders = []HeaderAction{{Kind: HeaderSet, Name: "x-test", Values: []string{"bad\x7f"}}}
		}},
		{"hop-by-hop", func(value *Policy) {
			value.Sites[0].RequestHeaders = []HeaderAction{{Kind: HeaderSet, Name: "Connection", Values: []string{"close"}}}
		}},
		{"host", func(value *Policy) {
			value.Sites[0].RequestHeaders = []HeaderAction{{Kind: HeaderSet, Name: "Host", Values: []string{"evil.test"}}}
		}},
		{"content-length", func(value *Policy) {
			value.Sites[0].ResponseHeaders = []HeaderAction{{Kind: HeaderDelete, Name: "Content-Length", Values: []string{}}}
		}},
		{"internal-identity", func(value *Policy) {
			value.Sites[0].RequestHeaders = []HeaderAction{{Kind: HeaderSet, Name: "X-CDNCA-Tenant-ID", Values: []string{"other"}}}
		}},
		{"forwarded-identity", func(value *Policy) {
			value.Sites[0].RequestHeaders = []HeaderAction{{Kind: HeaderSet, Name: "X-Forwarded-For", Values: []string{"127.0.0.1"}}}
		}},
		{"cors-owned", func(value *Policy) {
			value.Sites[0].ResponseHeaders = []HeaderAction{{Kind: HeaderSet, Name: "Access-Control-Allow-Origin", Values: []string{"*"}}}
		}},
		{"hsts-owned", func(value *Policy) {
			value.Sites[0].ResponseHeaders = []HeaderAction{{Kind: HeaderDelete, Name: "Strict-Transport-Security", Values: []string{}}}
		}},
		{"alt-svc-owned", func(value *Policy) {
			value.Sites[0].ResponseHeaders = []HeaderAction{{Kind: HeaderSet, Name: "Alt-Svc", Values: []string{"clear"}}}
		}},
		{"cache-status-owned", func(value *Policy) {
			value.Sites[0].ResponseHeaders = []HeaderAction{{Kind: HeaderSet, Name: "X-CDN-Cache", Values: []string{"HIT"}}}
		}},
		{"cdnca-internal", func(value *Policy) {
			value.Sites[0].ResponseHeaders = []HeaderAction{{Kind: HeaderSet, Name: "X-Cdnca-Site", Values: []string{"x"}}}
		}},
		{"duplicate-case", func(value *Policy) {
			value.Sites[0].RequestHeaders = []HeaderAction{{Kind: HeaderDelete, Name: "X-One", Values: []string{}}, {Kind: HeaderDelete, Name: "x-one", Values: []string{}}}
		}},
		{"delete-value", func(value *Policy) {
			value.Sites[0].RequestHeaders = []HeaderAction{{Kind: HeaderDelete, Name: "x-one", Values: []string{"bad"}}}
		}},
		{"encoded-rewrite", func(value *Policy) { value.Sites[0].Rewrites[0].TargetPath = "/safe/%2e%2e/private" }},
		{"traversal-rewrite", func(value *Policy) { value.Sites[0].Rewrites[0].TargetPath = "/safe/../private" }},
		{"self-rewrite", func(value *Policy) { value.Sites[0].Rewrites[0].TargetPath = value.Sites[0].Rewrites[0].MatchPath }},
		{"unlisted-redirect", func(value *Policy) { value.Sites[0].Redirects[0].TargetURL = "https://evil.test/next" }},
		{"redirect-userinfo", func(value *Policy) {
			value.Sites[0].RedirectAllowedHosts = []string{"example.test"}
			value.Sites[0].Redirects[0].TargetURL = "https://user@example.test/next"
		}},
		{"redirect-query", func(value *Policy) {
			value.Sites[0].Redirects[0].TargetURL = "https://redirect.example.test/next?target=evil"
		}},
		{"cors-wildcard-credentials", func(value *Policy) {
			value.Sites[0].CORS.AllowedOrigins = []string{"*"}
			value.Sites[0].CORS.AllowCredentials = true
		}},
		{"cors-wildcard-with-origin", func(value *Policy) { value.Sites[0].CORS.AllowedOrigins = []string{"*", "https://app.example.test"} }},
		{"cors-origin-path", func(value *Policy) { value.Sites[0].CORS.AllowedOrigins = []string{"https://app.example.test/path"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy(1)
			test.mutate(&policy)
			raw, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CompileJSON(raw); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("expected ErrInvalidPolicy, got %v", err)
			}
		})
	}
}

func TestCompileJSONRejectsAmbiguousJSON(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":"cdnca.edge.http-policy/v1","schema_version":"cdnca.edge.http-policy/v1","policy_version":1,"sites":[]}`,
		`{"schema_version":"cdnca.edge.http-policy/v1","policy_version":1,"sites":[],"unknown":true}`,
		`{"schema_version":"cdnca.edge.http-policy/v1","policy_version":1}`,
		`{"schema_version":"cdnca.edge.http-policy/v1","policy_version":1,"sites":[]} {}`,
	} {
		if _, err := CompileJSON([]byte(raw)); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("ambiguous JSON accepted: %s: %v", raw, err)
		}
	}
}

func TestCompileJSONRejectsPolicySizeBounds(t *testing.T) {
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte(" "), MaxPolicyBytes+1)} {
		if _, err := CompileJSON(raw); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("policy size accepted: %d bytes: %v", len(raw), err)
		}
	}
}

func compilePolicy(t *testing.T, policy Policy) Artifact {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func validPolicy(version uint64) Policy {
	return Policy{
		SchemaVersion: SchemaVersion,
		PolicyVersion: version,
		Sites: []SitePolicy{{
			SiteID: "site-a", MaxUploadBytes: 16,
			RequestHeaders:  []HeaderAction{},
			ResponseHeaders: []HeaderAction{},
			Rewrites: []RewriteRule{{
				RuleID: "rewrite", Priority: 10, MatchKind: MatchExact,
				MatchPath: "/before", TargetPath: "/after", PreserveQuery: true, PreserveCookie: true,
			}},
			RedirectAllowedHosts: []string{"redirect.example.test"},
			Redirects: []RedirectRule{{
				RuleID: "redirect", Priority: 10, MatchKind: MatchExact, MatchPath: "/go",
				Status: 307, TargetURL: "https://redirect.example.test/next", PreserveQuery: true,
			}},
			CORS: &CORSPolicy{
				AllowedOrigins: []string{"https://app.example.test"}, AllowedMethods: []string{"GET", "POST"},
				AllowedHeaders: []string{"x-token"}, ExposedHeaders: []string{"x-result"},
				AllowCredentials: true, MaxAgeSeconds: 600,
			},
		}},
	}
}
