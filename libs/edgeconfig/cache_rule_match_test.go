package edgeconfig

import (
	"strings"
	"testing"
)

func TestValidateCachePathRegex(t *testing.T) {
	for _, value := range []string{
		`^/static/.+\.(?:css|js)$`, `^/img/[0-9]{1,6}/`, `(?i)^/Download/`, `^/a(b|c)d$`, `/v[0-9]+/assets/`,
		`^/(?:[a-z]+/)?file$`, `^/x{2,100}$`,
	} {
		if err := ValidateCachePathRegex(value); err != nil {
			t.Errorf("%q refused: %v", value, err)
		}
	}
	for _, value := range []string{
		"", strings.Repeat("a", MaxCachePathRegexBytes+1), `(a+)+$`, `(?:a*b*)*c`, `(.*a){3,}`, `^/(\w+\s?)*$`,
		`a{101}`, `a{1,200}`, `\C`, `\Qx\E`, `(?U)a+`, `(?P<n>a)`, `(?<n>a)`, `[`, `a\z`, "a\x00b", "a\nb",
	} {
		if err := ValidateCachePathRegex(value); err == nil {
			t.Errorf("%q accepted", value)
		}
	}
}

func TestCacheContentTypes(t *testing.T) {
	normalized, err := NormalizeCacheContentTypes([]string{" Text/HTML ", "image/*", "application/vnd.*"})
	if err != nil || strings.Join(normalized, ",") != "application/vnd.*,image/*,text/html" {
		t.Fatalf("normalized = %v, %v", normalized, err)
	}
	for _, bad := range [][]string{{}, {"text"}, {"text/"}, {"/html"}, {"text/html", "TEXT/HTML"}, {"text/html; charset=utf-8"},
		{"a b/c"}, make([]string, MaxCacheContentTypes+1)} {
		if _, err := NormalizeCacheContentTypes(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, test := range []struct {
		header string
		types  []string
		want   bool
	}{
		{"text/html; charset=UTF-8", []string{"text/html"}, true},
		{"TEXT/HTML", []string{"text/html"}, true},
		{"text/htmlx", []string{"text/html"}, false},
		{"image/png", []string{"image/*"}, true},
		{"application/vnd.api+json", []string{"application/vnd.*"}, true},
		{"", []string{"*"}, false},
		{"", nil, true},
		{"application/json", []string{"image/*", "text/*"}, false},
	} {
		if got := CacheContentTypeMatches(test.types, CacheMediaType(test.header)); got != test.want {
			t.Errorf("%q %v = %v", test.header, test.types, got)
		}
	}
}

func TestCachePolicyDocumentRuleMatch(t *testing.T) {
	policy := func(rules ...CacheRuleDocument) CachePolicyDocument {
		for index := range rules {
			rules[index].Order = index + 1
			if rules[index].Action == "" {
				rules[index].Action, rules[index].TTLSeconds = CacheRuleActionCache, 60
			}
		}
		return CachePolicyDocument{SchemaVersion: CachePolicyDocumentSchemaV2, Revision: 1, Mode: CacheOverride,
			Rules: rules, QueryMode: CacheQueryPreserve, DiskQuotaBytes: 64 << 20}
	}
	valid := policy(CacheRuleDocument{PathRegex: `^/a/[0-9]+$`}, CacheRuleDocument{ContentTypes: []string{"image/*"}})
	if err := validateCachePolicyDocument(valid); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if !CachePolicyUsesRuleMatch(valid) || !cachePolicyExtended(valid) {
		t.Fatal("rule match not reported")
	}
	if _, err := CachePolicyFromDocument(valid); err != nil {
		t.Fatalf("runtime policy: %v", err)
	}
	v1 := valid
	v1.SchemaVersion = 0
	v1.Rules = []CacheRuleDocument{{Order: 1, PathRegex: `^/a`, TTLSeconds: 60}, {Order: 2, ContentTypes: []string{"image/*"}, TTLSeconds: 60}}
	if err := validateCachePolicyDocument(v1); err != nil {
		t.Fatalf("schema v1 rule conditions refused: %v", err)
	}
	for _, bad := range []CachePolicyDocument{
		policy(CacheRuleDocument{PathRegex: `(a+)+`}),
		policy(CacheRuleDocument{ContentTypes: []string{"text/html", "image/*"}}), // unsorted
		policy(CacheRuleDocument{ContentTypes: []string{}}),
	} {
		if validateCachePolicyDocument(bad) == nil {
			t.Errorf("accepted %+v", bad.Rules)
		}
	}
	many := make([]CacheRuleDocument, MaxCacheConditionalRules+1)
	for index := range many {
		many[index].PathRegex = `^/x`
	}
	if validateCachePolicyDocument(policy(many...)) == nil {
		t.Fatal("more than MaxCacheConditionalRules conditional rules accepted")
	}
	before := CacheGeneration("example.com", false, valid)
	changed := valid
	changed.Rules = append([]CacheRuleDocument(nil), valid.Rules...)
	changed.Rules[0].PathRegex = `^/b/[0-9]+$`
	if CacheGeneration("example.com", false, changed) == before {
		t.Fatal("path_regex does not change the cache generation")
	}
}
