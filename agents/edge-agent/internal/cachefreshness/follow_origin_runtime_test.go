package cachefreshness

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCompileFollowOriginDisabledRuntimeGolden(t *testing.T) {
	artifact, err := Compile(validPolicy(), testPaths())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got, want := fmt.Sprintf("%x", sha256.Sum256(artifact.Nginx)), "7f4691bad5c30b5cb98d340d9b98c965bc12f0f67c2ee8a06d7c6939bf3e5992"; got != want {
		t.Fatalf("disabled runtime SHA-256 = %s, want %s", got, want)
	}
}

func TestCompileFollowOriginEnhancementWiresStrictHeaderFacts(t *testing.T) {
	policy := validPolicy()
	policy.FollowOriginHeaders = true
	artifact, err := Compile(policy, testPaths())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	config := string(artifact.Nginx)
	for _, fragment := range []string{
		"access({ identity = ngx.var.cache_freshness_identity, request_bypass = ngx.var.cache_freshness_request_bypass == \"1\", follow_origin_headers = true,",
		"header_filter({ identity = ngx.var.cache_freshness_identity, response_bypass = ngx.var.cache_freshness_response_bypass == \"1\", validator_bypass = ngx.var.cache_freshness_validator_bypass == \"1\", vary_bypass = ngx.var.cache_freshness_enhancement_vary_bypass == \"1\", follow_origin_headers = true,",
		"map $upstream_http_vary $cache_freshness_enhancement_vary_bypass { default 0; ~*^\\s*\\*\\s*$ 1; }",
	} {
		if !strings.Contains(config, fragment) {
			t.Errorf("follow-origin enhancement config missing %q", fragment)
		}
	}
	if strings.Contains(config, "map $upstream_http_vary $cache_freshness_enhancement_vary_bypass { default 1; \"\" 0; }") {
		t.Fatal("follow-origin enhancement still rejects every Vary name")
	}
	for _, name := range []string{"Reason", "State", "Policy", "Status"} {
		if !strings.Contains(config, "proxy_hide_header X-CDNCA-Cache-"+name+";") {
			t.Errorf("origin can expose forged internal %s header", name)
		}
	}
}

func TestCompileFollowOriginBaselineUsesFailClosedHeaderFilter(t *testing.T) {
	policy := validPolicy()
	policy.Mode = ModeBaseline
	policy.Enhancement = EnhancementPolicy{Enabled: false}
	policy.FollowOriginHeaders = true
	artifact, err := Compile(policy, testPaths())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	config := string(artifact.Nginx)
	for _, fragment := range []string{
		"set $cache_freshness_fail_closed 0;",
		"header_filter_by_lua_block { require(\"guard\").origin_header_filter({ follow_origin_headers = true }) }",
		"proxy_no_cache $cache_freshness_request_bypass $cache_freshness_response_bypass $cache_freshness_fail_closed;",
	} {
		if !strings.Contains(config, fragment) {
			t.Errorf("follow-origin baseline config missing %q", fragment)
		}
	}
}

func TestFollowOriginGuardHasStrictRawHeaderRuntime(t *testing.T) {
	raw, err := os.ReadFile("../../../../edge/openresty/cachefreshness/guard.lua")
	if err != nil {
		t.Fatalf("read guard.lua: %v", err)
	}
	source := string(raw)
	for _, fragment := range []string{
		`local freshness_prefix = "freshness:"`,
		"ngx.resp.get_headers",
		"ngx.parse_http_time",
		"local function parse_origin_freshness",
		"function _M.origin_header_filter",
		"options.follow_origin_headers",
	} {
		if !strings.Contains(source, fragment) {
			t.Errorf("guard runtime missing %q", fragment)
		}
	}
}
