package cachefreshness

import (
	"bytes"
	"strings"
	"testing"
)

func TestCompileDisabledEnhancementIsBaselineByteForByte(t *testing.T) {
	baseline := validPolicy()
	baseline.Mode = ModeBaseline
	baseline.Enhancement = EnhancementPolicy{Enabled: false}

	disabled := validPolicy()
	disabled.Mode = ModeEnhancement
	disabled.Enhancement.Enabled = false

	baselineArtifact, err := Compile(baseline, testPaths())
	if err != nil {
		t.Fatalf("compile baseline: %v", err)
	}
	disabledArtifact, err := Compile(disabled, testPaths())
	if err != nil {
		t.Fatalf("compile disabled enhancement: %v", err)
	}
	if !bytes.Equal(baselineArtifact.Nginx, disabledArtifact.Nginx) {
		t.Fatal("disabled enhancement changed baseline nginx bytes")
	}
	config := string(baselineArtifact.Nginx)
	for _, variable := range []string{"cache_freshness_validator_bypass", "cache_freshness_enhancement_vary_bypass"} {
		if strings.Contains(config, variable) {
			t.Fatalf("baseline config contains enhancement-only variable %q", variable)
		}
	}
	for _, fragment := range []string{
		"map $cache_freshness_cache_reason $cache_freshness_cache_state",
		"add_header X-CDNCA-Cache-State $cache_freshness_cache_state always;",
	} {
		if !strings.Contains(config, fragment) {
			t.Errorf("baseline config missing stable cache state fragment %q", fragment)
		}
	}
}

func TestCompileEnhancementUsesNativeCacheControlsAndCompleteIdentity(t *testing.T) {
	policy := validPolicy()
	artifact, err := Compile(policy, testPaths())
	if err != nil {
		t.Fatalf("compile enhancement: %v", err)
	}
	config := string(artifact.Nginx)
	for _, fragment := range []string{
		"variables_hash_max_size 4096;",
		"variables_hash_bucket_size 128;",
		"map $cache_freshness_cache_reason $cache_freshness_cache_state",
		"init_worker_by_lua_block { require(\"guard\").init_worker() }",
		"listen 127.0.0.1:18086 default_server;",
		"server_name _; return 421;",
		"proxy_cache_lock on;",
		"proxy_cache_lock_timeout 5s;",
		"proxy_cache_lock_age 5s;",
		"lock_timeout_seconds = 5.000",
		"metadata_ttl_seconds = 360",
		"proxy_cache_background_update on;",
		"proxy_cache_use_stale updating error timeout http_500 http_502 http_503 http_504;",
		"proxy_cache_revalidate on;",
		"tenant=tenant-a|site=site-a|config=19|scheme=$scheme|host=$host|port=$server_port|method=$cache_freshness_method|request=$request_uri",
		"set $cache_freshness_generation \"\";",
		"set $cache_freshness_object_token \"\";",
		"map \"$upstream_http_etag|$upstream_http_last_modified|$upstream_http_content_length|$upstream_http_date\" $cache_freshness_validator_bypass { default 0; \"|||\" 1; }",
		"map $upstream_http_vary $cache_freshness_enhancement_vary_bypass { default 1; \"\" 0; }",
		"rewrite_by_lua_block { require(\"guard\").access(",
		"validator_bypass = ngx.var.cache_freshness_validator_bypass == \"1\"",
		"vary_bypass = ngx.var.cache_freshness_enhancement_vary_bypass == \"1\"",
		"body_filter_by_lua_block { require(\"guard\").body_filter() }",
		"proxy_cache_key \"$cache_freshness_generation|$cache_freshness_object_token|v=1|tenant=tenant-a|site=site-a|config=19|scheme=$scheme|host=$host|port=$server_port|method=$cache_freshness_method|request=$request_uri\";",
		"proxy_hide_header X-CDNCA-Cache-Reason;",
		"proxy_hide_header X-CDNCA-Cache-State;",
		"proxy_cache_bypass $cache_freshness_request_bypass $cache_freshness_hard_bypass $cache_freshness_fail_closed;",
		"proxy_no_cache $cache_freshness_request_bypass $cache_freshness_response_bypass $cache_freshness_validator_bypass $cache_freshness_enhancement_vary_bypass $cache_freshness_fail_closed;",
		"proxy_cache_valid 200 30s;",
	} {
		if !strings.Contains(config, fragment) {
			t.Errorf("compiled config missing %q", fragment)
		}
	}
	if strings.Count(config, "proxy_pass http://cache_freshness_origin;") != 1 {
		t.Fatal("origin proxy must exist only in the declared-host server")
	}
	for _, forbidden := range []string{"http_403", "http_404", "http_429", "proxy_cache_valid any", "$http_authorization|", "$http_cookie|"} {
		if strings.Contains(config, forbidden) {
			t.Errorf("compiled config contains forbidden fragment %q", forbidden)
		}
	}
	if strings.Contains(config, "access_by_lua_block") {
		t.Fatal("cache generation must be fixed before the access phase")
	}
}

func TestCompileHostSinkPreservesIPv6ListenerSyntax(t *testing.T) {
	policy := validPolicy()
	policy.ListenAddress = "::1"
	artifact, err := Compile(policy, testPaths())
	if err != nil {
		t.Fatalf("compile IPv6 listener: %v", err)
	}
	config := string(artifact.Nginx)
	if strings.Count(config, "listen [::1]:18086") != 2 || !strings.Contains(config, "listen [::1]:18086 default_server;") {
		t.Fatalf("compiled IPv6 listener does not preserve sink and declared-host servers:\n%s", config)
	}
}

func TestCompileRejectsInvalidPolicyWithoutPartialArtifact(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{"zero stale window", func(policy *Policy) { policy.Enhancement.StaleWindowSeconds = 0 }},
		{"stale above hard cap", func(policy *Policy) { policy.Enhancement.StaleWindowSeconds = MaxStaleSeconds + 1 }},
		{"lock timeout below floor", func(policy *Policy) {
			policy.Enhancement.Expert.LockTimeoutMilliseconds = MinLockTimeoutMilliseconds - 1
		}},
		{"lock age above cap", func(policy *Policy) { policy.Enhancement.Expert.LockAgeMilliseconds = MaxLockAgeMilliseconds + 1 }},
		{"unsafe stale class", func(policy *Policy) { policy.Enhancement.Expert.FailureClasses = []FailureClass{"http_404"} }},
		{"unsafe identifier", func(policy *Policy) { policy.TenantID = "tenant|escape" }},
		{"invalid cache status", func(policy *Policy) { policy.CacheableStatuses = []uint16{200, 206} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy()
			test.mutate(&policy)
			artifact, err := Compile(policy, testPaths())
			if err == nil {
				t.Fatal("invalid policy compiled")
			}
			if len(artifact.Nginx) != 0 || len(artifact.CanonicalPolicy) != 0 {
				t.Fatal("invalid policy returned a partial artifact")
			}
		})
	}
}

func TestCompileIsDeterministic(t *testing.T) {
	first := validPolicy()
	first.Hosts = []string{"B.example.test", "a.example.test"}
	first.Enhancement.Expert.FailureClasses = []FailureClass{"http_504", "error", "timeout", "http_500"}
	second := first
	second.Hosts = []string{"a.example.test", "b.example.test"}
	second.Enhancement.Expert = &ExpertPolicy{
		LockTimeoutMilliseconds: 5000,
		LockAgeMilliseconds:     5000,
		BackgroundUpdate:        boolPointer(true),
		Revalidation:            boolPointer(true),
		FailureClasses:          []FailureClass{"http_500", "timeout", "error", "http_504"},
	}

	left, err := Compile(first, testPaths())
	if err != nil {
		t.Fatalf("compile first policy: %v", err)
	}
	right, err := Compile(second, testPaths())
	if err != nil {
		t.Fatalf("compile second policy: %v", err)
	}
	if !bytes.Equal(left.CanonicalPolicy, right.CanonicalPolicy) || !bytes.Equal(left.Nginx, right.Nginx) || left.Digest != right.Digest {
		t.Fatal("equivalent policies did not compile deterministically")
	}
}

func validPolicy() Policy {
	return Policy{
		SchemaVersion:        SchemaVersion,
		PolicyVersion:        7,
		ConfigurationVersion: 19,
		TenantID:             "tenant-a",
		SiteID:               "site-a",
		Mode:                 ModeEnhancement,
		ListenAddress:        "127.0.0.1",
		ListenPort:           18086,
		Hosts:                []string{"cache.example.test"},
		OriginHost:           "origin.example.test",
		OriginPort:           8080,
		CacheMaxBytes:        128 << 20,
		CacheInactiveSeconds: 300,
		FreshSeconds:         30,
		CacheableStatuses:    []uint16{200},
		Enhancement: EnhancementPolicy{
			Enabled:            true,
			StaleWindowSeconds: 60,
			Expert: &ExpertPolicy{
				LockTimeoutMilliseconds: 5000,
				LockAgeMilliseconds:     5000,
				BackgroundUpdate:        boolPointer(true),
				Revalidation:            boolPointer(true),
				FailureClasses:          []FailureClass{"updating", "error", "timeout", "http_500", "http_502", "http_503", "http_504"},
			},
		},
	}
}

func testPaths() RuntimePaths {
	return RuntimePaths{StateRoot: "/var/lib/cdnca-cache-freshness", LuaRoot: "/opt/cdnca-cache-freshness"}
}

func boolPointer(value bool) *bool { return &value }
