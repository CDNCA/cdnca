package edgeconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

func TestCacheFreshnessFollowOriginHeadersDefaultsFalse(t *testing.T) {
	policy := followOriginTestPolicy()
	canonical, err := CanonicalCacheFreshnessPolicy(policy)
	if err != nil {
		t.Fatalf("canonical default policy: %v", err)
	}
	if bytes.Contains(canonical, []byte(`"follow_origin_headers"`)) {
		t.Fatalf("default policy changed canonical bytes: %s", canonical)
	}

	decoded, err := DecodeCacheFreshnessPolicy(canonical)
	if err != nil {
		t.Fatalf("decode default policy: %v", err)
	}
	if decoded.FollowOriginHeaders {
		t.Fatal("missing follow_origin_headers did not default to false")
	}
}

func TestCacheFreshnessFollowOriginHeadersIsCanonical(t *testing.T) {
	policy := followOriginTestPolicy()
	policy.FollowOriginHeaders = true
	canonical, err := CanonicalCacheFreshnessPolicy(policy)
	if err != nil {
		t.Fatalf("canonical follow-origin policy: %v", err)
	}
	if !bytes.Contains(canonical, []byte(`"follow_origin_headers":true`)) {
		t.Fatalf("canonical policy omitted follow_origin_headers: %s", canonical)
	}

	decoded, err := DecodeCacheFreshnessPolicy(canonical)
	if err != nil {
		t.Fatalf("decode follow-origin policy: %v", err)
	}
	if !decoded.FollowOriginHeaders {
		t.Fatal("follow_origin_headers was not preserved")
	}
}

func TestCacheFreshnessEmbeddedGuardMatchesStandaloneRuntime(t *testing.T) {
	standalone, err := os.ReadFile("../../edge/openresty/cachefreshness/guard.lua")
	if err != nil {
		t.Fatalf("read standalone guard: %v", err)
	}
	embedded := CacheFreshnessGuard()
	if !bytes.Equal(embedded, standalone) {
		t.Fatal("embedded cache freshness guard differs from the smoke-tested standalone runtime")
	}
	digest := sha256.Sum256(embedded)
	if got := hex.EncodeToString(digest[:]); got != CacheFreshnessGuardSHA256 {
		t.Fatalf("embedded guard digest = %s, want %s", got, CacheFreshnessGuardSHA256)
	}
}

func followOriginTestPolicy() CacheFreshnessPolicy {
	return CacheFreshnessPolicy{
		SchemaVersion: CacheFreshnessSchemaVersion, PolicyVersion: 1, ConfigurationVersion: 1,
		TenantID: "tenant-a", SiteID: "site-a", Mode: CacheFreshnessModeBaseline,
		ListenAddress: "127.0.0.1", ListenPort: 18086, Hosts: []string{"cache.example.test"},
		OriginHost: "origin.example.test", OriginPort: 8080, CacheMaxBytes: 64 << 20,
		CacheInactiveSeconds: 300, FreshSeconds: 30, CacheableStatuses: []uint16{200},
	}
}
