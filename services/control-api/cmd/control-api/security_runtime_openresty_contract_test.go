package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestSecurityRuntimeOpenRestyImageCopiesAndVerifiesExactLuaAssets(t *testing.T) {
	dockerfile, err := os.ReadFile("../../../../edge/openresty/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	text := string(dockerfile)
	assets := []struct {
		source      string
		destination string
	}{
		{"edge/openresty/lua/cdnca_waf.lua", "/usr/local/share/cdnca/security/cdnca_waf.lua"},
		{"edge/openresty/ccv2/engine.lua", "/usr/local/share/cdnca/security/cc.lua"},
		{"edge/openresty/ccadaptive/engine.lua", "/usr/local/share/cdnca/security/cc_adaptive.lua"},
	}
	for _, asset := range assets {
		raw, err := os.ReadFile("../../../../" + asset.source)
		if err != nil {
			t.Fatal(err)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(raw))
		for _, required := range []string{
			"COPY --chmod=0444 " + asset.source + " " + asset.destination,
			digest + "  " + asset.destination,
		} {
			if !strings.Contains(text, required) {
				t.Errorf("OpenResty Dockerfile missing %q", required)
			}
		}
	}
	waf, err := os.ReadFile("../../../../edge/openresty/lua/cdnca_waf.lua")
	if err != nil {
		t.Fatal(err)
	}
	entrypoint, err := os.ReadFile("../../../../edge/openresty/entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	wafPin := fmt.Sprintf(`waf_sha256="%x"`, sha256.Sum256(waf))
	if !strings.Contains(string(entrypoint), wafPin) {
		t.Errorf("OpenResty entrypoint missing exact WAF pin %q", wafPin)
	}
	cc, err := os.ReadFile("../../../../edge/openresty/ccv2/engine.lua")
	if err != nil {
		t.Fatal(err)
	}
	ccDigest := fmt.Sprintf("%x", sha256.Sum256(cc))
	if count := strings.Count(text, ccDigest); count != 2 {
		t.Errorf("OpenResty Dockerfile CC digest count = %d, want 2 for %q", count, ccDigest)
	}
	ccEntrypointPin := fmt.Sprintf(`cc_sha256="%s"`, ccDigest)
	if count := strings.Count(string(entrypoint), ccEntrypointPin); count != 1 {
		t.Errorf("OpenResty entrypoint CC pin count = %d, want 1 for %q", count, ccEntrypointPin)
	}
	for _, required := range []string{
		"CDNCA_SECURITY_RUNTIME_READY_FILE",
		"sha256sum -c",
		"HEALTHCHECK",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("OpenResty Dockerfile missing truthful security readiness contract %q", required)
		}
	}
}
