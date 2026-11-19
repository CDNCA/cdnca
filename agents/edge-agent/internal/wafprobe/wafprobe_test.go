package wafprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// TestContextParses: the probe's transaction ID is a valid c3 context of
// its own site that is never audited.
func TestContextParses(t *testing.T) {
	text := context3()
	parsed, ok := edgeconfig.ParseDynamicWAFContext(text)
	if !ok || parsed.SiteID != probeSite || strings.HasSuffix(text, edgeconfig.DynamicWAFSampleDigit) {
		t.Fatalf("context %q parsed %v", text, ok)
	}
}

// TestRenderConfig: one worker, no daemon, a unix socket in the scratch
// directory, /a on the tier file and /b on the bucket file.
func TestRenderConfig(t *testing.T) {
	cfg := Config{Dir: "/var/lib/cdnca/wafprobe", Probe: &dynwaf.Probe{Engine: dynwaf.Engine{ModulePath: "/m.so", UnicodeMapPath: "/u.map"},
		RulesPath: "/w/main.conf", TierFile: "/w/tiers/t.conf"}}
	conf := renderConfig(cfg, "/var/lib/cdnca/wafprobe/bucket.conf")
	for _, want := range []string{"daemon off;", "master_process off;", "worker_processes 1;", "load_module /m.so;",
		"listen unix:/var/lib/cdnca/wafprobe/probe.sock;", "modsecurity_rules_file /w/main.conf;",
		"location ^~ /a/ {\n      modsecurity on;\n      modsecurity_rules_file /w/tiers/t.conf;",
		"location ^~ /b/ {\n      modsecurity on;\n      modsecurity_rules_file /var/lib/cdnca/wafprobe/bucket.conf;",
		"modsecurity_transaction_id \"" + context3() + "\";"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in\n%s", want, conf)
		}
	}
}

func TestMedian(t *testing.T) {
	if median([]int64{5, -3, 9, 1, 7}) != 5 || median([]int64{4}) != 4 || quantile([]int64{1, 2, 3, 4, 5, 6, 7}, 0.75) != 6 {
		t.Fatal("median")
	}
}

// TestMeasureEarlyExit: an OpenResty that exits at once
// (Ubuntu 24.04 node: getgrnam("nobody") failed) fails the self test at once
// with its stderr in the error, not after the 15 s readiness wait with an
// empty error.log; the native worker user goes in with -g and early errors
// go to stderr (-e stderr), not to the prefix's missing logs/error.log.
func TestMeasureEarlyExit(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "openresty")
	script := "#!/bin/sh\necho \"args: $*\" >&2\necho 'nginx: [emerg] getgrnam(\"nobody\") failed' >&2\nexit 1\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	probe := testProbe(t)
	started := time.Now()
	_, err := Measure(context.Background(), Config{OpenResty: fake, Dir: filepath.Join(dir, "probe"), Probe: probe,
		Globals: "user cdnca-runtime cdnca-runtime;"})
	if err == nil {
		t.Fatal("Measure succeeded on an exited OpenResty")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Errorf("Measure took %s on an OpenResty that exited at once", elapsed)
	}
	for _, want := range []string{`getgrnam("nobody") failed`, "-e stderr", "-g user cdnca-runtime cdnca-runtime;"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

// testProbe is the self test input of one 严格防护 (system/crs-pl2) site, as
// dynwaf.Prepare gives it on a node (the signed catalog's CRS text and
// libs/rulepack's system profile packs).
func testProbe(t *testing.T) *dynwaf.Probe {
	t.Helper()
	files, err := rulecatalog.DecodeWAFEngineBundle(*rulecatalog.CRSRulesBundle())
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile("../../../../libs/rulepack/testdata/crs-profiles/crs-pl2.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	_, profile, err := rulepack.LoadCRSProfile(content, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	result, err := dynwaf.Prepare(dynwaf.Input{CRSText: &edgeconfig.CRSRuleText{Version: rulecatalog.CRSRulesBundle().Version, Files: files},
		Profiles: map[string]edgeconfig.CRSProfile{profile.Ref.SHA256: profile}, Root: t.TempDir(),
		Engine: &dynwaf.Engine{ModulePath: "/m.so", UnicodeMapPath: "/u.map"}, AuditLog: "/var/lib/node/shared/audit.log",
		Sites: []edgesite.Site{{SiteID: probeSite, Security: edgesite.Security{ManagedWAF: &edgesite.ManagedWAF{
			PolicyID: "0d110000-0000-4000-8000-000000000001", PolicyVersion: 1,
			Profile: edgesite.ManagedWAFProfile{RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 131072,
				RequestBodyLimitAction: "reject", ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000,
				InspectionLimitAction: "log"},
			CRSProfile: profile.Ref, Exclusions: []int{}, AllowCIDRs: []string{}}}}}})
	if err != nil || result.Probe == nil {
		t.Fatalf("prepare: %v, probe %v", err, result.Probe)
	}
	return result.Probe
}
