package wafprobe

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/libs/edgeconfig"
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
