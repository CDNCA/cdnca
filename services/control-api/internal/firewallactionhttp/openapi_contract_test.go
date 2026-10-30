package firewallactionhttp

import (
	"os"
	"strings"
	"testing"
)

func TestFirewallActionOpenAPIContract(t *testing.T) {
	content, err := os.ReadFile("../../../../api/control-firewall-actions.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"/v1/firewall-actions/policy:", "/v1/firewall-actions/policy/recover:", "firewall.read", "firewall.manage",
		"Idempotency-Key", "If-Match", "ETag", "normal_action", "escalated_action", "nftables", "disconnect", "return_page",
		"engage_threshold", "recover_threshold", "recovery_windows", "trusted_proxies", "trusted_crawlers", "lkg_revision",
	} {
		if !strings.Contains(string(content), fragment) {
			t.Errorf("OpenAPI missing %q", fragment)
		}
	}
}
