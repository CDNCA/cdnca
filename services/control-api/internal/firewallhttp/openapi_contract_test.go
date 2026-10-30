package firewallhttp

import (
	"os"
	"strings"
	"testing"
)

func TestGlobalFirewallOpenAPIContract(t *testing.T) {
	content, err := os.ReadFile("../../../../api/control-firewall.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, fragment := range []string{
		"/v1/firewall/policy:", "/v1/firewall/policy/recover:", "/v1/firewall/hits:",
		"firewall.read", "firewall.manage", "Idempotency-Key", "If-Match", "ETag",
		"protocol:", "port_start:", "port_end:", "site_ids:", "deployment_state:",
		"active_revision:", "active_sha256:", "next_cursor:", "request_id:",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("OpenAPI missing %q", fragment)
		}
	}
}
