package edgeskeleton

import (
	"strings"
	"testing"
)

// fix-l2trust: the node networks reach cdnca_dynroute.configure (an L2 node
// trusts an L1's hop only from them) and the trusted hop variable is
// declared (it survives ngx.exec into cache variants).
func TestRenderNodeNetworksAndL2TrustVariable(t *testing.T) {
	input := testInput()
	input.NodeNetworks = []string{"198.51.100.7/32", "2001:db8::7/128"}
	config := render(t, input)
	for _, want := range []string{
		`node_networks = { "198.51.100.7/32", "2001:db8::7/128" },`,
		"set $" + L2TrustedVariable + " \"\";",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("config lacks %q", want)
		}
	}
	if config := render(t, testInput()); !strings.Contains(config, "node_networks = {  },") {
		t.Fatal("no node networks must render an empty list")
	}
}
