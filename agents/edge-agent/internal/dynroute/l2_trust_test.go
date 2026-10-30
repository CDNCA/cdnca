package dynroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// fix-l2trust: the running system's node networks (merged over the scopes by
// selectSystem) are rendered into the skeleton's configure call, also with
// every DDoS limit off.
func TestRenderCarriesNodeNetworks(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "l2t")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	runtime, err := New(Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, "shared"),
		LuaRoot: root, OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: -1})
	if err != nil {
		t.Fatal(err)
	}
	// every DDoS limit off: the block still carries the node networks
	system := testSystem(t, 1, edgeconfig.CCKernelBanOff, "203.0.113.9/32", "198.51.100.0/30")
	off, err := edgeconfig.NewSiteRuntimeDDoS(edgeconfig.DDoSProtection{AllowNetworks: []string{}, CCKernelBan: edgeconfig.CCKernelBanOff},
		system.DDoS.NodeNetworks)
	if err != nil {
		t.Fatal(err)
	}
	system.DDoS = &off
	conf, err := runtime.render([]edgesite.Site{testSite(testScopeA, testSiteA, 80)}, dynwaf.Result{}, system, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := `node_networks = { "198.51.100.0/30", "203.0.113.9/32" },`; !strings.Contains(string(conf), want) {
		t.Fatalf("skeleton lacks %s", want)
	}
}
