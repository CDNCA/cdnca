package dynroute

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// fz-x12: the node's region is the control plane's (Input.NodeRegion, from
// the key document), not a node setting: it picks the region node page and
// is what the skeleton hands cdnca_site / cdnca_origin; Config.Node.Region
// is ignored, and the region survives a restart (state.json).
func TestNodeRegionComesFromTheInput(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "nrg") // short: the control socket path has a length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	runtime, err := New(Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, "shared"),
		LuaRoot: root, OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: -1, CacheMaxBytes: 10 << 30})
	if err != nil {
		t.Fatal(err)
	}
	runtime.config.Node.Region = "local-setting" // never used
	runtime.region = "region-7"
	pages := []NodePage{
		{Category: "node_ip_access", Status: 403, MIMEType: "text/html", Body: []byte("global")},
		{Category: "node_ip_access", Status: 403, MIMEType: "text/html", Body: []byte("region"), Region: "region-7"},
		{Category: "http_403", Status: 403, MIMEType: "text/html", Body: []byte("local"), Region: "local-setting"},
	}
	records, err := runtime.writeNodePages(pages)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Category != "node_ip_access" {
		t.Fatalf("records = %+v", records)
	}
	body, err := os.ReadFile(runtime.nodePageRoot() + "/" + records[0].SHA256)
	if err != nil || string(body) != "region" {
		t.Fatalf("picked %q, %v", body, err)
	}
	conf, err := runtime.render([]edgesite.Site{testSite(testScopeA, testSiteA, 80)}, dynwaf.Result{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), `node_region = "region-7",`) || strings.Contains(string(conf), "local-setting") {
		t.Fatal("skeleton does not carry the control plane's region")
	}

	// No region from the control plane: the region page drops.
	runtime.region = ""
	if records, err = runtime.writeNodePages(pages); err != nil || len(records) != 1 {
		t.Fatalf("records = %+v, %v", records, err)
	}
	if body, _ := os.ReadFile(runtime.nodePageRoot() + "/" + records[0].SHA256); string(body) != "global" {
		t.Fatalf("picked %q without a region", body)
	}

	// A malformed region is refused before anything is written.
	if _, err := runtime.Apply(context.Background(), Input{NodeRegion: "华东"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-code region: %v", err)
	}

	// The persisted region is the runtime's after a restart.
	runtime.state.NodeRegion = "region-7"
	if err := runtime.saveState(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(runtime.config)
	if err != nil || restarted.region != "region-7" {
		t.Fatalf("restarted region %q, %v", restarted.region, err)
	}
	raw, _ := os.ReadFile(runtime.statePath())
	var state map[string]any
	if json.Unmarshal(raw, &state) != nil || state["node_region"] != "region-7" {
		t.Fatalf("state.json = %s", raw)
	}
}
