package systemconfig

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func intOverride(value int) *int { return &value }

// 全局 → 区域 → 节点, region overrides by the catalog
// display ID the node's region maps to.
func TestEdgeNodeNginxSettingsPriority(t *testing.T) {
	configuration := ProjectBootstrapConfiguration()
	version, off := "1.0", false
	gzipTypes := []string{"text/css"}
	configuration.Nginx.Overrides = []ScopedNginxOverride{
		{ID: "region-east", Scope: ConfigurationScopeRegion, ScopeID: "12", Values: NginxOverride{
			Worker: &NginxWorkerOverride{WorkerConnections: intOverride(8192)},
			HTTP:   &NginxHTTPOverride{GzipLevel: intOverride(9), ProxyHTTPVersion: &version}}},
		{ID: "node-a0001", Scope: ConfigurationScopeNode, ScopeID: "00000000-0000-4000-8000-0000000000a1", Values: NginxOverride{
			HTTP: &NginxHTTPOverride{GzipLevel: intOverride(2), ProxyRequestBuffering: &off}}},
	}
	configuration.Defaults.Overrides = []ScopedDefaultOverride{{ID: "default-east", Scope: ConfigurationScopeRegion, ScopeID: "12",
		Values: DefaultOverrides{Website: &DefaultWebsiteOverride{Other: &DefaultWebsiteOtherSettings{
			LoadBalancing: "round_robin", GzipEnabled: true, GzipTypes: gzipTypes}}}}}
	normalized, _, _, err := CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	nodeA := uuid.MustParse("00000000-0000-4000-8000-0000000000a1") // region 12 + node override
	nodeB := uuid.MustParse("00000000-0000-4000-8000-0000000000b2") // region 12
	nodeC := uuid.MustParse("00000000-0000-4000-8000-0000000000c3") // other region
	settings, err := EdgeNodeNginxSettings(normalized, []EdgeNodeTarget{
		{NodeID: nodeA, RegionID: "12"}, {NodeID: nodeB, RegionID: "12"}, {NodeID: nodeC, RegionID: "7"}})
	if err != nil {
		t.Fatal(err)
	}
	global := EdgeNginxSettings(normalized)
	a, b, c := settings[nodeA.String()], settings[nodeB.String()], settings[nodeC.String()]
	// node beats region, region beats global; keys the node does not set keep the region's
	if a.GzipLevel != 2 || !a.ProxyRequestBufferingDisabled || a.WorkerConnections != 8192 || a.ProxyHTTPVersion != "1.0" {
		t.Fatalf("node A = %+v", a)
	}
	if b.GzipLevel != 9 || b.ProxyRequestBufferingDisabled || b.WorkerConnections != 8192 || b.ProxyHTTPVersion != "1.0" {
		t.Fatalf("node B = %+v", b)
	}
	if !reflect.DeepEqual(c, global) {
		t.Fatalf("node outside the region = %+v, want global %+v", c, global)
	}
	// the region's website defaults (gzip types) reach its nodes too
	if strings.Join(b.GzipTypes, ",") != "text/css" || strings.Join(global.GzipTypes, ",") == "text/css" {
		t.Fatalf("defaults override: region %v, global %v", b.GzipTypes, global.GzipTypes)
	}
	// they build one per-node block: the outside node is the base
	system, err := edgeconfig.NewSiteRuntimeSystem("00000000-0000-4000-8000-000000000001", 3, strings.Repeat("a", 64), global)
	if err != nil {
		t.Fatal(err)
	}
	withNodes, err := system.WithNodeNginx(settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(withNodes.NodeNginx) != 2 || withNodes.ForNode(nodeC.String()).Nginx.GzipLevel != global.GzipLevel ||
		withNodes.ForNode(nodeA.String()).Nginx.GzipLevel != 2 || withNodes.ForNode(nodeB.String()).Nginx.GzipLevel != 9 {
		t.Fatalf("node groups = %+v", withNodes.NodeNginx)
	}
	none, err := EdgeNodeNginxSettings(ProjectBootstrapConfiguration(), []EdgeNodeTarget{{NodeID: nodeA, RegionID: "12"}})
	if err != nil || len(none) != 0 {
		t.Fatalf("no overrides = %v, %v", none, err)
	}
}

// The nine fields that were saved but not projected (fix/nginx-region.md 需后端 2).
func TestEdgeNginxSettingsProjectsAllFields(t *testing.T) {
	configuration := ProjectBootstrapConfiguration()
	value := &configuration.Nginx
	value.GzipHTTPVersion, value.ServerAddrOutgoing, value.ProxyRequestBuffering = "1.0", true, false
	value.ProxyHTTPVersion, value.ProxyNextUpstream = "1.0", []string{"error", "http_503"}
	value.LargeClientHeaderBuffers = LargeClientHeaderBuffers{Count: 8, SizeBytes: 32 << 10}
	value.ServerNamesHashBucketSize, value.ClientBodyBufferSizeBytes = 256, 64<<10
	settings := EdgeNginxSettings(configuration)
	if settings.GzipHTTPVersion != "1.0" || !settings.ServerAddrOutgoing || !settings.ProxyRequestBufferingDisabled ||
		settings.ProxyHTTPVersion != "1.0" || strings.Join(settings.ProxyNextUpstream, " ") != "error http_503" ||
		settings.LargeClientHeaderBufferCount != 8 || settings.LargeClientHeaderBufferBytes != 32<<10 ||
		settings.ServerNamesHashBucketSize != 256 || settings.ClientBodyBufferBytes != 64<<10 {
		t.Fatalf("projection = %+v", settings)
	}
	// every bootstrap value is a valid edge document
	if _, err := edgeconfig.NewSiteRuntimeSystem("00000000-0000-4000-8000-000000000001", 1, strings.Repeat("a", 64),
		EdgeNginxSettings(ProjectBootstrapConfiguration())); err != nil {
		t.Fatalf("bootstrap projection rejected: %v", err)
	}
}
