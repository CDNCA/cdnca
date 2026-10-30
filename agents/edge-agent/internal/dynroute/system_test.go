package dynroute

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

const (
	testPlatform = "0d13c000-0000-4000-8000-000000000001"
	testScopeA   = "0d13c000-0000-4000-8000-0000000000a1"
	testScopeB   = "0d13c000-0000-4000-8000-0000000000b1"
	testSiteA    = "0d13c000-0000-4000-8000-00000000a001"
	testSiteB    = "0d13c000-0000-4000-8000-00000000b001"
)

func testSystem(t *testing.T, revision int64, mode string, networks ...string) *edgeconfig.SiteRuntimeSystem {
	t.Helper()
	system, err := edgeconfig.NewSiteRuntimeSystem(testPlatform, revision, strings.Repeat(string(rune('a'+revision)), 64),
		edgeconfig.NginxSettings{WorkerProcesses: 2, WorkerRlimitNoFile: 65535, WorkerShutdownTimeout: 30 * time.Second,
			WorkerConnections: 20000, ResolverAddresses: []string{"1.1.1.1"}, ResolverTimeout: 5 * time.Second, GzipLevel: 5,
			GzipMinimumBytes: 1024, ProxyCacheMethods: []string{"GET", "HEAD"}, ProxyCacheMaxBytes: 1 << 30,
			ProxyCacheZoneBytes: 64 << 20, ProxyMaxTempFileBytes: 1 << 20, ProxyConnectTimeout: 10 * time.Second,
			ProxySendTimeout: 60 * time.Second, ProxyReadTimeout: 60 * time.Second, StreamProxyTimeout: 10 * time.Minute,
			ServerHeader: "cdnca", ClientMaxBodyBytes: 100 << 20, DefaultMIMEType: "text/html", KeepaliveRequests: 1000,
			KeepaliveTimeout: 75 * time.Second, ServerNamesHashMaxSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	protection := edgeconfig.DefaultDDoSProtection()
	protection.MaxConnectionsPerIP, protection.CCKernelBan = 100, mode
	value, err := edgeconfig.NewSiteRuntimeDDoS(protection, append([]string{}, networks...))
	if err != nil {
		t.Fatal(err)
	}
	system.DDoS = &value
	return &system
}

func testSite(scope, site string, ports ...int) edgesite.Site {
	value := edgesite.Site{ConfigurationScopeID: scope, SiteID: site}
	for _, port := range ports {
		value.Listeners = append(value.Listeners, edgesite.Listener{Port: port, AddressFamily: edgesite.FamilyIPv4})
	}
	return value
}

type recordedDDoS struct{ specs []*ddos.Spec }

func (r *recordedDDoS) Apply(_ context.Context, spec *ddos.Spec) error {
	r.specs = append(r.specs, spec)
	return nil
}

func TestSelectSystemTakesHighestRevisionAndMergesNodeNetworks(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	if system, err := runtime.selectSystem(nil); err != nil || system != nil {
		t.Fatalf("no scope system: %v %v", system, err)
	}
	older := testSystem(t, 1, edgeconfig.CCKernelBanOff, "10.0.0.0/24")
	newer := testSystem(t, 2, edgeconfig.CCKernelBanSitePorts, "10.0.1.0/24")
	system, err := runtime.selectSystem([]*edgeconfig.SiteRuntimeSystem{older, newer})
	if err != nil || system.Revision != 2 || system.DDoS.Protection.CCKernelBan != edgeconfig.CCKernelBanSitePorts ||
		!slices.Equal(system.DDoS.NodeNetworks, []string{"10.0.0.0/24", "10.0.1.0/24"}) {
		t.Fatalf("selected %+v %v", system, err)
	}
	if newer.DDoS.NodeNetworks[0] != "10.0.1.0/24" || len(newer.DDoS.NodeNetworks) != 1 {
		t.Fatal("input system was modified")
	}
	other := *newer
	other.PlatformScopeID = "0d13c000-0000-4000-8000-000000000002"
	if _, err := runtime.selectSystem([]*edgeconfig.SiteRuntimeSystem{older, &other}); err == nil {
		t.Fatal("two platforms accepted")
	}
}

func TestApplyDDoSCoversSitePorts(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	recorded := &recordedDDoS{}
	runtime.config.DDoS = recorded
	sites := []edgesite.Site{testSite(testScopeA, testSiteA, 80, 443), testSite(testScopeB, testSiteB, 81, 443)}
	// an L4 forward's TCP ports count as well (D13-c0)
	runtime.applyDDoS(context.Background(), testSystem(t, 1, edgeconfig.CCKernelBanOff), sites,
		[]ddos.PortRange{{First: 82, Last: 82}, {First: 9000, Last: 9010}})
	runtime.applyDDoS(context.Background(), nil, sites, nil)
	if len(recorded.specs) != 2 || recorded.specs[1] != nil {
		t.Fatalf("specs %+v", recorded.specs)
	}
	if got := recorded.specs[0].Ports; !slices.Equal(got, []ddos.PortRange{{First: 80, Last: 82}, {First: 443, Last: 443}, {First: 9000, Last: 9010}}) {
		t.Fatalf("ports %+v", got)
	}
}

func TestCCKernelBanPortsFollowMode(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	runtime.sites = []edgesite.Site{testSite(testScopeA, testSiteA, 80, 8080, 80), testSite(testScopeB, testSiteB, 80, 81)}
	for _, test := range []struct {
		mode string
		want []uint16
	}{
		{edgeconfig.CCKernelBanOff, nil},
		{edgeconfig.CCKernelBanSitePorts, []uint16{80, 8080}},
		{edgeconfig.CCKernelBanExclusivePorts, []uint16{8080}},
	} {
		runtime.state.System = testSystem(t, 1, test.mode)
		if got := runtime.CCKernelBanPorts(testScopeA, testSiteA); !slices.Equal(got, test.want) {
			t.Fatalf("%s: %v, want %v", test.mode, got, test.want)
		}
	}
	if got := runtime.CCKernelBanPorts(testScopeB, testSiteA); got != nil {
		t.Fatalf("other scope's site: %v", got)
	}
	// an L4 forward sharing 8080 makes it not exclusive (D13-c0)
	runtime.state.L4TCP = []ddos.PortRange{{First: 8000, Last: 8080}}
	if got := runtime.CCKernelBanPorts(testScopeA, testSiteA); got != nil {
		t.Fatalf("exclusive with a shared L4 port: %v", got)
	}
	runtime.state.L4TCP = nil
	runtime.state.System = nil
	if got := runtime.CCKernelBanPorts(testScopeA, testSiteA); got != nil {
		t.Fatalf("no system: %v", got)
	}
}

// WAF kernel bans name only the site: the running site's scope completes it.
func TestSiteTenantScopeOfRunningSites(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	runtime.sites = []edgesite.Site{testSite(testScopeA, testSiteA, 80), testSite(testScopeB, testSiteB, 81)}
	if got := runtime.SiteTenantScope(testSiteB); got != testScopeB {
		t.Fatalf("site B scope %q", got)
	}
	if got := runtime.SiteTenantScope("018f47a2-5b9c-7d31-8a60-104c9c0b7f99"); got != "" {
		t.Fatalf("site not running here: %q", got)
	}
}

// The deployment checks read the last sync's unavailable certificates; a
// later sync replaces the list (a copy: callers cannot change it).
func TestUnavailableCertificatesFollowTheLastSync(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	if got := runtime.UnavailableCertificates(); got != nil {
		t.Fatalf("before any sync: %+v", got)
	}
	runtime.setUnavailable(dyntls.SyncResult{Unavailable: []dyntls.Unavailable{{SiteID: testSiteA, VersionID: "v1"}}})
	got := runtime.UnavailableCertificates()
	if len(got) != 1 || got[0].SiteID != testSiteA || got[0].VersionID != "v1" {
		t.Fatalf("after sync: %+v", got)
	}
	got[0].SiteID = "changed"
	runtime.setUnavailable(dyntls.SyncResult{})
	if got := runtime.UnavailableCertificates(); len(got) != 0 {
		t.Fatalf("after a clean sync: %+v", got)
	}
}

// A08: on a node the tenant does not own, site_ports narrows to the site's
// exclusive ports, so a CC/WAF/security_ban kernel ban (nftables and XDP)
// never covers a port another tenant's site serves.
func TestSharedNodeCCKernelBanPortsNeverCoverSharedPorts(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	runtime.sites = []edgesite.Site{testSite(testScopeA, testSiteA, 80, 8080, 80), testSite(testScopeB, testSiteB, 80, 81)}
	for _, test := range []struct {
		mode string
		want []uint16
	}{
		{edgeconfig.CCKernelBanOff, nil},
		{edgeconfig.CCKernelBanSitePorts, []uint16{8080}},
		{edgeconfig.CCKernelBanExclusivePorts, []uint16{8080}},
	} {
		runtime.state.System = testSystem(t, 1, test.mode)
		if got := runtime.SharedNodeCCKernelBanPorts(testScopeA, testSiteA); !slices.Equal(got, test.want) {
			t.Fatalf("%s: %v, want %v", test.mode, got, test.want)
		}
	}
}

// A node runs its own nginx base (region/node
// overrides) from the selected block, and renders it.
func TestSelectSystemTakesThisNodesNginx(t *testing.T) {
	const self, other = "0d13c000-0000-4000-8000-00000000e001", "0d13c000-0000-4000-8000-00000000e002"
	base := testSystem(t, 3, edgeconfig.CCKernelBanOff, "10.0.0.0/24")
	tuned := base.Nginx.Settings()
	tuned.WorkerConnections, tuned.ProxyHTTPVersion = 30000, "1.0"
	withNodes, err := base.WithNodeNginx(map[string]edgeconfig.NginxSettings{self: tuned})
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/tmp", "nrb") // short: the control socket path has a length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	runtime, err := New(Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, "shared"),
		LuaRoot: root, OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: -1, CacheMaxBytes: 10 << 30, NodeID: self})
	if err != nil {
		t.Fatal(err)
	}
	system, err := runtime.selectSystem([]*edgeconfig.SiteRuntimeSystem{testSystem(t, 1, edgeconfig.CCKernelBanOff), &withNodes})
	if err != nil || system.Nginx.WorkerConnections != 30000 || system.NodeNginx != nil || system.DDoS == nil {
		t.Fatalf("own node: %+v %v", system, err)
	}
	conf, err := runtime.render([]edgesite.Site{testSite(testScopeA, testSiteA, 80)}, dynwaf.Result{}, system, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"events { worker_connections 30000; }", "      proxy_http_version 1.0;\n",
		// proxy_cache_max_size (1g) caps the 10g local budget: 4 zones of 256m; min_free unset
		" max_size=256m "} {
		if !strings.Contains(string(conf), want) {
			t.Fatalf("rendered skeleton lacks %q", want)
		}
	}
	if strings.Contains(string(conf), "min_free=") {
		t.Fatal("min_free rendered without one")
	}
	runtime.config.NodeID = other
	if system, err = runtime.selectSystem([]*edgeconfig.SiteRuntimeSystem{&withNodes}); err != nil ||
		system.Nginx.WorkerConnections != 20000 {
		t.Fatalf("other node: %+v %v", system, err)
	}
}
