package edgeconfig

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func testSystemNginx() NginxSettings {
	return NginxSettings{
		WorkerProcesses: 8, WorkerRlimitNoFile: 65535, WorkerShutdownTimeout: 30 * time.Second, WorkerConnections: 20000,
		ResolverAddresses: []string{"8.8.8.8", "1.1.1.1"}, ResolverTimeout: 5 * time.Second,
		GzipLevel: 5, GzipMinimumBytes: 1024, GzipVary: true, ProxyBuffering: true,
		ProxyCacheMethods: []string{"HEAD", "GET"}, ProxyCacheMaxBytes: 1 << 30, ProxyCacheZoneBytes: 64 << 20,
		ProxyMaxTempFileBytes: 1 << 20, ProxyConnectTimeout: 10 * time.Second, ProxySendTimeout: 60 * time.Second,
		ProxyReadTimeout: 60 * time.Second, StreamProxyTimeout: 10 * time.Minute, ServerHeader: "cdnca",
		ClientMaxBodyBytes: 100 << 20, DefaultMIMEType: "text/html", KeepaliveRequests: 1000,
		KeepaliveTimeout: 75 * time.Second, LogNotFound: false, ServerNamesHashMaxSize: 4096, ServerTokens: false,
	}
}

const testPlatformScope = "018f47a2-5b9c-7d31-8a60-104c9c0b7301"

func testSystem(t *testing.T, revision int64, digest string) *SiteRuntimeSystem {
	t.Helper()
	value, err := NewSiteRuntimeSystem(testPlatformScope, revision, strings.Repeat(digest, 64), testSystemNginx())
	if err != nil {
		t.Fatal(err)
	}
	return &value
}

func TestNewSiteRuntimeSystemIsCanonical(t *testing.T) {
	value := testSystem(t, 3, "a")
	if strings.Join(value.Nginx.ResolverAddresses, ",") != "1.1.1.1,8.8.8.8" ||
		strings.Join(value.Nginx.ProxyCacheMethods, ",") != "GET,HEAD" {
		t.Fatalf("not normalized: %+v", value.Nginx)
	}
	unsorted := *value
	unsorted.Nginx.ResolverAddresses = []string{"8.8.8.8", "1.1.1.1"}
	if unsorted.Validate() == nil {
		t.Fatal("noncanonical resolver order accepted")
	}
	bad := testSystemNginx()
	bad.WorkerConnections = 100
	if _, err := NewSiteRuntimeSystem(testPlatformScope, 1, strings.Repeat("a", 64), bad); err == nil {
		t.Fatal("out-of-range worker_connections accepted")
	}
	fraction := testSystemNginx()
	fraction.ProxyReadTimeout = 1500*time.Millisecond + time.Microsecond
	if _, err := NewSiteRuntimeSystem(testPlatformScope, 1, strings.Repeat("a", 64), fraction); err == nil {
		t.Fatal("sub-millisecond duration accepted")
	}
}

func TestSiteRuntimeSystemRendersEveryLevel(t *testing.T) {
	value := testSystem(t, 3, "a")
	main := SiteRuntimeSystemMain(value)
	for _, want := range []string{"worker_processes 8;\n", "worker_rlimit_nofile 65535;\n", "worker_shutdown_timeout 30s;\n"} {
		if !strings.Contains(main, want) {
			t.Fatalf("main lacks %q:\n%s", want, main)
		}
	}
	if SiteRuntimeSystemEvents(value) != "events { worker_connections 20000; }\n" {
		t.Fatalf("events = %q", SiteRuntimeSystemEvents(value))
	}
	http := SiteRuntimeSystemHTTP(value)
	for _, want := range []string{"  resolver 1.1.1.1 8.8.8.8;\n", "  gzip_comp_level 5;\n", "  client_max_body_size 104857600;\n",
		"  keepalive_timeout 75s;\n", "  server_tokens off;\n", "  more_set_headers \"Server: cdnca\";\n"} {
		if !strings.Contains(http, want) {
			t.Fatalf("http lacks %q:\n%s", want, http)
		}
	}
	if SiteRuntimeSystemMain(nil) != "worker_processes auto;\n" || SiteRuntimeSystemHTTP(nil) != "  server_tokens off;\n" ||
		SiteRuntimeSystemEvents(nil) != "events { worker_connections 4096; }\n" {
		t.Fatal("defaults without a system configuration changed")
	}
}

func TestSelectSiteRuntimeSystemHighestRevisionWins(t *testing.T) {
	older, newer := testSystem(t, 2, "a"), testSystem(t, 5, "b")
	selected, err := SelectSiteRuntimeSystem([]*SiteRuntimeSystem{older, nil, newer})
	if err != nil || selected != newer {
		t.Fatalf("selected = %+v, %v", selected, err)
	}
	if selected, err := SelectSiteRuntimeSystem([]*SiteRuntimeSystem{nil, nil}); err != nil || selected != nil {
		t.Fatalf("no system = %+v, %v", selected, err)
	}
	if _, err := SelectSiteRuntimeSystem([]*SiteRuntimeSystem{testSystem(t, 5, "c"), newer}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("one revision with two snapshots = %v", err)
	}
	foreign := testSystem(t, 1, "a")
	foreign.PlatformScopeID = "018f47a2-5b9c-7d31-8a60-104c9c0b7399"
	if _, err := SelectSiteRuntimeSystem([]*SiteRuntimeSystem{newer, foreign}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("two platforms = %v", err)
	}
}

// The fields that used to be saved but never rendered.
func TestSiteRuntimeSystemRendersRegionBFields(t *testing.T) {
	settings := testSystemNginx()
	settings.GzipHTTPVersion, settings.ProxyRequestBufferingDisabled = "1.0", true
	settings.ProxyHTTPVersion, settings.ProxyNextUpstream = "1.0", []string{"http_504", "error", "timeout"}
	settings.LargeClientHeaderBufferCount, settings.LargeClientHeaderBufferBytes = 8, 16<<10
	settings.ServerNamesHashBucketSize, settings.ServerAddrOutgoing, settings.ClientBodyBufferBytes = 128, true, 32<<10
	value, err := NewSiteRuntimeSystem(testPlatformScope, 1, strings.Repeat("a", 64), settings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(value.Nginx.ProxyNextUpstream, " ") != "error timeout http_504" {
		t.Fatalf("proxy_next_upstream not canonical: %v", value.Nginx.ProxyNextUpstream)
	}
	http := SiteRuntimeSystemHTTP(&value)
	for _, want := range []string{"  gzip_http_version 1.0;\n", "  proxy_request_buffering off;\n",
		"  large_client_header_buffers 8 16384;\n", "  server_names_hash_bucket_size 128;\n",
		"  client_body_buffer_size 32768;\n", "  default_type \"text/html\";\n"} {
		if !strings.Contains(http, want) {
			t.Fatalf("http lacks %q:\n%s", want, http)
		}
	}
	got := value.Nginx.Settings()
	if NginxProxyHTTPVersion(got) != "1.0" || NginxProxyNextUpstream(got) != "error timeout http_504" || !got.ServerAddrOutgoing {
		t.Fatalf("location values = %q %q %v", NginxProxyHTTPVersion(got), NginxProxyNextUpstream(got), got.ServerAddrOutgoing)
	}
	// A document from before keeps the earlier rendering.
	old := SiteRuntimeSystemHTTP(testSystem(t, 1, "a"))
	for _, absent := range []string{"gzip_http_version", "proxy_request_buffering", "large_client_header_buffers",
		"server_names_hash_bucket_size", "client_body_buffer_size"} {
		if strings.Contains(old, absent) {
			t.Fatalf("old document renders %s:\n%s", absent, old)
		}
	}
	if NginxProxyHTTPVersion(NginxSettings{}) != "1.1" || NginxProxyNextUpstream(NginxSettings{}) != "error timeout http_502 http_503 http_504" {
		t.Fatal("defaults without a value changed")
	}
	for name, mutate := range map[string]func(*NginxSettings){
		"off with others":     func(v *NginxSettings) { v.ProxyNextUpstream = []string{"off", "error"} },
		"unknown condition":   func(v *NginxSettings) { v.ProxyNextUpstream = []string{"http_418"} },
		"bucket not power":    func(v *NginxSettings) { v.ServerNamesHashBucketSize = 100 },
		"buffers half set":    func(v *NginxSettings) { v.LargeClientHeaderBufferCount = 4 },
		"gzip version":        func(v *NginxSettings) { v.GzipHTTPVersion = "2.0" },
		"default_type quote":  func(v *NginxSettings) { v.DefaultMIMEType = "text/\"x" },
		"body buffer too big": func(v *NginxSettings) { v.ClientBodyBufferBytes = 2 << 30 },
		"proxy version 2":     func(v *NginxSettings) { v.ProxyHTTPVersion = "2" },
	} {
		bad := testSystemNginx()
		mutate(&bad)
		if _, err := NewSiteRuntimeSystem(testPlatformScope, 1, strings.Repeat("a", 64), bad); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestSiteRuntimeSystemNodeNginx(t *testing.T) {
	base := testSystem(t, 4, "a")
	const nodeA, nodeB, nodeC = "018f47a2-5b9c-7d31-8a60-104c9c0b7a01", "018f47a2-5b9c-7d31-8a60-104c9c0b7a02",
		"018f47a2-5b9c-7d31-8a60-104c9c0b7a03"
	region := testSystemNginx()
	region.GzipLevel, region.ProxyHTTPVersion = 9, "1.0"
	node := testSystemNginx()
	node.WorkerConnections = 30000
	value, err := base.WithNodeNginx(map[string]NginxSettings{nodeB: region, nodeA: region, nodeC: node,
		"018f47a2-5b9c-7d31-8a60-104c9c0b7a04": testSystemNginx()})
	if err != nil {
		t.Fatal(err)
	}
	// one group per distinct base, the node equal to the base left out
	if len(value.NodeNginx) != 2 || strings.Join(value.NodeNginx[0].NodeIDs, ",") != nodeA+","+nodeB ||
		strings.Join(value.NodeNginx[1].NodeIDs, ",") != nodeC {
		t.Fatalf("groups = %+v", value.NodeNginx)
	}
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	a := value.ForNode(nodeA)
	if a.Nginx.GzipLevel != 9 || a.NodeNginx != nil || !strings.Contains(SiteRuntimeSystemHTTP(a), "gzip_comp_level 9;") {
		t.Fatalf("node A = %+v", a.Nginx)
	}
	if c := value.ForNode(nodeC); SiteRuntimeSystemEvents(c) != "events { worker_connections 30000; }\n" {
		t.Fatalf("node C events = %q", SiteRuntimeSystemEvents(c))
	}
	if other := value.ForNode("018f47a2-5b9c-7d31-8a60-104c9c0b7a09"); other.Nginx.GzipLevel != 5 || other.NodeNginx != nil {
		t.Fatalf("unlisted node = %+v", other.Nginx)
	}
	if empty, err := base.WithNodeNginx(nil); err != nil || empty.NodeNginx != nil {
		t.Fatalf("no overrides = %+v, %v", empty.NodeNginx, err)
	}
	twice := value
	twice.NodeNginx = append(slices.Clone(value.NodeNginx), SiteRuntimeSystemNodeNginx{NodeIDs: []string{nodeA}, Nginx: value.NodeNginx[1].Nginx})
	if twice.Validate() == nil {
		t.Fatal("a node in two groups accepted")
	}
	same := value
	same.NodeNginx = []SiteRuntimeSystemNodeNginx{{NodeIDs: []string{nodeA}, Nginx: value.Nginx}}
	if same.Validate() == nil {
		t.Fatal("a group equal to the base accepted")
	}
	var none *SiteRuntimeSystem
	if none.ForNode(nodeA) != nil {
		t.Fatal("nil system for a node")
	}
}
