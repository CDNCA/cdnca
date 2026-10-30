package siteobject

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestDynamicRoutingVersionMatchesEdgeconfig(t *testing.T) {
	if DynamicRoutingSiteRuntimeVersion != edgeconfig.DynamicRoutingSiteRuntimeVersion {
		t.Fatal("site runtime versions drifted from edgeconfig")
	}
}

func v2Input(sites int) BuildV2Input {
	input := BuildV2Input{
		ConfigurationScopeID: testScopeID, ConfigVersionID: "c0000000-0000-4000-8000-000000000002",
		SourceRevision: 3, KeyEpoch: 1, RequiredCapabilities: []Capability{{"cc", 2}, {"site_runtime", 9}},
		DocumentSHA256: Digest([]byte("document")), Referenced: map[string][]byte{},
		ScopeFiles: map[string][]byte{"security/modsecurity/crs/a.conf": []byte("SecRule")},
	}
	ref := []byte(`{"policy":1}`)
	input.Referenced[Digest(ref)] = ref
	for index := range sites {
		id := fmt.Sprintf("a0000000-0000-4000-8000-%012d", index+1)
		input.Sites = append(input.Sites, SiteV2{SiteID: id, Revision: int64(index + 1), Plaintext: []byte(`{"site":"` + id + `"}`)})
	}
	return input
}

func TestBuildV2ParsesBack(t *testing.T) {
	publication, root, err := BuildV2(v2Input(300))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRootV2(publication.RootBytes)
	if err != nil || parsed.ScopeSHA256 != root.ScopeSHA256 || parsed.BucketCount != 2 ||
		!slices.Equal(parsed.RequiredCapabilities, []Capability{{"cc", 2}, {"site_runtime", 9}}) {
		t.Fatalf("%+v %v", parsed, err)
	}
	objects := map[string][]byte{}
	for _, object := range publication.Objects {
		objects[object.SHA256] = object.Plaintext
	}
	scope, err := ParseScopeV2(objects[root.ScopeSHA256])
	if err != nil || len(scope.Files) != 1 || len(scope.Objects) != 1 {
		t.Fatalf("%+v %v", scope, err)
	}
	sites := 0
	for _, digest := range root.Buckets {
		bucket, err := ParseBucketV2(objects[digest])
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range bucket.Sites {
			if _, present := objects[entry.SHA256]; !present {
				t.Fatalf("site %s missing", entry.SiteID)
			}
			sites++
		}
	}
	if sites != 300 || len(publication.Objects) != 300+2+1+2 {
		t.Fatalf("sites %d objects %d", sites, len(publication.Objects))
	}
	again, _, err := BuildV2(v2Input(300))
	if err != nil || !bytes.Equal(again.RootBytes, publication.RootBytes) {
		t.Fatal("v2 build is not deterministic")
	}
}

func TestBuildV2Rejects(t *testing.T) {
	input := v2Input(1)
	input.ScopeFiles["site-runtime.v2.json"] = []byte("{}")
	if _, _, err := BuildV2(input); err == nil {
		t.Fatal("a scope file outside the security directory was accepted")
	}
	input = v2Input(1)
	input.Referenced["00"] = []byte("x")
	if _, _, err := BuildV2(input); err == nil {
		t.Fatal("a referenced object under a wrong digest was accepted")
	}
	input = v2Input(1)
	input.RequiredCapabilities = []Capability{{"site_runtime", 8}}
	if _, _, err := BuildV2(input); err == nil {
		t.Fatal("v8 capabilities were accepted")
	}
}

// The document's system block rides on the v2 scope (D13-c0): it parses
// back as built, and an invalid one is refused on both sides.
func TestBuildV2CarriesSystem(t *testing.T) {
	system, err := edgeconfig.NewSiteRuntimeSystem("0d13c000-0000-4000-8000-000000000001", 4, strings.Repeat("d", 64),
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
	input := v2Input(1)
	input.System = &system
	publication, root, err := BuildV2(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range publication.Objects {
		if object.SHA256 == root.ScopeSHA256 {
			scope, err := ParseScopeV2(object.Plaintext)
			if err != nil || scope.System == nil || scope.System.Revision != 4 || scope.System.Nginx.ClientMaxBodyBytes != 100<<20 {
				t.Fatalf("%+v %v", scope.System, err)
			}
		}
	}
	bad := system
	bad.Revision = 0
	input.System = &bad
	if _, _, err := BuildV2(input); err == nil {
		t.Fatal("invalid system accepted")
	}
}

// The document's L4 forwards ride on the v2 scope (D13-c0): v2 streams
// only, validated as the v2 document's L4 artifact.
func TestBuildV2CarriesStreams(t *testing.T) {
	tenant := "c0000000-0000-4000-8000-0000000000aa"
	stream := "c0000000-0000-4000-8000-0000000000ac"
	value := edgeconfig.L4StreamRuntimeV2{SchemaVersion: "cdnca.edge.l4/v2", TenantID: tenant, StreamID: stream, Revision: 1,
		Listener: edgeconfig.L4ListenerV2{Protocol: "tcp", Address: "*", Port: 9000}, Endpoint: edgeconfig.L4EndpointV2{Address: "192.0.2.1", Port: 80},
		Geo:              edgeconfig.L4GeoPolicyV2{TenantID: tenant, StreamID: stream, Revision: 1, UnknownRegionAction: "allow"},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 3000, MaxConnectionsPerClient: 10, DrainTimeoutMS: 30000}
	input := v2Input(1)
	input.Streams = &edgeconfig.StreamRuntime{TenantID: tenant, StreamsV2: []edgeconfig.L4StreamRuntimeV2{value}}
	publication, root, err := BuildV2(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range publication.Objects {
		if object.SHA256 == root.ScopeSHA256 {
			scope, err := ParseScopeV2(object.Plaintext)
			if err != nil || scope.Streams == nil || len(scope.Streams.StreamsV2) != 1 || scope.Streams.StreamsV2[0].Listener.Port != 9000 {
				t.Fatalf("%+v %v", scope.Streams, err)
			}
		}
	}
	for name, streams := range map[string]*edgeconfig.StreamRuntime{
		"empty":        {TenantID: tenant},
		"wrong tenant": {TenantID: "c0000000-0000-4000-8000-0000000000ff", StreamsV2: []edgeconfig.L4StreamRuntimeV2{value}},
	} {
		input := v2Input(1)
		input.Streams = streams
		if _, _, err := BuildV2(input); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// Node pages (D13-b2) ride on the v2 scope with their bodies among the
// objects; a page whose body is missing or whose status the category does
// not allow is refused.
func TestBuildV2CarriesNodePages(t *testing.T) {
	body := []byte("host required\n")
	input := v2Input(1)
	input.Referenced[Digest(body)] = body
	input.NodePages = []NodePageV2{
		{Category: NodePageUnknownSite, Status: 404, MIMEType: "text/plain", SHA256: Digest(body)},
		{Category: NodePageNoHost, Status: 400, MIMEType: "text/plain", SHA256: Digest(body)},
	}
	publication, root, err := BuildV2(input)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	for _, object := range publication.Objects {
		if object.SHA256 == root.ScopeSHA256 {
			raw = object.Plaintext
		}
	}
	scope, err := ParseScopeV2(raw)
	if err != nil || len(scope.NodePages) != 2 || scope.NodePages[0].Category != NodePageNoHost {
		t.Fatalf("%+v %v", scope.NodePages, err)
	}
	for _, bad := range []NodePageV2{
		{Category: NodePageNoHost, Status: 404, MIMEType: "text/plain", SHA256: Digest(body)},
		{Category: NodePageUnknownSite, Status: 404, MIMEType: "text/plain", SHA256: Digest([]byte("missing"))},
		{Category: "origin_response", Status: 404, MIMEType: "text/plain", SHA256: Digest(body)},
	} {
		input.NodePages = []NodePageV2{bad}
		if _, _, err := BuildV2(input); err == nil {
			t.Fatalf("node page %+v was accepted", bad)
		}
	}
}

// errpage-3: slot node pages with region / node selectors need
// error_page_slots; ordering is (category, node, region).
func TestBuildV2SlotNodePages(t *testing.T) {
	body := []byte("<p>blocked</p>")
	input := v2Input(1)
	input.Referenced[Digest(body)] = body
	nodeID := "b0000000-0000-4000-8000-000000000009"
	input.NodePages = []NodePageV2{
		{Category: NodePageBlacklist, Status: 403, MIMEType: "text/html", SHA256: Digest(body), Region: "cn-east"},
		{Category: NodePageBlacklist, Status: 403, MIMEType: "text/html", SHA256: Digest(body)},
		{Category: NodePageBlacklist, Status: 403, MIMEType: "text/html", SHA256: Digest(body), NodeID: nodeID},
		{Category: NodePagePackageExpired, Status: 403, MIMEType: "text/html", SHA256: Digest(body)},
	}
	if _, _, err := BuildV2(input); err == nil {
		t.Fatal("slot node pages without error_page_slots were accepted")
	}
	input.RequiredCapabilities = []Capability{{"cc", 2}, {ErrorPageSlotsCapability, 1}, {"site_runtime", 9}}
	publication, root, err := BuildV2(input)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	for _, object := range publication.Objects {
		if object.SHA256 == root.ScopeSHA256 {
			raw = object.Plaintext
		}
	}
	scope, err := ParseScopeV2(raw)
	if err != nil || len(scope.NodePages) != 4 || scope.NodePages[0].NodeID != "" || scope.NodePages[0].Region != "" ||
		scope.NodePages[1].Region != "cn-east" || scope.NodePages[2].NodeID != nodeID ||
		scope.NodePages[3].Category != NodePagePackageExpired {
		t.Fatalf("%+v %v", scope.NodePages, err)
	}
	for _, bad := range []NodePageV2{
		{Category: NodePageTrafficExceeded, Status: 403, MIMEType: "text/html", SHA256: Digest(body)},
		{Category: NodePageBlacklist, Status: 403, MIMEType: "text/html", SHA256: Digest(body), Region: "CN"},
		{Category: NodePageBlacklist, Status: 403, MIMEType: "text/html", SHA256: Digest(body), NodeID: "node-1"},
		{Category: NodePageBlacklist, Status: 403, MIMEType: "text/html", SHA256: Digest(body), NodeID: nodeID, Region: "a"},
		{Category: "site_locked", Status: 403, MIMEType: "text/html", SHA256: Digest(body)},
	} {
		input.NodePages = []NodePageV2{bad}
		if _, _, err := BuildV2(input); err == nil {
			t.Fatalf("node page %+v was accepted", bad)
		}
	}
	input.NodePages = []NodePageV2{
		{Category: NodePageBlacklist, Status: 403, MIMEType: "text/html", SHA256: Digest(body)},
		{Category: NodePageBlacklist, Status: 403, MIMEType: "text/plain", SHA256: Digest(body)},
	}
	if _, _, err := BuildV2(input); err == nil {
		t.Fatal("two global pages of one category were accepted")
	}
}
