package l4runtime

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sharedPortSpec's site argument is unused since tcp/udp v12 (a stream
// belongs to no website); it is kept so the callers read as before.
func sharedPortSpec(tenant, _, stream string, port int, passthrough bool, names ...string) StreamRuntimeSpecV2 {
	spec := multiListenerV2Spec()
	spec.AdditionalListeners = nil
	spec.TenantID, spec.StreamID = tenant, stream
	spec.Geo.TenantID, spec.Geo.StreamID = tenant, stream
	spec.Listener = ListenerSocketV2{Protocol: ProtocolTCP, Address: "*", Port: port}
	spec.TLSPassthrough, spec.ServerNames = passthrough, names
	return spec
}

const (
	sharedTenantA = "aaaaaaaa-0000-4000-8000-00000000000a"
	sharedTenantB = "bbbbbbbb-0000-4000-8000-00000000000b"
	sharedSiteA   = "aaaaaaaa-1111-4111-8111-00000000000a"
	sharedSiteB   = "bbbbbbbb-1111-4111-8111-00000000000b"
	sharedStreamA = "aaaaaaaa-2222-4222-8222-00000000000a"
	sharedStreamB = "bbbbbbbb-2222-4222-8222-00000000000b"
	sharedStreamC = "cccccccc-2222-4222-8222-00000000000c"
)

func compileShared(t *testing.T, sites []SiteSocketsV2, specs ...StreamRuntimeSpecV2) (CompiledConfigV2, error) {
	t.Helper()
	config, err := AggregateStreamRuntimeSpecsV2("shared-v1", 1, specs, sites...)
	if err != nil {
		return CompiledConfigV2{}, err
	}
	addresses := map[string][]netip.Addr{}
	for _, spec := range specs {
		addresses[spec.StreamID] = []netip.Addr{netip.MustParseAddr("8.8.8.8")}
	}
	return CompileV2(config, addresses)
}

func TestV2TLSPassthroughStreamsShareAPortBySNI(t *testing.T) {
	compiled, err := compileShared(t, nil,
		sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, true, "a.example", "*.a.example"),
		sharedPortSpec(sharedTenantB, sharedSiteB, sharedStreamB, 9443, true, "b.example"),
		sharedPortSpec(sharedTenantB, sharedSiteB, sharedStreamC, 9443, false))
	if err != nil {
		t.Fatalf("compile shared port: %v", err)
	}
	nginx := string(compiled.NginxConfig)
	if strings.Count(nginx, "listen 0.0.0.0:9443") != 1 {
		t.Fatalf("want one public listener on 9443:\n%s", nginx)
	}
	dispatcher := nginx[strings.Index(nginx, "listen 0.0.0.0:9443"):]
	dispatcher = dispatcher[:strings.Index(dispatcher, "    }\n")]
	for _, want := range []string{"ssl_preread on;", "proxy_protocol on;", "access_log off;"} {
		if !strings.Contains(dispatcher, want) {
			t.Fatalf("dispatcher missing %q:\n%s", want, dispatcher)
		}
	}
	socket := func(stream string) string { return L4DispatchSocketPath(stream) }
	for _, want := range []string{
		"hostnames;", `"a.example" "=unix:` + socket(sharedStreamA) + `";`, `"*.a.example" "=unix:` + socket(sharedStreamA) + `";`,
		`"b.example" "=unix:` + socket(sharedStreamB) + `";`,
		`"|" "unix:` + socket(sharedStreamC) + `";`, `default "unix:` + L4RejectSocketPath + `";`,
	} {
		if !strings.Contains(nginx, want) {
			t.Fatalf("dispatch maps missing %q:\n%s", want, nginx)
		}
	}
	for _, stream := range []string{sharedStreamA, sharedStreamB, sharedStreamC} {
		server := nginx[strings.Index(nginx, "listen unix:"+socket(stream)+" proxy_protocol;"):]
		server = server[:strings.Index(server, "    }\n")]
		for _, want := range []string{"set_real_ip_from unix:;", `$cdnca_l4_stream_id "` + stream + `"`, "l4_session_dispatched_v1;"} {
			if !strings.Contains(server, want) {
				t.Fatalf("stream %s internal server missing %q:\n%s", stream, want, server)
			}
		}
	}
	if !strings.Contains(nginx, `"server_port":"$proxy_protocol_server_port"`) {
		t.Fatalf("dispatched session log does not report the public port:\n%s", nginx)
	}
}

func TestV2SinglePassthroughStreamChecksSNIOnItsOwnPort(t *testing.T) {
	compiled, err := compileShared(t, nil, sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, true, "a.example"))
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(compiled.NginxConfig)
	if strings.Contains(strings.ReplaceAll(nginx, "listen unix:"+L4ControlSocketPath+";", ""), "listen unix:") {
		t.Fatalf("a lone passthrough stream needs no internal hop:\n%s", nginx)
	}
	for _, want := range []string{"listen 0.0.0.0:9443;", "ssl_preread on;", `"a.example" "l4_v2_upstream_`, `default "unix:` + L4RejectSocketPath + `";`} {
		if !strings.Contains(nginx, want) {
			t.Fatalf("passthrough server missing %q:\n%s", want, nginx)
		}
	}
}

func TestV2SharedPortSendsWebsiteTrafficToItsSockets(t *testing.T) {
	sites := []SiteSocketsV2{{Port: 9443, PlainSocket: "/var/lib/cdnca-edge/shared/mux/9443-plain.sock",
		TLSSocket: "/var/lib/cdnca-edge/shared/mux/9443-tls.sock", TLSServerNames: []string{"www.example"}}}
	// A TLS website and a plain TCP forward cannot both take plaintext.
	if _, err := compileShared(t, sites, sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, false)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("plaintext site and plain TCP forward on one port: %v", err)
	}
	sites[0].PlainSocket = ""
	compiled, err := compileShared(t, sites,
		sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, false),
		sharedPortSpec(sharedTenantB, sharedSiteB, sharedStreamB, 9443, true, "b.example"))
	if err != nil {
		t.Fatalf("TLS site + plain forward + TLS forward: %v", err)
	}
	nginx := string(compiled.NginxConfig)
	for _, want := range []string{`"www.example" "=unix:/var/lib/cdnca-edge/shared/mux/9443-tls.sock";`,
		`"|" "unix:` + L4DispatchSocketPath(sharedStreamA) + `";`,
		// TLS without a known name reaches the websites' default server, as before.
		`default "unix:/var/lib/cdnca-edge/shared/mux/9443-tls.sock";`} {
		if !strings.Contains(nginx, want) {
			t.Fatalf("shared website port missing %q:\n%s", want, nginx)
		}
	}
	// A forward may not repeat a website's server name.
	sites[0].TLSServerNames = []string{"b.example"}
	if _, err := compileShared(t, sites, sharedPortSpec(sharedTenantB, sharedSiteB, sharedStreamB, 9443, true, "b.example")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("repeated server name: %v", err)
	}
}

func TestV2SharedPortsRejectWhatCannotBeToldApart(t *testing.T) {
	for name, specs := range map[string][]StreamRuntimeSpecV2{
		"two plain TCP forwards": {sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, false),
			sharedPortSpec(sharedTenantB, sharedSiteB, sharedStreamB, 9443, false)},
		"repeated SNI": {sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, true, "x.example"),
			sharedPortSpec(sharedTenantB, sharedSiteB, sharedStreamB, 9443, true, "x.example")},
	} {
		if _, err := compileShared(t, nil, specs...); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	proxied := sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, true, "a.example")
	proxied.ProxyProtocolOutbound = true
	if _, err := compileShared(t, nil, proxied, sharedPortSpec(sharedTenantB, sharedSiteB, sharedStreamB, 9443, true, "b.example")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("PROXY protocol on a split port: %v", err)
	}
	if _, err := compileShared(t, nil, proxied); err != nil {
		t.Fatalf("PROXY protocol on a passthrough stream alone on its port: %v", err)
	}
	udp := sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, true, "a.example")
	udp.Listener.Protocol = ProtocolUDP
	if _, err := compileShared(t, nil, udp); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("UDP passthrough: %v", err)
	}
}

// Configurations without the new fields keep their bytes and digest.
func TestV2ExclusiveConfigurationIsUnchanged(t *testing.T) {
	spec := multiListenerV2Spec()
	config, err := AggregateStreamRuntimeSpecsV2("multi", 9, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalV2(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"tls_passthrough", "server_names", "site_sockets"} {
		if strings.Contains(string(canonical), field) {
			t.Fatalf("exclusive configuration serializes %s:\n%s", field, canonical)
		}
	}
	compiled, err := CompileV2(config, map[string][]netip.Addr{spec.StreamID: {netip.MustParseAddr("8.8.8.8")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, unexpected := range []string{"ssl_preread", "listen unix:", "l4_session_dispatched_v1"} {
		// the live registry's control socket is not a dispatch hop
		if strings.Contains(strings.ReplaceAll(string(compiled.NginxConfig), "listen unix:"+L4ControlSocketPath+";", ""), unexpected) {
			t.Fatalf("exclusive configuration renders %s:\n%s", unexpected, compiled.NginxConfig)
		}
	}
}

// L4F-E04: workers of a root OpenResty run as nobody; behind a 0700 parent
// (the deployment root and shared/ are private) they cannot reach the
// internal sockets and every dispatched connection is reset. The directory
// is refused at apply time instead.
func TestDispatchDirectoryMustBeTraversableByWorkers(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	directory := filepath.Join(private, "shared", "l4mux")
	if err := os.MkdirAll(filepath.Join(private, "shared"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketDirectoryFor(directory, 0o711, true, root); !errors.Is(err, ErrInvalidConfig) ||
		!strings.Contains(err.Error(), "not traversable") {
		t.Fatalf("0700 parent accepted for nobody workers: %v", err)
	}
	// Workers of the agent's own user own the path: 0700 parents are fine.
	if err := prepareSocketDirectoryFor(directory, 0o711, false, root); err != nil {
		t.Fatalf("same-user workers: %v", err)
	}
	for _, path := range []string{private, filepath.Join(private, "shared")} {
		if err := os.Chmod(path, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareSocketDirectoryFor(directory, 0o711, true, root); err != nil {
		t.Fatalf("traversable parents refused: %v", err)
	}
}

func TestV2DispatchDirectoryMovesInternalSockets(t *testing.T) {
	spec := sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, true, "a.example")
	config, err := AggregateStreamRuntimeSpecsV2("v2-dispatch-dir", 1, []StreamRuntimeSpecV2{spec},
		SiteSocketsV2{Port: 9443, TLSSocket: "/run/cdnca/mux/9443-tls.sock", TLSServerNames: []string{"www.example"}})
	if err != nil {
		t.Fatal(err)
	}
	config.DispatchDirectory = "/run/cdnca/mux/l4"
	compiled, err := CompileV2(config, map[string][]netip.Addr{sharedStreamA: {netip.MustParseAddr("8.8.8.8")}})
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(compiled.NginxConfig)
	for _, want := range []string{"listen unix:/run/cdnca/mux/l4/" + sharedStreamA + ".sock proxy_protocol;",
		`"a.example" "=unix:/run/cdnca/mux/l4/` + sharedStreamA + `.sock";`} {
		if !strings.Contains(nginx, want) {
			t.Fatalf("missing %q:\n%s", want, nginx)
		}
	}
	if strings.Contains(nginx, L4DispatchDirectory) {
		t.Fatalf("default dispatch directory still used:\n%s", nginx)
	}
	for _, bad := range []string{"relative/l4", "/run/cdnca/mux/../l4", "/", "/run/cdnca/mux l4"} {
		config.DispatchDirectory = bad
		if _, err := CanonicalV2(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%q accepted: %v", bad, err)
		}
	}
}
