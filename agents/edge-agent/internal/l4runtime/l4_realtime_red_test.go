package l4runtime

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCompileV2EmitsPrivatePerListenerL4Telemetry(t *testing.T) {
	const (
		tenantID = "018f47a2-5b9c-7d31-8a60-104c9c0b7102"
		siteID   = "018f47a2-5b9c-7d31-8a60-104c9c0b7103"
		streamID = "018f47a2-5b9c-7d31-8a60-104c9c0b7104"
		version  = "018f47a2-5b9c-7d31-8a60-104c9c0b7105"
	)
	compiled, err := CompileV2(ConfigV2{
		SchemaVersion: SchemaVersionV2, VersionID: version, Revision: 9,
		Listeners: []ListenerV2{{
			ID: streamID, TenantID: tenantID, SiteID: siteID, StreamID: streamID,
			Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 18080,
			Endpoint:         EndpointV2{Address: "8.8.8.8", Port: 443},
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30_000,
			MaxConnectionsPerClient: 100, DrainTimeoutMS: 30_000,
		}}}, map[string][]netip.Addr{streamID: {netip.MustParseAddr("8.8.8.8")}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(compiled.NginxConfig)
	wantPath, err := L4TelemetryLogPathForConfigListener("/var/lib/cdnca-edge", version, compiled.Config.Listeners[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"log_format l4_session_v1 escape=json",
		"set $cdnca_l4_tenant_id \"" + tenantID + "\";",
		"set $cdnca_l4_site_id \"" + siteID + "\";",
		"set $cdnca_l4_stream_id \"" + streamID + "\";",
		"set $cdnca_l4_config_version_id \"" + version + "\";",
		"access_log \"" + wantPath + "\" l4_session_v1;",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("compiled L4 runtime omitted %q:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"remote_addr\\\":", "proxy_protocol_addr\\\":", "upstream_addr\\\":"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("L4 telemetry leaked a sensitive address field %q", forbidden)
		}
	}
}

func TestL4TelemetryLogPathDoesNotAliasSamePortProtocols(t *testing.T) {
	const (
		root     = "/var/lib/cdnca-edge"
		version  = "018f47a2-5b9c-7d31-8a60-104c9c0b7105"
		site     = "018f47a2-5b9c-7d31-8a60-104c9c0b7103"
		stream   = "018f47a2-5b9c-7d31-8a60-104c9c0b7104"
		listener = "018f47a2-5b9c-7d31-8a60-104c9c0b7106"
	)
	tcp, err := L4TelemetryLogPathForIdentity(root, version, site, stream, listener, ProtocolTCP, "0.0.0.0", 18080)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := L4TelemetryLogPathForIdentity(root, version, site, stream, listener, ProtocolUDP, "0.0.0.0", 18080)
	if err != nil {
		t.Fatal(err)
	}
	if tcp == udp {
		t.Fatalf("same-port TCP and UDP telemetry paths alias: %q", tcp)
	}
	if strings.Contains(tcp, "..") || strings.Contains(udp, "..") {
		t.Fatalf("identity-aware telemetry path contains traversal: %q %q", tcp, udp)
	}
	if _, err := L4TelemetryLogPathForIdentity(root, version, site, "../escape", listener, ProtocolTCP, "0.0.0.0", 18080); err == nil {
		t.Fatal("telemetry path accepted a traversal identity")
	}
}
