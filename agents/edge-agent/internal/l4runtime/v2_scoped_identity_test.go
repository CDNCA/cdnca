package l4runtime

import (
	"net/netip"
	"strings"
	"testing"
)

// A multi-tenant node runs every scope's L4 streams in one OpenResty. Each
// stream keeps its own scope's config version for telemetry attribution.
func TestV2ScopedListenersKeepTheirOwnConfigVersion(t *testing.T) {
	first := multiListenerV2Spec()
	first.AdditionalListeners = nil
	first.ConfigVersionID, first.ConfigRevision = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", 41
	second := multiListenerV2Spec()
	second.AdditionalListeners = nil
	second.TenantID, second.StreamID = "66666666-6666-4666-8666-666666666666", "88888888-8888-4888-8888-888888888888"
	second.Geo.TenantID, second.Geo.StreamID = second.TenantID, second.StreamID
	second.Listener.Port = 9500
	second.ConfigVersionID, second.ConfigRevision = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1", 12
	config, err := AggregateStreamRuntimeSpecsV2("composed-0123456789abcdef", 1, []StreamRuntimeSpecV2{first, second})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileV2(config, map[string][]netip.Addr{
		first.StreamID: {netip.MustParseAddr("8.8.8.8")}, second.StreamID: {netip.MustParseAddr("8.8.4.4")},
	})
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(compiled.NginxConfig)
	for _, spec := range []StreamRuntimeSpecV2{first, second} {
		path, err := L4TelemetryLogPathForRuntimeStream("/var/lib/cdnca-edge", spec.ConfigVersionID, spec)
		if err != nil {
			t.Fatal(err)
		}
		server := nginx[strings.Index(nginx, `$cdnca_l4_stream_id "`+spec.StreamID+`"`):]
		server = server[:strings.Index(server, "    }\n")]
		for _, want := range []string{`$cdnca_l4_config_version_id "` + spec.ConfigVersionID + `"`,
			`access_log "` + path + `"`} {
			if !strings.Contains(server, want) {
				t.Fatalf("stream %s missing %q:\n%s", spec.StreamID, want, server)
			}
		}
	}
	if strings.Contains(nginx, `$cdnca_l4_config_version_id "composed-`) {
		t.Fatalf("a scoped stream reports the composed version:\n%s", nginx)
	}

	unscoped := multiListenerV2Spec()
	unscoped.ConfigVersionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1" // revision missing
	if _, err := AggregateStreamRuntimeSpecsV2("v", 1, []StreamRuntimeSpecV2{unscoped}); err == nil {
		t.Fatal("a stream version without its revision was accepted")
	}
}
