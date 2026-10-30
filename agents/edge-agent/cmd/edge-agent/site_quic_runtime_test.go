package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// SITE_QUIC (a v2 HTTPS listener also listens on QUIC)
// follows only the OpenResty build (--with-http_v3_module), never h3probe,
// which only the standalone HTTP/3 runtime (HTTP_3) needs.
func TestOpenRestyServesSiteQUICOnlyWithTheHTTP3Module(t *testing.T) {
	directory := t.TempDir()
	fake := func(name, configure string) string {
		path := filepath.Join(directory, name)
		script := "#!/bin/sh\necho 'nginx version: openresty/1.31.1.1' >&2\necho 'configure arguments: " + configure + "' >&2\n"
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, test := range map[string]struct {
		configure string
		want      bool
	}{
		"native":         {"--prefix=/usr/local/openresty/nginx --with-http_ssl_module --with-http_v2_module --with-http_v3_module --with-stream", true},
		"last argument":  {"--with-http_ssl_module --with-http_v3_module", true},
		"without module": {"--prefix=/usr/local/openresty/nginx --with-http_ssl_module --with-http_v2_module", false},
		"similar name":   {"--with-http_v3_module_x --without-http_v3_module", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := openRestyServesSiteQUIC(context.Background(), fake(name, test.configure)); got != test.want {
				t.Fatalf("openRestyServesSiteQUIC = %v, want %v", got, test.want)
			}
		})
	}
	if openRestyServesSiteQUIC(context.Background(), filepath.Join(directory, "missing")) || openRestyServesSiteQUIC(context.Background(), "") {
		t.Fatal("missing binary reported QUIC")
	}
}

// The declared feature set: SITE_QUIC without HTTP_3 when only the build has
// QUIC (no h3probe), HTTP_3 only with a ready standalone runtime.
func TestSiteQUICAndHTTP3AreDeclaredIndependently(t *testing.T) {
	for _, test := range []struct {
		quic, http3 bool
	}{{true, false}, {false, false}, {true, true}} {
		capabilities := agentCapabilities("1.31.1.1")
		addHTTPProtocolCapabilities(capabilities, test.quic, test.http3)
		seen := map[agentv1.CapabilityName]bool{}
		for _, feature := range capabilities.Features {
			seen[feature.Name] = true
		}
		if seen[agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC] != test.quic ||
			seen[agentv1.CapabilityName_CAPABILITY_NAME_HTTP_3] != test.http3 {
			t.Fatalf("quic=%v http3=%v declared %v", test.quic, test.http3, seen)
		}
	}
}
