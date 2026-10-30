package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// EDGE_BROTLI follows the OpenResty build (ngx_brotli).
func TestOpenRestyCompressesBrotliOnlyWithTheModule(t *testing.T) {
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
		"native":         {"--with-http_v3_module --add-module=/tmp/openresty-source/bundle/cdnca-ja4 --add-module=/tmp/openresty-source/bundle/ngx_brotli", true},
		"middle":         {"--add-module=/x/ngx_brotli --with-stream", true},
		"without module": {"--with-http_v3_module --add-module=/tmp/openresty-source/bundle/cdnca-ja4", false},
		"similar name":   {"--add-module=/x/ngx_brotli_static --add-module=/x/ngx_brotlix", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := openRestyCompressesBrotli(context.Background(), fake(name, test.configure)); got != test.want {
				t.Fatalf("openRestyCompressesBrotli = %v, want %v", got, test.want)
			}
		})
	}
	if openRestyCompressesBrotli(context.Background(), filepath.Join(directory, "missing")) || openRestyCompressesBrotli(context.Background(), "") {
		t.Fatal("missing binary reported Brotli")
	}
}

// EDGE_WEBP needs both Lua modules and a LuaJIT that loads libgd's WebP
// encoder (the probe's output "webp ok").
func TestOpenRestyConvertsWebPNeedsModulesAndLibgd(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "openresty", "bin", "openresty")
	luajit := filepath.Join(root, "openresty", "luajit", "bin", "luajit")
	lua := filepath.Join(root, "lua")
	for _, path := range []string{filepath.Dir(binary), filepath.Dir(luajit), filepath.Join(lua, "dynroute")} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeLuaJIT := func(output string) {
		if err := os.WriteFile(luajit, []byte("#!/bin/sh\necho '"+output+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeLuaJIT("webp ok")
	if openRestyConvertsWebP(context.Background(), binary, lua) {
		t.Fatal("WebP without the Lua modules")
	}
	for _, name := range []string{"cdnca_webp.lua", "cdnca_webp_codec.lua"} {
		if err := os.WriteFile(filepath.Join(lua, "dynroute", name), []byte("return {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !openRestyConvertsWebP(context.Background(), binary, lua) {
		t.Fatal("WebP not reported with modules and libgd")
	}
	writeLuaJIT("no")
	if openRestyConvertsWebP(context.Background(), binary, lua) {
		t.Fatal("WebP reported without libgd")
	}
	if openRestyConvertsWebP(context.Background(), "", lua) || openRestyConvertsWebP(context.Background(), binary, "") {
		t.Fatal("WebP reported without a runtime")
	}
}

func TestCompressionCapabilitiesAreDeclaredIndependently(t *testing.T) {
	for _, test := range []struct{ brotli, webp bool }{{true, false}, {false, true}, {true, true}, {false, false}} {
		capabilities := &agentv1.AgentCapabilities{}
		addCompressionCapabilities(capabilities, test.brotli, test.webp)
		got := map[agentv1.CapabilityName]uint32{}
		for _, feature := range capabilities.Features {
			got[feature.Name] = feature.ApiVersion
		}
		if (got[agentv1.CapabilityName_CAPABILITY_NAME_EDGE_BROTLI] == 1) != test.brotli ||
			(got[agentv1.CapabilityName_CAPABILITY_NAME_EDGE_WEBP] == 1) != test.webp || len(got) != len(capabilities.Features) {
			t.Fatalf("brotli=%v webp=%v: %v", test.brotli, test.webp, got)
		}
	}
}
