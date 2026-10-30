package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// brotliModulePattern finds ngx_brotli (native source chain step 25; step 26,
// the compression levels with variables, is in the same chain) in
// `openresty -V` configure arguments.
var brotliModulePattern = regexp.MustCompile(`(?:^|\s)--add-module=\S*/ngx_brotli(?:\s|$)`)

// openRestyCompressesBrotli reports whether the OpenResty binary was built
// with ngx_brotli; the agent declares EDGE_BROTLI only then.
func openRestyCompressesBrotli(ctx context.Context, binary string) bool {
	if binary == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// nginx prints -V to stderr.
	output, err := exec.CommandContext(ctx, binary, "-V").CombinedOutput()
	if err != nil || len(output) > 1<<20 {
		return false
	}
	for _, line := range bytes.Split(output, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("configure arguments:")) && brotliModulePattern.Match(line) {
			return true
		}
	}
	return false
}

// webpProbe loads libgd with the runtime's own LuaJIT and resolves its WebP
// encoder and JPEG/PNG decoders (what cdnca_webp_codec calls).
const webpProbe = `local ffi = require "ffi"
ffi.cdef "void *gdImageWebpPtrEx(void *, int *, int); void *gdImageCreateFromJpegPtrEx(int, void *, int); void *gdImageCreateFromPngPtr(int, void *);"
local ok, gd = pcall(ffi.load, "libgd.so.3")
if not ok then ok, gd = pcall(ffi.load, "gd") end
assert(ok, gd)
assert(gd.gdImageWebpPtrEx and gd.gdImageCreateFromJpegPtrEx and gd.gdImageCreateFromPngPtr)
print("webp ok")`

// openRestyConvertsWebP reports whether the runtime ships the WebP modules
// (cdnca_webp, cdnca_webp_codec under luaRoot/dynroute) and its LuaJIT can
// load libgd with the WebP encoder; the agent declares EDGE_WEBP only then.
// binary is <prefix>/bin/openresty, the LuaJIT is <prefix>/luajit/bin/luajit.
func openRestyConvertsWebP(ctx context.Context, binary, luaRoot string) bool {
	if binary == "" || luaRoot == "" {
		return false
	}
	for _, name := range []string{"cdnca_webp.lua", "cdnca_webp_codec.lua"} {
		if info, err := os.Stat(filepath.Join(luaRoot, "dynroute", name)); err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	luajit := filepath.Join(filepath.Dir(filepath.Dir(binary)), "luajit", "bin", "luajit")
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, luajit, "-e", webpProbe).CombinedOutput()
	return err == nil && bytes.Equal(bytes.TrimSpace(output), []byte("webp ok"))
}

// addCompressionCapabilities declares EDGE_BROTLI and EDGE_WEBP independently.
func addCompressionCapabilities(capabilities *agentv1.AgentCapabilities, brotli, webp bool) {
	if brotli {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_BROTLI, ApiVersion: 1,
		})
	}
	if webp {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_WEBP, ApiVersion: 1,
		})
	}
}
