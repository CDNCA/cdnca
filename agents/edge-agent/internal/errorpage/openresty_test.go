package errorpage

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSITE13OpenRestyAdapterRendersStableIncludesAndPrechecksReloads(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(root, "versions", strings.Repeat("a", 64))
	if err := os.MkdirAll(release, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "policy.lua"), []byte("return { schema = 'cdnca.error-pages/v1', revision = 9, resources = {}, bindings = {} }\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	runtime, err := NewOpenRestyRuntime(OpenRestyRuntimeConfig{
		Binary: "/usr/local/openresty/bin/openresty", RuntimePrefix: filepath.Join(root, "site-current"), ConfigFile: "nginx.conf",
		Run: func(_ context.Context, binary string, args ...string) error {
			calls = append(calls, append([]string{binary}, args...))
			return nil
		},
		Probe: func(context.Context, Artifact) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	httpInclude, siteInclude, err := OpenRestyIncludes(filepath.Join(root, "error-pages", "current", "policy.lua"),
		"/usr/local/share/cdnca/errorpage/handler.lua", "01990000-0000-7000-8000-000000000002")
	if err != nil || !strings.Contains(httpInclude, "cdnca_error_policy") || !strings.Contains(httpInclude, "policy.lua") ||
		!strings.Contains(siteInclude, "proxy_intercept_errors on") || !strings.Contains(siteInclude, "content_by_lua_file") ||
		!strings.Contains(siteInclude, "01990000-0000-7000-8000-000000000002") {
		t.Fatalf("http=%q site=%q err=%v", httpInclude, siteInclude, err)
	}
	artifact := Artifact{Revision: 9, Digest: strings.Repeat("b", 64)}
	if err := runtime.Precheck(t.Context(), release); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(t.Context(), release); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Health(t.Context(), release, artifact); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	joined := make([]string, len(calls))
	for index := range calls {
		joined[index] = strings.Join(calls[index], " ")
	}
	if len(calls) != 5 || !slices.ContainsFunc(joined, func(value string) bool { return strings.Contains(value, " -t ") }) ||
		!slices.ContainsFunc(joined, func(value string) bool { return strings.Contains(value, " -s reload ") }) {
		t.Fatalf("calls=%v", calls)
	}
}

// On a node /usr/local/openresty is the installer's symlink to the current native release
// (scripts/install-node.sh activate_native_package). The OpenResty binary path names the
// stable link, not a resolved release path, so the adapter must accept a symlinked binary.
func TestOpenRestyRuntimeAcceptsSymlinkedBinaryLikeNativeNodes(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(root, "releases", "r1", "runtime", "openresty", "bin")
	if err := os.MkdirAll(release, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "openresty"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "usr-local-openresty")
	if err := os.Symlink(filepath.Join(root, "releases", "r1", "runtime", "openresty"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOpenRestyRuntime(OpenRestyRuntimeConfig{
		Binary: filepath.Join(link, "bin", "openresty"), RuntimePrefix: filepath.Join(root, "site-current"), ConfigFile: "nginx.conf",
		Probe: func(context.Context, Artifact) error { return nil },
	}); err != nil {
		t.Fatalf("symlinked OpenResty binary refused: %v", err)
	}
	if _, err := NewOpenRestyRuntime(OpenRestyRuntimeConfig{
		Binary: "relative/openresty", RuntimePrefix: filepath.Join(root, "site-current"), ConfigFile: "nginx.conf",
		Probe: func(context.Context, Artifact) error { return nil },
	}); err == nil {
		t.Fatal("relative binary accepted")
	}
}
