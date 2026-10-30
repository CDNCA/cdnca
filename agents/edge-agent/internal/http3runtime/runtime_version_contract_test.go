package http3runtime

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// lockedOpenRestyVersion is the single source of the node runtime version:
// edge/openresty/runtime.env, which must equal native/sources.lock.json (the
// signed native package and the container image are built from that lock).
func lockedOpenRestyVersion(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve contract test path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../.."))
	envBytes, err := os.ReadFile(filepath.Join(repoRoot, "edge/openresty/runtime.env"))
	if err != nil {
		t.Fatal(err)
	}
	var fromEnv []string
	for _, line := range strings.Split(string(envBytes), "\n") {
		if value, found := strings.CutPrefix(line, "OPENRESTY_VERSION="); found {
			fromEnv = append(fromEnv, value)
		}
	}
	if len(fromEnv) != 1 || fromEnv[0] == "" {
		t.Fatalf("runtime.env must define OPENRESTY_VERSION exactly once, got %q", fromEnv)
	}
	lockBytes, err := os.ReadFile(filepath.Join(repoRoot, "edge/openresty/native/sources.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Source struct {
			Version string `json:"version"`
		} `json:"source"`
	}
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Source.Version != fromEnv[0] {
		t.Fatalf("runtime.env OPENRESTY_VERSION=%s, sources.lock.json source.version=%s", fromEnv[0], lock.Source.Version)
	}
	return fromEnv[0]
}

// The HTTP/3 runtime accepts exactly one OpenResty release: the one nodes run.
func TestRuntimeVersionEqualsLockedNodeRuntime(t *testing.T) {
	if want := lockedOpenRestyVersion(t); RuntimeVersionOpenResty != want {
		t.Fatalf("RuntimeVersionOpenResty=%s, node runtime (edge/openresty/runtime.env)=%s", RuntimeVersionOpenResty, want)
	}
}

func TestVersionOneFixturePinsLockedNodeRuntime(t *testing.T) {
	policyBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "http3", "fixtures", "policy-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy Policy
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		t.Fatal(err)
	}
	if want := lockedOpenRestyVersion(t); policy.Runtime.Version != want {
		t.Fatalf("policy-v1.json runtime.version=%s, node runtime=%s", policy.Runtime.Version, want)
	}
}

func TestRuntimeVersionMismatchIsRejected(t *testing.T) {
	for _, version := range []string{"1.27.1.2", RuntimeVersionOpenResty + "0", RuntimeVersionOpenResty + ".1", ""} {
		policy := validPolicy("http3-v1")
		policy.Runtime.Version = version
		if _, err := Compile(policy); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Compile(runtime %q) error = %v, want ErrUnsupported", version, err)
		}
	}
}

// supportsRuntime compares the binary's version token, not a substring:
// openresty/1.31.1.10 is not openresty/1.31.1.1.
func TestSupportsRuntimeComparesWholeVersionToken(t *testing.T) {
	ref := RuntimeRef{Family: RuntimeFamilyOpenResty, Version: RuntimeVersionOpenResty}
	flags := "configure arguments: --with-http_ssl_module --with-http_v2_module --with-http_v3_module"
	real := "nginx version: openresty/" + RuntimeVersionOpenResty + "\nbuilt with OpenSSL 3.4.1\n" + flags
	if !supportsRuntime(real, ref) {
		t.Fatal("multi-line -V output of the pinned runtime was rejected")
	}
	for name, output := range map[string]string{
		"longer patch":      "nginx version: openresty/" + RuntimeVersionOpenResty + "0\n" + flags,
		"extra component":   "nginx version: openresty/" + RuntimeVersionOpenResty + ".1\n" + flags,
		"version elsewhere": "nginx version: openresty/1.27.1.2\nbuilt for openresty/" + RuntimeVersionOpenResty + "\n" + flags,
		"not first token":   "nginx version: nginx/1.31.1 openresty/" + RuntimeVersionOpenResty + "\n" + flags,
	} {
		t.Run(name, func(t *testing.T) {
			if supportsRuntime(output, ref) {
				t.Fatal("non-matching runtime version was accepted")
			}
		})
	}
}
