package l4runtime

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Workers drop to the unprivileged nginx user while the version directory is
// sealed 0500/0400 for the agent, so the master must read the Geo config.
func TestV2GeoConfigIsPreloadedByMaster(t *testing.T) {
	compiled, err := CompileV2(v2LifecycleConfig(t, "preload", 3, 3), map[string][]netip.Addr{l403Stream: {netip.MustParseAddr("8.8.8.8")}})
	if err != nil {
		t.Fatal(err)
	}
	want := "stream {\n    lua_package_path '/opt/cdnca/l4geo/?.lua;/opt/cdnca/?.lua;;';\n" +
		"    init_by_lua_block { require(\"cdnca_l4_geo\").preload() }\n"
	if !strings.Contains(string(compiled.NginxConfig), want) {
		t.Fatalf("v2 nginx does not preload Geo in the master:\n%s", compiled.NginxConfig)
	}
}

// A stored nginx.conf must be the current render byte for byte: a version
// without the preload directive (the 1.0.33 render) is a conflict like any
// other difference.
func TestV2StoredVersionMustMatchCurrentRender(t *testing.T) {
	compiled, err := CompileV2(v2LifecycleConfig(t, "stored", 3, 3), map[string][]netip.Addr{l403Stream: {netip.MustParseAddr("8.8.8.8")}})
	if err != nil {
		t.Fatal(err)
	}
	runtimeJSON, err := encodeStoredRuntimeV2(compiled)
	if err != nil {
		t.Fatal(err)
	}
	legacy := bytes.Replace(compiled.NginxConfig, []byte(geoPreloadDirectiveV2), nil, 1)
	if bytes.Equal(legacy, compiled.NginxConfig) {
		t.Fatal("compiled nginx has no Geo preload directive")
	}
	for _, test := range []struct {
		name  string
		nginx []byte
		want  error
	}{
		{"current", compiled.NginxConfig, nil},
		{"without preload", legacy, ErrConflict},
		{"tampered", append(append([]byte(nil), legacy...), "# drift\n"...), ErrConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "version")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, content := range map[string][]byte{"runtime.json": runtimeJSON, "config.json": compiled.GeoJSON, "nginx.conf": test.nginx} {
				if err := os.WriteFile(filepath.Join(directory, name), content, 0o400); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(directory, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
			if err := verifyVersionDirectoryV2(directory, compiled); !errors.Is(err, test.want) {
				t.Fatalf("verify %s = %v, want %v", test.name, err, test.want)
			}
		})
	}
}
