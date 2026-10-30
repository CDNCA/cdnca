package acmehttp01

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// siteRuntimeOverlayRoot is a deployment root whose current release is a
// signed site runtime v2 release (no nginx.conf) and whose rendered config
// lives in the site runtime's own current release, as on a v2 node.
func siteRuntimeOverlayRoot(t *testing.T, route bool) (string, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "deployment")
	signed := filepath.Join(root, "releases", "signed-v2")
	derived := filepath.Join(base, "site-runtime", "releases", "derived-v2")
	for _, path := range []string{filepath.Join(root, "state"), signed, derived} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(signed, "site-runtime.v2.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", "signed-v2"), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	config := "http {\n  server {\n    listen 80;\n    location / { return 200; }\n  }\n}\n"
	if route {
		config = "http {\n  server {\n    listen 80;\n" + edgeconfig.RenderACMEHTTP01Location(root) + "    location / { return 200; }\n  }\n}\n"
	}
	if err := os.WriteFile(filepath.Join(derived, "nginx.conf"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", "derived-v2"), filepath.Join(base, "site-runtime", "current")); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(base, "site-runtime", "current", "nginx.conf")
}

func siteRuntimeOverlayManager(t *testing.T, root string, paths ...string) *Manager {
	t.Helper()
	manager, err := NewManagerWithConfig(root, Config{
		Probe: &filesystemProbe{root: root}, ProbeAddress: "127.0.0.1:80", RequestTimeout: time.Second,
		Now: time.Now, RuntimeConfigPaths: paths,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

// On a site runtime v2 node the overlay route is in the site runtime's
// rendered config, not in the signed release deployment_root/current names.
func TestManagerReadyFindsSiteRuntimeV2Route(t *testing.T) {
	root, siteRuntimeConfig := siteRuntimeOverlayRoot(t, true)
	if siteRuntimeOverlayManager(t, root).Ready() {
		t.Fatal("ready without consulting the site runtime config")
	}
	if !siteRuntimeOverlayManager(t, root, siteRuntimeConfig).Ready() {
		t.Fatal("site runtime v2 route was not recognized")
	}
}

func TestManagerReadyRejectsSiteRuntimeV2ConfigWithoutRoute(t *testing.T) {
	root, siteRuntimeConfig := siteRuntimeOverlayRoot(t, false)
	if siteRuntimeOverlayManager(t, root, siteRuntimeConfig).Ready() {
		t.Fatal("site runtime config without the overlay route was ready")
	}
}

func TestManagerRejectsUnsafeRuntimeConfigPaths(t *testing.T) {
	root, _ := siteRuntimeOverlayRoot(t, true)
	for _, path := range []string{"relative/nginx.conf", "/a/../b/nginx.conf", ""} {
		if _, err := NewManagerWithConfig(root, Config{
			Probe: &filesystemProbe{root: root}, RequestTimeout: time.Second, Now: time.Now, RuntimeConfigPaths: []string{path},
		}); err == nil {
			t.Fatalf("runtime config path %q was accepted", path)
		}
	}
}
