package cachetask

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// activateSiteRuntimeRelease activates a signed site runtime v2 release (no
// nginx.conf) under root and writes the node-compiled derived release the
// site runtime adapter keeps under <root>/../site-runtime/releases/<digest>.
func activateSiteRuntimeRelease(t *testing.T, root string, derived map[string][]byte) string {
	t.Helper()
	return activateSiteRuntimeReleaseUnder(t, root, filepath.Dir(root), derived)
}

// activateSiteRuntimeReleaseUnder is activateSiteRuntimeRelease for a release
// root (a scope's, on a multi-scope node) whose node state root is base. The
// signed document is unique per derived content so each release has its own
// digest.
func activateSiteRuntimeReleaseUnder(t *testing.T, root, base string, derived map[string][]byte) string {
	t.Helper()
	document := []byte(fmt.Sprintf("{\"derived\":%q}\n", derivedDigest(derived)))
	activateRawRelease(t, root, map[string][]byte{siteRuntimeDocumentFile: document})
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	digest := filepath.Base(target)
	signedManifest, err := os.ReadFile(filepath.Join(root, target, activeReleaseManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(base, "site-runtime", "releases", digest)
	if _, err := os.Stat(release); err == nil {
		return release
	}
	files := map[string][]byte{activeReleaseManifestFile: signedManifest, siteRuntimeDocumentFile: document}
	for path, content := range derived {
		files[path] = content
	}
	for path, content := range files {
		full := filepath.Join(release, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	return release
}

func derivedDigest(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	sum := sha256.New()
	for _, path := range paths {
		fmt.Fprintf(sum, "%s\x00%d\x00", path, len(files[path]))
		sum.Write(files[path])
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func siteRuntimeDerivedFiles(t *testing.T, nginx []byte) map[string][]byte {
	t.Helper()
	manifest, err := edgeconfig.SiteRuntimeCacheManifest(productionVersionV1, 7, productionTenantID, nginx,
		[]edgeconfig.CacheListenerPolicy{productionListener(8080), productionListener(8443)})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"nginx.conf": nginx, edgeconfig.CachePolicyManifestPath: manifest,
		edgeconfig.CachePolicyKeyModulePath: edgeconfig.CachePolicyKeyModule(),
	}
}

// Refresh and prewarm on a site runtime v2 node read the cache identity the
// node compiled; before, the signed release had no nginx.conf or manifest and
// every cache command failed with site not found.
func TestActiveReleaseResolverReadsSiteRuntimeDerivedCacheIdentity(t *testing.T) {
	root := testStateRoot(t)
	activateSiteRuntimeRelease(t, root, siteRuntimeDerivedFiles(t, []byte("# compiled site runtime\n")))
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	site, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil {
		t.Fatalf("ResolveSite() error = %v", err)
	}
	if site.CacheIdentity != edgeconfig.CacheNamespaceID(productionTenantID, productionSiteID, productionVersionV1) ||
		len(site.Listeners) != 2 || site.Listeners[0].PrewarmPort != 19080 || site.Listeners[0].CacheFreshness ||
		site.NginxSHA256 == "" {
		t.Fatalf("site runtime cache identity = %+v", site)
	}
}

func TestActiveReleaseResolverRejectsUnboundSiteRuntimeCacheIdentity(t *testing.T) {
	for name, mutate := range map[string]func(map[string][]byte){
		"nginx differs": func(files map[string][]byte) { files["nginx.conf"] = []byte("# other\n") },
		"key module":    func(files map[string][]byte) { files[edgeconfig.CachePolicyKeyModulePath] = []byte("return {}\n") },
		"no manifest":   func(files map[string][]byte) { delete(files, edgeconfig.CachePolicyManifestPath) },
	} {
		t.Run(name, func(t *testing.T) {
			root := testStateRoot(t)
			files := siteRuntimeDerivedFiles(t, []byte("# compiled site runtime\n"))
			mutate(files)
			activateSiteRuntimeRelease(t, root, files)
			resolver, err := NewActiveReleaseResolver(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7); !errors.Is(err, ErrSiteNotFound) {
				t.Fatalf("ResolveSite() error = %v, want ErrSiteNotFound", err)
			}
		})
	}
	// A derived release of another signed release is not this release's.
	root := testStateRoot(t)
	release := activateSiteRuntimeRelease(t, root, siteRuntimeDerivedFiles(t, []byte("# compiled site runtime\n")))
	if err := os.Chmod(filepath.Join(release, activeReleaseManifestFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, activeReleaseManifestFile), []byte(`{"files":[]}`), 0o440); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7); !errors.Is(err, ErrSiteNotFound) {
		t.Fatalf("foreign derived release error = %v, want ErrSiteNotFound", err)
	}
}
