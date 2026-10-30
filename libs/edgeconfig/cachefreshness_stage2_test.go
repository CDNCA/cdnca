package edgeconfig

import (
	"bytes"
	"encoding/json"
	"testing"
)

func assertCacheFreshnessBundleRejected(t *testing.T, candidate Bundle) {
	t.Helper()
	if err := ValidateCacheFreshnessBundle(candidate); err == nil {
		t.Error("cache freshness validator accepted an independent opaque Lua identity writer")
	}
	if err := ValidateBundle(candidate); err == nil {
		t.Error("complete bundle validator accepted an independent opaque Lua identity writer")
	}
	if _, err := MarshalBundle(candidate); err == nil {
		t.Error("MarshalBundle accepted an independent opaque Lua identity writer")
	}
	wire, err := json.Marshal(BundleDocument{
		Version: bundleDocumentVersion, Manifest: candidate.Manifest,
		ManifestSHA256: candidate.ManifestSHA256, Files: candidate.Files,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalBundle(wire); err == nil {
		t.Error("UnmarshalBundle accepted an independent opaque Lua identity writer")
	}
}

func testCacheFreshnessPolicy(spec Spec) *CacheFreshnessPolicy {
	return &CacheFreshnessPolicy{
		SchemaVersion: CacheFreshnessSchemaVersion, PolicyVersion: 7, ConfigurationVersion: spec.ConfigRevision,
		TenantID: spec.TenantID, SiteID: spec.Sites[0].ID, Mode: CacheFreshnessModeEnhancement,
		ListenAddress: "0.0.0.0", ListenPort: spec.Sites[0].ListenPort, Hosts: []string{spec.Sites[0].Domain},
		OriginHost: "127.0.0.1", OriginPort: 19001, CacheMaxBytes: 64 << 20,
		CacheInactiveSeconds: 3600, FreshSeconds: 30, CacheableStatuses: []uint16{200},
		Enhancement: CacheFreshnessEnhancementPolicy{Enabled: true, StaleWindowSeconds: 60},
	}
}

func injectNestedCacheFreshnessIdentitySet(t *testing.T, nginx []byte, domain, canonicalSet string) string {
	t.Helper()
	if !bytes.Contains(nginx, []byte(canonicalSet)) {
		t.Fatal("canonical identity set is not in the release")
	}
	return injectCacheFreshnessLocationDirective(t, nginx, domain,
		`      if ($request_uri = /identity-decoy) { set $cache_freshness_identity "forged"; }`+"\n")
}

func injectCacheFreshnessLocationDirective(t *testing.T, nginx []byte, domain, directive string) string {
	t.Helper()
	serverName := []byte("    server_name " + domain + ";\n")
	serverNameAt := bytes.Index(nginx, serverName)
	if serverNameAt < 0 {
		t.Fatal("public server_name not found")
	}
	serverStart := bytes.LastIndex(nginx[:serverNameAt], []byte("  server {\n"))
	if serverStart < 0 {
		t.Fatal("public server block not found")
	}
	locationOpening := []byte("    location / {\n")
	locationOffset := bytes.Index(nginx[serverNameAt:], locationOpening)
	if locationOffset < 0 {
		t.Fatal("public location block not found")
	}
	locationStart := serverNameAt + locationOffset
	insertion := locationStart + len(locationOpening)
	result := make([]byte, 0, len(nginx)+len(directive))
	result = append(result, nginx[:insertion]...)
	result = append(result, directive...)
	result = append(result, nginx[insertion:]...)
	return string(result)
}

func injectCacheFreshnessServerDirective(t *testing.T, nginx []byte, domain, directive string) string {
	t.Helper()
	serverName := []byte("    server_name " + domain + ";\n")
	serverNameAt := bytes.Index(nginx, serverName)
	if serverNameAt < 0 {
		t.Fatal("public server_name not found")
	}
	serverOpening := []byte("  server {\n")
	serverStart := bytes.LastIndex(nginx[:serverNameAt], serverOpening)
	if serverStart < 0 {
		t.Fatal("public server block not found")
	}
	insertion := serverStart + len(serverOpening)
	result := make([]byte, 0, len(nginx)+len(directive))
	result = append(result, nginx[:insertion]...)
	result = append(result, directive...)
	result = append(result, nginx[insertion:]...)
	return string(result)
}

func injectCacheFreshnessHTTPDirective(t *testing.T, nginx []byte, directive string) string {
	t.Helper()
	opening := []byte("http {\n")
	index := bytes.Index(nginx, opening)
	if index < 0 {
		t.Fatal("http block not found")
	}
	insertion := index + len(opening)
	result := make([]byte, 0, len(nginx)+len(directive))
	result = append(result, nginx[:insertion]...)
	result = append(result, directive...)
	result = append(result, nginx[insertion:]...)
	return string(result)
}

func injectCacheFreshnessNamedRouteDirective(t *testing.T, nginx []byte, domain, route, directive string) string {
	t.Helper()
	serverName := []byte("    server_name " + domain + ";\n")
	serverNameAt := bytes.Index(nginx, serverName)
	if serverNameAt < 0 {
		t.Fatal("public server_name not found")
	}
	locationOpening := []byte("    location " + route + " {\n")
	locationOffset := bytes.Index(nginx[serverNameAt:], locationOpening)
	if locationOffset < 0 {
		t.Fatal("cache policy named route not found")
	}
	insertion := serverNameAt + locationOffset + len(locationOpening)
	result := make([]byte, 0, len(nginx)+len(directive))
	result = append(result, nginx[:insertion]...)
	result = append(result, directive...)
	result = append(result, nginx[insertion:]...)
	return string(result)
}

func cacheFreshnessTestBundleWithNginx(t *testing.T, bundle Bundle, nginx []byte) Bundle {
	t.Helper()
	files := make(map[string][]byte, len(bundle.Files))
	for path, content := range bundle.Files {
		files[path] = bytes.Clone(content)
	}
	files["nginx.conf"] = bytes.Clone(nginx)
	manifest, err := ParseCachePolicyManifest(files[CachePolicyManifestPath])
	if err != nil {
		t.Fatal(err)
	}
	manifest.NginxSHA256 = digestHex(nginx)
	manifestContent, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files[CachePolicyManifestPath] = append(manifestContent, '\n')
	candidate, err := newBundle(files)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func manifestContainsPath(manifest Manifest, path string) bool {
	for _, file := range manifest.Files {
		if file.Path == path {
			return true
		}
	}
	return false
}
