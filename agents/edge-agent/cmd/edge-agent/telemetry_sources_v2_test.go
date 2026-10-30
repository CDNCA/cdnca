package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// siteRuntimeV2TelemetryRelease is a derived site runtime v2 release as the
// site runtime adapter hands it to the precheck: the signed bundle (with its
// telemetry identity, revision != 0, and no legacy cache identity) plus the
// rendered nginx.conf.
func siteRuntimeV2TelemetryRelease(t *testing.T, root string) (string, edgeconfig.TelemetryIdentityManifest) {
	t.Helper()
	const version = "018f47a2-5b9c-7d31-8a60-104c9c0b7102"
	directory := filepath.Join(root, "shared", "telemetry", version, telemetryTestSiteID, "443")
	manifest := edgeconfig.TelemetryIdentityManifest{
		SchemaVersion: 1, ConfigVersionID: version, ConfigRevision: 41, TenantID: telemetryTestTenantID,
		Sites: []edgeconfig.TelemetrySiteIdentity{{
			SiteID: telemetryTestSiteID, Domain: "www.example.test", ListenPort: 443,
			NamespaceID:   edgeconfig.CacheSiteNamespaceID(telemetryTestTenantID, telemetryTestSiteID),
			AccessLogPath: filepath.Join(directory, "access.jsonl"), SecurityLogPath: filepath.Join(directory, "security.jsonl"),
		}},
		CapturePolicy: edgeconfig.TelemetryCapturePolicyManifest{SchemaVersion: 1, Sites: []edgeconfig.TelemetrySiteCapturePolicy{{
			SiteID: telemetryTestSiteID, Domain: "www.example.test", ListenPort: 443,
			Methods: []string{}, URIPrefixes: []string{}, RequestHeaderAllowlist: []string{}, ResponseHeaderAllowlist: []string{},
			RequestBodyFieldAllowlist: []string{}, ResponseBodyFieldAllowlist: []string{},
			MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20,
		}}},
		SourceCapabilities: edgeconfig.TelemetrySourceCapabilities{SchemaVersion: 1},
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(root, "site-runtime-release")
	for path, value := range map[string][]byte{
		edgeconfig.TelemetryIdentityManifestPath: append(content, '\n'),
		"site-runtime.v2.json":                   []byte("{}\n"),
		"nginx.conf":                             []byte("events {}\n"),
	} {
		target := filepath.Join(release, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return release, manifest
}

// A release whose sites do not cache carries no cache identity: its telemetry
// precheck must still prepare the signed log sources rather than refuse the
// release (which would leave the node without usage logs).
func TestTelemetryPrecheckPreparesSiteRuntimeV2SourcesWithoutCacheIdentity(t *testing.T) {
	root := telemetrySecureRoot(t)
	release, manifest := siteRuntimeV2TelemetryRelease(t, root)
	called := false
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error {
		called = true
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), manifest.ConfigVersionID, release); err != nil {
		t.Fatalf("site runtime v2 Precheck() error = %v", err)
	}
	if !called {
		t.Fatal("OpenResty delegate was not called")
	}
	for _, path := range []string{manifest.Sites[0].AccessLogPath, manifest.Sites[0].SecurityLogPath} {
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("site runtime v2 telemetry source %q = %v, %v", path, info, err)
		}
	}
}
