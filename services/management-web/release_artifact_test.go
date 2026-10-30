package main

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func releaseArtifactHandler(t *testing.T, authorization *url.URL) (http.Handler, string) {
	t.Helper()
	artifacts := t.TempDir()
	files := map[string]string{
		"control-api/1.0.40/cdnca-control-native.tar":   "control-package",
		"edge-agent/1.0.40/cdnca-edge-agent.bundle":     "edge-package",
		".incoming/upload-123.part":                     "partial",
		"edge-agent/latest/SHA256SUMS":                  "uploaded-latest",
		"edge-agent/1.0.40/nested/cdnca-edge-agent.tar": "too-deep",
	}
	for name, body := range files {
		path := filepath.Join(artifacts, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	upstream, _ := url.Parse("http://127.0.0.1:1")
	handler, err := newHandlerWithOptions(downloadRoot(t), upstream, handlerOptions{
		MasterDownloadAuthorization: authorization, AuthorizationTimeout: 300 * time.Millisecond,
		ReleaseArtifactRoot: artifacts})
	if err != nil {
		t.Fatal(err)
	}
	return handler, artifacts
}

func TestReleaseArtifactDirectoryServesUploadedPackages(t *testing.T) {
	stub := newAuthorizationStub(t, http.StatusNoContent)
	handler, _ := releaseArtifactHandler(t, stub.url(t))
	for target, body := range map[string]string{
		"/downloads/control-api/1.0.40/cdnca-control-native.tar": "control-package",
		"/downloads/edge-agent/1.0.40/cdnca-edge-agent.bundle":   "edge-package",
		// The release static tree keeps precedence over uploads.
		"/downloads/edge-agent/latest/SHA256SUMS": "edge-sums\n",
	} {
		response := serve(handler, http.MethodGet, target, "198.51.100.7:4000", nil)
		if response.Code != http.StatusOK || response.Body.String() != body {
			t.Fatalf("%s: status=%d body=%q", target, response.Code, response.Body.String())
		}
	}
	response := serve(handler, http.MethodGet, "/downloads/edge-agent/1.0.40/cdnca-edge-agent.bundle", "198.51.100.7:4000", nil)
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Encoding") != "" {
		t.Fatalf("uploaded package headers = %#v", response.Header())
	}
}

func TestReleaseArtifactDirectoryKeepsMasterGate(t *testing.T) {
	stub := newAuthorizationStub(t, http.StatusForbidden)
	handler, _ := releaseArtifactHandler(t, stub.url(t))
	response := serve(handler, http.MethodGet, "/downloads/control-api/1.0.40/cdnca-control-native.tar", "198.51.100.7:4000", nil)
	if response.Code != http.StatusForbidden || response.Header().Get("X-CDNCA-Download-Denied") != "master-ip" {
		t.Fatalf("gated upload: status=%d headers=%#v", response.Code, response.Header())
	}
	// Edge agent packages stay public, like the release tree.
	response = serve(handler, http.MethodGet, "/downloads/edge-agent/1.0.40/cdnca-edge-agent.bundle", "198.51.100.7:4000", nil)
	if response.Code != http.StatusOK || response.Body.String() != "edge-package" {
		t.Fatalf("edge upload: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestReleaseArtifactDirectoryRejectsHiddenAndNonVersionedPaths(t *testing.T) {
	stub := newAuthorizationStub(t, http.StatusNoContent)
	handler, _ := releaseArtifactHandler(t, stub.url(t))
	for _, target := range []string{
		"/downloads/.incoming/upload-123.part",
		"/downloads/edge-agent/.incoming/upload-123.part",
		"/downloads/edge-agent/1.0.40/nested/cdnca-edge-agent.tar",
		"/downloads/edge-agent/1.0.40",
		"/downloads/edge-agent/1.0.40/missing.tar",
		"/downloads/edge-agent/1.0.40/../../.incoming/upload-123.part",
	} {
		response := serve(handler, http.MethodGet, target, "198.51.100.7:4000", nil)
		if response.Body.String() == "partial" || response.Body.String() == "too-deep" ||
			response.Body.String() == "edge-package" {
			t.Fatalf("%s served uploaded content: status=%d", target, response.Code)
		}
		// http.ServeFile answers ".." request paths with 400 before the index
		// fallback; either way nothing from the upload tree is served.
		if response.Code != http.StatusBadRequest && response.Body.String() != "<html>shell</html>" {
			t.Fatalf("%s: status=%d body=%q, want index fallback", target, response.Code, response.Body.String())
		}
	}
}
