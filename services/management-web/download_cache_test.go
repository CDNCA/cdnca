package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// /downloads/ names are reused across releases (latest/…, and a
// same-version re-cut with new bytes), so they always revalidate instead of
// being cached as immutable; a full read and a Range read answer the same.
func TestDownloadsRevalidateEvenWhenNamedLikeHashedAssets(t *testing.T) {
	root := testStaticRoot(t)
	for _, rel := range []string{"downloads/edge-agent/latest/cdnca-edge-agent.tar.gz", "downloads/edge-agent/1.0.35/cdnca-edge-agent-1.0.35-linux-amd64.bundle"} {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, make([]byte, 8192), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	upstream, _ := url.Parse("http://127.0.0.1:8080")
	handler, err := newHandler(root, upstream)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz", "/downloads/edge-agent/1.0.35/cdnca-edge-agent-1.0.35-linux-amd64.bundle"} {
		for _, ranged := range []bool{false, true} {
			request := httptest.NewRequest(http.MethodGet, target, nil)
			want := http.StatusOK
			if ranged {
				request.Header.Set("Range", "bytes=0-4095")
				want = http.StatusPartialContent
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != want {
				t.Fatalf("%s range=%v: status %d, want %d", target, ranged, response.Code, want)
			}
			if got := response.Header().Get("Cache-Control"); got != "no-cache" {
				t.Fatalf("%s range=%v: cache control %q, want no-cache", target, ranged, got)
			}
		}
	}
	// hashed Vite assets keep immutable caching
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/assets/index-12345678.js", nil))
	if got := response.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("hashed asset cache control %q", got)
	}
}
