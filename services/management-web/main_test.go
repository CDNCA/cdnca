package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStaticRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<html>shell</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "index-12345678.js"), []byte(strings.Repeat("const shell = true;\n", 100)), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestStaticAssetsUseGzipAndImmutableCaching(t *testing.T) {
	upstream, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newHandler(testStaticRoot(t), upstream)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/dashboard/assets/index-12345678.js", nil)
	request.Header.Set("Accept-Encoding", "gzip, deflate")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if got := response.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("content encoding = %q, want gzip", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("cache control = %q", got)
	}
	if got := response.Header().Get("Content-Length"); got != "" {
		t.Fatalf("content length = %q, want omitted for gzip", got)
	}
	reader, err := gzip.NewReader(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decoded), "const shell = true") {
		t.Fatalf("decoded body does not contain asset payload")
	}
}

func TestIndexFallbackIsNotCachedAndGzipHonorsQZero(t *testing.T) {
	upstream, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newHandler(testStaticRoot(t), upstream)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/dashboard/site/list", nil)
	request.Header.Set("Accept-Encoding", "gzip;q=0")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "<html>shell</html>" {
		t.Fatalf("fallback = status %d body %q", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
	if got := response.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("content encoding = %q, want empty", got)
	}
}
