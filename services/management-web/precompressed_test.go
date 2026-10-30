package main

import (
	"bytes"
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

const precompressedMarker = "precompressed-on-disk"

func precompressedHandler(t *testing.T) (http.Handler, string) {
	t.Helper()
	root := testStaticRoot(t)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte(precompressedMarker))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "index-12345678.js.gz"), compressed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "vendor-87654321.css"), []byte(strings.Repeat("a{b:c}\n", 50)), 0o644); err != nil {
		t.Fatal(err)
	}
	// A .gz beside the static root must never be reachable through "../".
	if err := os.WriteFile(filepath.Join(filepath.Dir(root), "secret.js.gz"), compressed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	upstream, _ := url.Parse("http://127.0.0.1:8080")
	handler, err := newHandler(root, upstream)
	if err != nil {
		t.Fatal(err)
	}
	return handler, root
}

func getStatic(handler http.Handler, target, acceptEncoding string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if acceptEncoding != "" {
		request.Header.Set("Accept-Encoding", acceptEncoding)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func gunzipBody(t *testing.T, body []byte) string {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(plain)
}

func TestStaticServesPrecompressedFile(t *testing.T) {
	handler, _ := precompressedHandler(t)
	response := getStatic(handler, "/dashboard/assets/index-12345678.js", "gzip, br")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	header := response.Header()
	if header.Get("Content-Encoding") != "gzip" || header.Get("Vary") != "Accept-Encoding" ||
		!strings.Contains(header.Get("Content-Type"), "javascript") ||
		header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("headers = %v", header)
	}
	if got := gunzipBody(t, response.Body.Bytes()); got != precompressedMarker {
		t.Fatalf("body = %q, want the on-disk .gz", got)
	}
}

func TestStaticPrecompressedSkippedWithoutGzipSupport(t *testing.T) {
	handler, _ := precompressedHandler(t)
	for _, encoding := range []string{"", "br", "gzip;q=0"} {
		response := getStatic(handler, "/dashboard/assets/index-12345678.js", encoding)
		if response.Code != http.StatusOK || response.Header().Get("Content-Encoding") != "" ||
			!strings.HasPrefix(response.Body.String(), "const shell = true;") {
			t.Fatalf("encoding %q: status=%d headers=%v", encoding, response.Code, response.Header())
		}
	}
}

func TestStaticWithoutGzFileCompressesOnTheFly(t *testing.T) {
	handler, _ := precompressedHandler(t)
	response := getStatic(handler, "/dashboard/assets/vendor-87654321.css", "gzip")
	if response.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(response.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("headers = %v", response.Header())
	}
	if got := gunzipBody(t, response.Body.Bytes()); got != strings.Repeat("a{b:c}\n", 50) {
		t.Fatalf("body = %q", got)
	}
}

func TestStaticPrecompressedRejectsTraversal(t *testing.T) {
	handler, root := precompressedHandler(t)
	for _, target := range []string{"/assets/../../secret.js", "/dashboard/../../secret.js", "/dashboard/assets/../../secret.js"} {
		response := getStatic(handler, target, "gzip")
		if strings.Contains(response.Body.String(), precompressedMarker) {
			t.Fatalf("%s leaked a file outside the root", target)
		}
		if response.Header().Get("Content-Encoding") == "gzip" {
			if body := response.Body.Bytes(); len(body) > 0 && strings.Contains(gunzipBody(t, body), precompressedMarker) {
				t.Fatalf("%s served %s", target, filepath.Join(filepath.Dir(root), "secret.js.gz"))
			}
		}
	}
	// Direct helper: a raw "../" path is refused even before path cleaning.
	recorder := httptest.NewRecorder()
	if servePrecompressed(recorder, httptest.NewRequest(http.MethodGet, "/", nil), root, "/../secret.js") {
		t.Fatal("servePrecompressed accepted a ../ path")
	}
}

func TestPortalServesPrecompressedAsset(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "index.html"), []byte("<html>portal</html>"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "assets", "app-AbCdEf12.js"), []byte("plain"), 0o644)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte(precompressedMarker))
	_ = writer.Close()
	_ = os.WriteFile(filepath.Join(root, "assets", "app-AbCdEf12.js.gz"), compressed.Bytes(), 0o644)
	upstream, _ := url.Parse("http://127.0.0.1:8080")
	handler, err := newHandlerWithOptions(testStaticRoot(t), upstream, handlerOptions{PortalStaticRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	response := getStatic(handler, "/console/assets/app-AbCdEf12.js", "gzip")
	if response.Header().Get("Content-Encoding") != "gzip" || gunzipBody(t, response.Body.Bytes()) != precompressedMarker {
		t.Fatalf("headers = %v", response.Header())
	}
}
