package main

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 构建期同时写 .br；浏览器接受 br 且文件存在时直接发 .br（比 gzip 小约 15%），
// 否则仍走 .gz / 现压 / 原文，行为与原先一致。
const brotliMarker = "brotli-on-disk"

func brotliHandler(t *testing.T) http.Handler {
	t.Helper()
	handler, root := precompressedHandler(t)
	if err := os.WriteFile(filepath.Join(root, "assets", "index-12345678.js.br"), []byte(brotliMarker), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(root), "secret.js.br"), []byte(brotliMarker), 0o644); err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestStaticServesBrotliWhenAccepted(t *testing.T) {
	handler := brotliHandler(t)
	for _, encoding := range []string{"gzip, deflate, br", "br", "br;q=0.9, gzip;q=1", "BR"} {
		response := getStatic(handler, "/dashboard/assets/index-12345678.js", encoding)
		header := response.Header()
		if response.Code != http.StatusOK || header.Get("Content-Encoding") != "br" || header.Get("Vary") != "Accept-Encoding" ||
			!strings.Contains(header.Get("Content-Type"), "javascript") ||
			header.Get("Cache-Control") != "public, max-age=31536000, immutable" || response.Body.String() != brotliMarker {
			t.Fatalf("encoding %q: status=%d headers=%v body=%q", encoding, response.Code, header, response.Body.String())
		}
	}
}

func TestStaticBrotliFallsBackToGzip(t *testing.T) {
	handler := brotliHandler(t)
	for _, encoding := range []string{"gzip", "gzip, br;q=0"} {
		response := getStatic(handler, "/dashboard/assets/index-12345678.js", encoding)
		if response.Header().Get("Content-Encoding") != "gzip" || gunzipBody(t, response.Body.Bytes()) != precompressedMarker {
			t.Fatalf("encoding %q: headers=%v", encoding, response.Header())
		}
	}
	// No .br on disk: a br-capable browser still gets the .gz.
	handler, _ = precompressedHandler(t)
	response := getStatic(handler, "/dashboard/assets/index-12345678.js", "gzip, br")
	if response.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("headers = %v", response.Header())
	}
}

func TestStaticBrotliRejectsTraversalAndRange(t *testing.T) {
	handler := brotliHandler(t)
	for _, target := range []string{"/assets/../../secret.js", "/dashboard/../../secret.js", "/dashboard/assets/../../secret.js"} {
		if response := getStatic(handler, target, "br"); strings.Contains(response.Body.String(), brotliMarker) {
			t.Fatalf("%s leaked a file outside the root", target)
		}
	}
	request, _ := http.NewRequest(http.MethodGet, "/dashboard/assets/index-12345678.js", nil)
	request.Header.Set("Accept-Encoding", "br")
	request.Header.Set("Range", "bytes=0-3")
	if acceptsEncoding(request, "br") {
		t.Fatal("a Range request must get the identity file")
	}
}

func TestPortalServesBrotliAsset(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "index.html"), []byte("<html>portal</html>"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "assets", "app-AbCdEf12.js"), []byte("plain"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "assets", "app-AbCdEf12.js.br"), []byte(brotliMarker), 0o644)
	upstream, _ := url.Parse("http://127.0.0.1:8080")
	handler, err := newHandlerWithOptions(testStaticRoot(t), upstream, handlerOptions{PortalStaticRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	response := getStatic(handler, "/console/assets/app-AbCdEf12.js", "gzip, br")
	if response.Header().Get("Content-Encoding") != "br" || response.Body.String() != brotliMarker {
		t.Fatalf("headers = %v body=%q", response.Header(), response.Body.String())
	}
}
