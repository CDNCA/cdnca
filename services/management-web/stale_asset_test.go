package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// fix-cfl-c：发版后旧标签页请求已删除的哈希分块，
// 必须得到 404，而不是 200 的 index.html（浏览器按 JS 解析 HTML 会报 MIME 错误）。
func TestMissingHashedAssetIsNotFoundInsteadOfIndex(t *testing.T) {
	upstream, _ := url.Parse("http://127.0.0.1:8080")
	handler, err := newHandler(testStaticRoot(t), upstream)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/operator/assets/CustomersPage-0ldHash12.js", "/assets/index-0ldHash12.css", "/dashboard/assets/x-0ldHash12.js"} {
		response := serve(handler, http.MethodGet, target, "203.0.113.9:1", nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404 (body %q)", target, response.Code, response.Body.String())
		}
		if got := response.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s cache control = %q, want no-store", target, got)
		}
	}
	// 页面路由仍回 index.html。
	if response := serve(handler, http.MethodGet, "/operator/customers", "203.0.113.9:1", nil); response.Code != http.StatusOK || response.Body.String() != "<html>shell</html>" {
		t.Fatalf("route fallback = %d %q", response.Code, response.Body.String())
	}
}

// fix-cfl-c：授权端 management-web 直接监听 443，前面没有 nginx，
// 页面与接口响应都要带基本安全响应头；上游已给的值不被覆盖或重复。
func TestSecurityHeadersOnStaticAndProxiedResponses(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstreamServer.Close)
	upstream, _ := url.Parse(upstreamServer.URL)
	handler, err := newHandler(testStaticRoot(t), upstream)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Strict-Transport-Security": "max-age=31536000",
	}
	for _, target := range []string{"/operator/", "/operator/assets/index-12345678.js", "/operator/assets/missing-12345678.js", "/health/live"} {
		response := serve(handler, http.MethodGet, target, "203.0.113.9:1", nil)
		for name, value := range want {
			if got := response.Header().Values(name); len(got) != 1 || got[0] != value {
				t.Fatalf("%s %s = %q, want [%q]", target, name, got, value)
			}
		}
	}
	proxied := serve(handler, http.MethodGet, "/operator/v1/session", "203.0.113.9:1", nil)
	if proxied.Code != http.StatusNoContent {
		t.Fatalf("proxied status = %d", proxied.Code)
	}
	for name, value := range map[string]string{"Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
		"X-Frame-Options": "DENY", "Strict-Transport-Security": "max-age=31536000"} {
		if got := proxied.Header().Values(name); len(got) != 1 || got[0] != value {
			t.Fatalf("proxied %s = %q, want [%q]", name, got, value)
		}
	}
}
