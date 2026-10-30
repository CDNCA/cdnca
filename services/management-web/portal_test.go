package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type capturedRequest struct {
	method, uri, origin, cookie, realIP, xff, host, body string
}

func portalRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"index.html":                "<html>portal</html>",
		"assets/index-AbCdEf12.js":  strings.Repeat("const portal = true;\n", 50),
		"assets/index-AbCdEf12.css": "body{}",
		"assets/plain.txt":          "plain",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func portalHandler(t *testing.T, portal string) (http.Handler, *[]capturedRequest) {
	t.Helper()
	seen := &[]capturedRequest{}
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		*seen = append(*seen, capturedRequest{method: request.Method, uri: request.URL.RequestURI(),
			origin: request.Header.Get("Origin"), cookie: request.Header.Get("Cookie"), realIP: request.Header.Get("X-Real-IP"),
			xff: strings.Join(request.Header.Values("X-Forwarded-For"), "|"), host: request.Header.Get("X-Forwarded-Host"),
			body: string(body)})
		response.Header().Set("Content-Type", "application/json")
		response.Header().Add("Set-Cookie", "__Secure-cdnca_portal_session=new; Path=/portal/v1; Secure; HttpOnly; SameSite=Strict")
		_, _ = io.WriteString(response, `{"items":[]}`)
	}))
	t.Cleanup(upstreamServer.Close)
	upstream, _ := url.Parse(upstreamServer.URL)
	// The operator console root is named operator-console in production.
	operatorRoot := filepath.Join(t.TempDir(), "operator-console")
	if err := os.MkdirAll(operatorRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(operatorRoot, "index.html"), []byte("<html>operator</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler, err := newHandlerWithOptions(operatorRoot, upstream, handlerOptions{PortalStaticRoot: portal})
	if err != nil {
		t.Fatal(err)
	}
	return handler, seen
}

func TestPortalAPIIsProxiedWithCookieAndOrigin(t *testing.T) {
	handler, seen := portalHandler(t, portalRoot(t))
	request := httptest.NewRequest(http.MethodPost, "https://auth.cdnca.com/portal/v1/licenses/abc/download-ip?x=1",
		strings.NewReader(`{"ip":"198.51.100.7"}`))
	request.RemoteAddr = "203.0.113.9:5000"
	request.Header.Set("Origin", "https://auth.cdnca.com")
	request.Header.Set("Cookie", "__Secure-cdnca_portal_session=s3cr3t")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", "198.51.100.7")
	request.Header.Set("X-Real-IP", "198.51.100.7")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(*seen) != 1 {
		t.Fatalf("status=%d upstream calls=%d", response.Code, len(*seen))
	}
	got := (*seen)[0]
	if got.method != http.MethodPost || got.uri != "/portal/v1/licenses/abc/download-ip?x=1" ||
		got.origin != "https://auth.cdnca.com" || got.cookie != "__Secure-cdnca_portal_session=s3cr3t" ||
		got.body != `{"ip":"198.51.100.7"}` || got.realIP != "203.0.113.9" || strings.Contains(got.xff, "198.51.100.7") ||
		got.host != "auth.cdnca.com" {
		t.Fatalf("upstream saw %+v", got)
	}
	if cookie := response.Header().Get("Set-Cookie"); !strings.Contains(cookie, "Path=/portal/v1") {
		t.Fatalf("set-cookie not passed back: %q", cookie)
	}
}

func TestPortalAPIIsProxiedWithoutPortalStaticDir(t *testing.T) {
	handler, seen := portalHandler(t, "")
	response := serve(handler, http.MethodGet, "/portal/v1/plans", "203.0.113.9:1", nil)
	if response.Code != http.StatusOK || len(*seen) != 1 || !strings.Contains(response.Body.String(), "items") {
		t.Fatalf("status=%d calls=%d body=%q", response.Code, len(*seen), response.Body.String())
	}
}

func TestPortalStaticRoutes(t *testing.T) {
	handler, seen := portalHandler(t, portalRoot(t))
	redirect := serve(handler, http.MethodGet, "/console?next=1", "203.0.113.9:1", nil)
	if redirect.Code != http.StatusPermanentRedirect || redirect.Header().Get("Location") != "/console/?next=1" {
		t.Fatalf("redirect status=%d location=%q", redirect.Code, redirect.Header().Get("Location"))
	}
	for _, target := range []string{"/console/", "/console/register", "/console/licenses/abc", "/console/portal/v1/plans"} {
		response := serve(handler, http.MethodGet, target, "203.0.113.9:1", nil)
		if response.Code != http.StatusOK || response.Body.String() != "<html>portal</html>" ||
			response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: status=%d cache=%q body=%q", target, response.Code, response.Header().Get("Cache-Control"), response.Body.String())
		}
	}
	asset := serve(handler, http.MethodGet, "/console/assets/index-AbCdEf12.js", "203.0.113.9:1", nil)
	if asset.Code != http.StatusOK || asset.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" ||
		!strings.Contains(asset.Body.String(), "const portal") {
		t.Fatalf("asset status=%d cache=%q", asset.Code, asset.Header().Get("Cache-Control"))
	}
	if css := serve(handler, http.MethodGet, "/console/assets/index-AbCdEf12.css", "203.0.113.9:1", nil); !strings.Contains(css.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("css content type %q", css.Header().Get("Content-Type"))
	}
	if plain := serve(handler, http.MethodGet, "/console/assets/plain.txt", "203.0.113.9:1", nil); plain.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unhashed asset cache=%q", plain.Header().Get("Cache-Control"))
	}
	for _, target := range []string{"/console/assets/missing-AbCdEf12.js", "/console/assets/../index.html", "/console/assets/"} {
		if response := serve(handler, http.MethodGet, target, "203.0.113.9:1", nil); response.Code != http.StatusNotFound ||
			strings.Contains(response.Body.String(), "<html>") {
			t.Fatalf("%s: status=%d body=%q", target, response.Code, response.Body.String())
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("static routes reached the upstream %d times", len(*seen))
	}
}

func TestOperatorRoutesUnaffectedByPortal(t *testing.T) {
	for _, portal := range []string{"", "set"} {
		root := ""
		if portal != "" {
			root = portalRoot(t)
		}
		handler, seen := portalHandler(t, root)
		// With the portal mounted, / is the unified sign-in page (see
		// TestUnifiedLoginEntry); without it / stays /operator/ and the
		// operator login page is served by the operator console.
		if portal == "" {
			if response := serve(handler, http.MethodGet, "/", "203.0.113.9:1", nil); response.Code != http.StatusFound ||
				response.Header().Get("Location") != "/operator/" {
				t.Fatalf("root redirect status=%d location=%q", response.Code, response.Header().Get("Location"))
			}
			if response := serve(handler, http.MethodGet, "/operator/login", "203.0.113.9:1", nil); response.Body.String() != "<html>operator</html>" {
				t.Fatalf("operator login body=%q", response.Body.String())
			}
		}
		if response := serve(handler, http.MethodGet, "/operator/customers", "203.0.113.9:1", nil); response.Body.String() != "<html>operator</html>" {
			t.Fatalf("operator spa body=%q", response.Body.String())
		}
		if response := serve(handler, http.MethodGet, "/operator/v1/session", "203.0.113.9:1", nil); response.Code != http.StatusOK || len(*seen) != 1 {
			t.Fatalf("operator api status=%d calls=%d", response.Code, len(*seen))
		}
		// Without the portal root, /console keeps the old operator fallback.
		if portal == "" {
			if response := serve(handler, http.MethodGet, "/console/login", "203.0.113.9:1", nil); response.Body.String() != "<html>operator</html>" {
				t.Fatalf("console without portal body=%q", response.Body.String())
			}
		}
	}
}

func TestUnifiedLoginEntry(t *testing.T) {
	handler, seen := portalHandler(t, portalRoot(t))
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		root := serve(handler, method, "/?next=%2Fconsole%2Forders", "203.0.113.9:1", nil)
		if root.Code != http.StatusOK || root.Header().Get("Cache-Control") != "no-store" ||
			(method == http.MethodGet && root.Body.String() != "<html>portal</html>") {
			t.Fatalf("%s /: status=%d cache=%q body=%q", method, root.Code, root.Header().Get("Cache-Control"), root.Body.String())
		}
	}
	for target, want := range map[string]string{
		"/console/login":  "/",
		"/operator/login": "/",
		"/console/login?next=%2Fconsole%2Forders%3Fpage%3D2":   "/?next=%2Fconsole%2Forders%3Fpage%3D2",
		"/operator/login?next=/operator/customers/abc":         "/?next=%2Foperator%2Fcustomers%2Fabc",
		"/operator/login?next=/operator/":                      "/?next=%2Foperator%2F",
		"/operator/login?next=//evil.example/operator/":        "/",
		"/operator/login?next=https://evil.example/operator/":  "/",
		"/operator/login?next=/%5Cevil.example":                "/",
		"/operator/login?next=%2F%5Cevil.example%2Fconsole%2F": "/",
		"/console/login?next=javascript:alert(1)":              "/",
		"/console/login?next=/elsewhere":                       "/",
		"/console/login?next=/console/../admin":                "/",
		"/console/login?next=/console/login":                   "/",
		"/console/login?next=/operator/login%3Fnext%3D%2F":     "/",
		"/console/login?next=%2Fconsole%2F%0d%0aSet-Cookie":    "/",
	} {
		response := serve(handler, http.MethodGet, target, "203.0.113.9:1", nil)
		if response.Code != http.StatusFound || response.Header().Get("Location") != want {
			t.Fatalf("%s: status=%d location=%q want %q", target, response.Code, response.Header().Get("Location"), want)
		}
	}
	// Other portal and operator pages are unchanged and nothing reaches the API.
	if response := serve(handler, http.MethodGet, "/console/forgot-password", "203.0.113.9:1", nil); response.Body.String() != "<html>portal</html>" {
		t.Fatalf("portal forgot-password body=%q", response.Body.String())
	}
	if response := serve(handler, http.MethodGet, "/operator/reset-password", "203.0.113.9:1", nil); response.Body.String() != "<html>operator</html>" {
		t.Fatalf("operator reset-password body=%q", response.Body.String())
	}
	if len(*seen) != 0 {
		t.Fatalf("entry routes reached the upstream %d times", len(*seen))
	}
	// The unified sign-in API is proxied to license-service.
	if response := serve(handler, http.MethodPost, "/auth/v1/sessions", "203.0.113.9:1", nil); response.Code != http.StatusOK || len(*seen) != 1 {
		t.Fatalf("auth api status=%d calls=%d", response.Code, len(*seen))
	}
}
