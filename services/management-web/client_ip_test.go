package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testOriginSecret = "0123456789abcdef0123456789abcdef-origin"

func cdnResolver(realIPHeader string) clientIPResolver {
	return clientIPResolver{authHeader: defaultOriginAuthHeader, secret: []byte(testOriginSecret), realIPHeader: realIPHeader}
}

func TestClientIPResolution(t *testing.T) {
	cases := []struct {
		name     string
		resolver clientIPResolver
		remote   string
		headers  map[string][]string
		want     string
		source   string
	}{
		{"no secret configured ignores headers", clientIPResolver{authHeader: defaultOriginAuthHeader}, "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "Cf-Connecting-Ip": {"198.51.100.7"}}, "203.0.113.9", "tcp"},
		{"forged real-ip without key", cdnResolver("CF-Connecting-IP"), "203.0.113.9:1",
			map[string][]string{"Cf-Connecting-Ip": {"198.51.100.7"}}, "203.0.113.9", "tcp"},
		{"wrong key", cdnResolver("CF-Connecting-IP"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret + "x"}, "Cf-Connecting-Ip": {"198.51.100.7"}}, "203.0.113.9", "tcp"},
		{"duplicated key header", cdnResolver("CF-Connecting-IP"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret, testOriginSecret}, "Cf-Connecting-Ip": {"198.51.100.7"}}, "203.0.113.9", "tcp"},
		{"valid key", cdnResolver("CF-Connecting-IP"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "Cf-Connecting-Ip": {"198.51.100.7"}}, "198.51.100.7", "cdn"},
		{"valid key ipv6", cdnResolver("True-Client-IP"), "[2001:db8::9]:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "True-Client-Ip": {"2001:db8::7"}}, "2001:db8::7", "cdn"},
		{"ipv4-mapped is unmapped", cdnResolver("X-Real-IP"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "X-Real-Ip": {"::ffff:198.51.100.7"}}, "198.51.100.7", "cdn"},
		{"xff single hop", cdnResolver("X-Forwarded-For"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "X-Forwarded-For": {"198.51.100.7"}}, "198.51.100.7", "cdn"},
		// The client forged the left side; the CDN appended the real source on the right.
		{"xff forged left, cdn appended right", cdnResolver("X-Forwarded-For"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "X-Forwarded-For": {"192.0.2.66, 192.0.2.67, 198.51.100.7"}}, "198.51.100.7", "cdn"},
		{"xff multiple header lines take the last hop", cdnResolver("X-Forwarded-For"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "X-Forwarded-For": {"192.0.2.66, 192.0.2.1", "198.51.100.7"}}, "198.51.100.7", "cdn"},
		{"xff right-most ipv6", cdnResolver("X-Forwarded-For"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "X-Forwarded-For": {"192.0.2.66,2001:db8::7"}}, "2001:db8::7", "cdn"},
		{"xff forged unparsable left is ignored", cdnResolver("X-Forwarded-For"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "X-Forwarded-For": {"unknown, 198.51.100.7"}}, "198.51.100.7", "cdn"},
		{"xff right-most unparsable falls back", cdnResolver("X-Forwarded-For"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "X-Forwarded-For": {"198.51.100.7, unknown"}}, "203.0.113.9", "tcp"},
		{"xff oversized falls back", cdnResolver("X-Forwarded-For"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "X-Forwarded-For": {strings.Repeat("192.0.2.66, ", 100) + "198.51.100.7"}}, "203.0.113.9", "tcp"},
		{"non-xff header with two values falls back", cdnResolver("CF-Connecting-IP"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "Cf-Connecting-Ip": {"198.51.100.7", "198.51.100.8"}}, "203.0.113.9", "tcp"},
		{"non-xff header with a list falls back", cdnResolver("CF-Connecting-IP"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "Cf-Connecting-Ip": {"198.51.100.7, 198.51.100.8"}}, "203.0.113.9", "tcp"},
		{"zone rejected", cdnResolver("X-Real-IP"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}, "X-Real-Ip": {"fe80::1%eth0"}}, "203.0.113.9", "tcp"},
		{"key but header missing", cdnResolver("CF-Connecting-IP"), "203.0.113.9:1",
			map[string][]string{defaultOriginAuthHeader: {testOriginSecret}}, "203.0.113.9", "tcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = tc.remote
			for name, values := range tc.headers {
				request.Header[http.CanonicalHeaderKey(name)] = values
			}
			address, source, ok := tc.resolver.resolve(request)
			if !ok || address.String() != tc.want || source != tc.source {
				t.Fatalf("resolve = %v %s %v, want %s %s", address, source, ok, tc.want, tc.source)
			}
		})
	}
}

func TestLoadOriginAuthSecret(t *testing.T) {
	dir := t.TempDir()
	if _, enabled, err := loadOriginAuthSecret(filepath.Join(dir, "missing")); err != nil || enabled {
		t.Fatalf("missing file: enabled=%v err=%v, want disabled", enabled, err)
	}
	write := func(name, content string, mode os.FileMode) string {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		return file
	}
	if _, _, err := loadOriginAuthSecret(write("short", "too-short\n", 0o600)); err == nil {
		t.Fatal("short secret accepted")
	}
	if _, _, err := loadOriginAuthSecret(write("open", testOriginSecret, 0o644)); err == nil {
		t.Fatal("world-readable secret accepted")
	}
	secret, enabled, err := loadOriginAuthSecret(write("ok", testOriginSecret+"\n", 0o600))
	if err != nil || !enabled || string(secret) != testOriginSecret {
		t.Fatalf("ok: %q %v %v", secret, enabled, err)
	}
}

type seenUpstream struct {
	realIP, xff, key, cf string
	calls                int
}

func cdnHandler(t *testing.T, resolver clientIPResolver, authorization *url.URL) (http.Handler, *seenUpstream) {
	t.Helper()
	seen := &seenUpstream{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		seen.calls++
		seen.realIP = request.Header.Get("X-Real-IP")
		seen.xff = strings.Join(request.Header.Values("X-Forwarded-For"), "|")
		seen.key = request.Header.Get(defaultOriginAuthHeader)
		seen.cf = request.Header.Get("CF-Connecting-IP")
		response.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	upstream, _ := url.Parse(server.URL)
	handler, err := newHandlerWithOptions(downloadRoot(t), upstream, handlerOptions{
		ClientIP: resolver, MasterDownloadAuthorization: authorization})
	if err != nil {
		t.Fatal(err)
	}
	return handler, seen
}

func TestProxyForwardsCDNClientAndStripsOriginKey(t *testing.T) {
	handler, seen := cdnHandler(t, cdnResolver("CF-Connecting-IP"), nil)
	response := serve(handler, http.MethodPost, "/activation/v1/installations:activate", "203.0.113.9:1", map[string]string{
		defaultOriginAuthHeader: testOriginSecret, "CF-Connecting-IP": "198.51.100.7",
		"X-Forwarded-For": "192.0.2.66", "X-Real-IP": "192.0.2.66"})
	// ReverseProxy appends RemoteAddr after the Director; every hop is the client.
	for _, hop := range strings.Split(seen.xff, ",") {
		if strings.TrimSpace(hop) != "198.51.100.7" {
			t.Fatalf("xff hop %q in %q", hop, seen.xff)
		}
	}
	if response.Code != http.StatusOK || seen.realIP != "198.51.100.7" || seen.key != "" || seen.cf != "" {
		t.Fatalf("status=%d upstream saw %+v", response.Code, *seen)
	}
}

func TestProxyIgnoresForgedRealIPWithWrongKey(t *testing.T) {
	handler, seen := cdnHandler(t, cdnResolver("CF-Connecting-IP"), nil)
	response := serve(handler, http.MethodPost, "/activation/v1/installations:activate", "203.0.113.9:1", map[string]string{
		defaultOriginAuthHeader: "wrong-wrong-wrong-wrong-wrong-wrong", "CF-Connecting-IP": "198.51.100.7",
		"X-Forwarded-For": "198.51.100.7"})
	if response.Code != http.StatusOK || seen.realIP != "203.0.113.9" || strings.Contains(seen.xff, "198.51.100.7") ||
		seen.key != "" || seen.cf != "" {
		t.Fatalf("status=%d upstream saw %+v", response.Code, *seen)
	}
}

// Without a secret the origin-auth header is still removed, and behaviour is
// otherwise the pre-T2 one (TestAPIProxyOverwritesClientForwardingHeaders).
func TestProxyWithoutSecretStripsOriginKeyOnly(t *testing.T) {
	handler, seen := cdnHandler(t, clientIPResolver{authHeader: defaultOriginAuthHeader}, nil)
	response := serve(handler, http.MethodPost, "/activation/v1/installations:activate", "203.0.113.9:1", map[string]string{
		defaultOriginAuthHeader: testOriginSecret, "CF-Connecting-IP": "198.51.100.7"})
	if response.Code != http.StatusOK || seen.realIP != "203.0.113.9" || seen.key != "" {
		t.Fatalf("status=%d upstream saw %+v", response.Code, *seen)
	}
}

func TestMasterDownloadUsesCDNClient(t *testing.T) {
	stub := newAuthorizationStub(t, http.StatusNoContent)
	handler, _ := cdnHandler(t, cdnResolver("X-Forwarded-For"), stub.url(t))
	response := serve(handler, http.MethodGet, "/downloads/control-api/latest/SHA256SUMS", "203.0.113.9:4000", map[string]string{
		defaultOriginAuthHeader: testOriginSecret, "X-Forwarded-For": "192.0.2.66, 2001:db8::7"})
	if response.Code != http.StatusOK || len(stub.realIPs) != 1 || stub.realIPs[0] != "2001:db8::7" || stub.xffs[0] != "2001:db8::7" {
		t.Fatalf("status=%d authorization saw real-ip=%v xff=%v", response.Code, stub.realIPs, stub.xffs)
	}
	forged := serve(handler, http.MethodGet, "/downloads/control-api/latest/SHA256SUMS", "203.0.113.9:4000", map[string]string{
		"X-Forwarded-For": "2001:db8::7"})
	if forged.Code != http.StatusOK || stub.realIPs[1] != "203.0.113.9" {
		t.Fatalf("forged: status=%d authorization saw %v", forged.Code, stub.realIPs)
	}
}
