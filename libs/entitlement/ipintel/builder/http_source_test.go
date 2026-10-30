package builder

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testdata/dnspup-snapshot-pull.ndjson.gz is real dnspup output (snapshot
// endpoint / cmd/ipintel-export, parity test fixture) with RIPE RIS,
// PeeringDB and Tor sources and tor rows.
// Obviously fake dnspup customer API credentials.
const (
	pullFixtureRelease = "ipx-98a5f2c77cd73826d2800b2f"
	pullTestAPIKey     = "dnp_key_fake_pull_0000000000000000"
	pullTestAPISecret  = "dnp_secret_fake_pull_00000000000000000000000000"
	pullTestURL        = "https://api.dnspup.com/v1/tools/ip-intel-snapshot"
)

func pullFixture(t *testing.T, edit func(string) string) []byte {
	t.Helper()
	compressed, err := os.ReadFile("testdata/dnspup-snapshot-pull.ndjson.gz")
	if err != nil {
		t.Fatal(err)
	}
	if edit == nil {
		return compressed
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	_, _ = writer.Write([]byte(edit(string(plain))))
	_ = writer.Close()
	return out.Bytes()
}

func TestDnspupSnapshotWithRoutingAndTorSources(t *testing.T) {
	collection, release, err := ParseDnspupSnapshot(bytes.NewReader(pullFixture(t, nil)), DefaultFileSourceMaxBytes)
	if err != nil || release != pullFixtureRelease {
		t.Fatalf("parse: %s %v", release, err)
	}
	ids := map[string]bool{}
	for _, source := range collection.Sources {
		ids[source.ID] = true
	}
	for _, id := range []string{"ripe-ris", "peeringdb", "tor-exitlist", "ip2region-v4", "dnspup-ip-library"} {
		if !ids[id] {
			t.Fatalf("source %s missing: %v", id, ids)
		}
	}
	if !strings.Contains(collection.Notice, "Tor Project bulk exit list") || !strings.Contains(collection.Notice, "RIPE NCC") {
		t.Fatalf("notice lacks attribution: %s", collection.Notice)
	}
}

func TestNewHTTPSourceValidates(t *testing.T) {
	good := HTTPSourceConfig{URL: pullTestURL, APIKey: pullTestAPIKey, APISecret: pullTestAPISecret}
	for name, edit := range map[string]func(*HTTPSourceConfig){
		"http remote":    func(c *HTTPSourceConfig) { c.URL = "http://api.dnspup.com/v1/tools/ip-intel-snapshot" },
		"userinfo":       func(c *HTTPSourceConfig) { c.URL = "https://user:pass@api.dnspup.com/x" },
		"fragment":       func(c *HTTPSourceConfig) { c.URL = "https://api.dnspup.com/x#frag" },
		"no host":        func(c *HTTPSourceConfig) { c.URL = "https:///x" },
		"no key":         func(c *HTTPSourceConfig) { c.APIKey = "" },
		"short key":      func(c *HTTPSourceConfig) { c.APIKey = "short" },
		"no secret":      func(c *HTTPSourceConfig) { c.APISecret = "" },
		"short secret":   func(c *HTTPSourceConfig) { c.APISecret = "dnp_secret_x" },
		"space secret":   func(c *HTTPSourceConfig) { c.APISecret = strings.Repeat("a", 20) + " " + strings.Repeat("b", 20) },
		"unicode secret": func(c *HTTPSourceConfig) { c.APISecret = strings.Repeat("令", 40) },
		"newline key":    func(c *HTTPSourceConfig) { c.APIKey = pullTestAPIKey + "\nX-Evil: 1" },
	} {
		config := good
		edit(&config)
		_, err := NewHTTPSource(config)
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		for _, secret := range []string{config.APISecret, config.APIKey} {
			if len(secret) > 8 && strings.Contains(err.Error(), secret) {
				t.Errorf("%s: error leaks a credential: %v", name, err)
			}
		}
	}
	for _, url := range []string{pullTestURL, "http://127.0.0.1:8787/x", "http://localhost/x", "http://[::1]/x"} {
		config := good
		config.URL = url
		if _, err := NewHTTPSource(config); err != nil {
			t.Errorf("%s rejected: %v", url, err)
		}
	}
}

// fakeDnspup imitates the dnspup customer API tool
// GET/HEAD /v1/tools/ip-intel-snapshot (error envelope + X-API-Error-Code).
type fakeDnspup struct {
	body        []byte
	status      int
	code        string
	codeInBody  bool // only the JSON body carries the code
	etag        string
	header      map[string]string
	lastKey     string
	lastSecret  string
	lastAuth    string
	lastIfNone  string
	lastMethod  string
	contentSize string
	chunked     bool // flush first: no Content-Length
}

func (f *fakeDnspup) apiError(w http.ResponseWriter, status int, code string) {
	if !f.codeInBody {
		w.Header().Set("X-API-Error-Code", code)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":{"code":"` + code + `","message":"x"}}`))
}

func (f *fakeDnspup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.lastKey, f.lastSecret = r.Header.Get("X-API-Key"), r.Header.Get("X-API-Secret")
	f.lastAuth, f.lastIfNone, f.lastMethod = r.Header.Get("Authorization"), r.Header.Get("If-None-Match"), r.Method
	if f.lastKey != pullTestAPIKey || f.lastSecret != pullTestAPISecret {
		f.apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	for key, value := range f.header {
		w.Header().Set(key, value)
	}
	if f.status != 0 && f.status != http.StatusOK {
		if f.code != "" {
			f.apiError(w, f.status, f.code)
			return
		}
		w.WriteHeader(f.status)
		return
	}
	etag := f.etag
	if etag == "" {
		etag = pullFixtureRelease
	}
	w.Header().Set("ETag", `"`+etag+`"`)
	w.Header().Set("X-IP-Intel-Release", etag)
	if r.Header.Get("If-None-Match") == `"`+etag+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	if r.Method == http.MethodHead {
		w.Header().Set("X-IP-Intel-Status", "ready")
		w.Header().Set("Content-Length", strconv.Itoa(len(f.body)))
		w.WriteHeader(http.StatusOK)
		return
	}
	if f.contentSize != "" {
		w.Header().Set("Content-Length", f.contentSize)
	}
	if f.chunked {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
	}
	_, _ = w.Write(f.body)
}

func sourceFor(t *testing.T, handler http.Handler, secret string, maxBytes int64) *HTTPSource {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	source, err := NewHTTPSource(HTTPSourceConfig{URL: server.URL + "/v1/tools/ip-intel-snapshot", APIKey: pullTestAPIKey,
		APISecret: secret, Timeout: 5 * time.Second, MaxBytes: maxBytes})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func fetchFrom(t *testing.T, handler http.Handler, secret, known string, maxBytes int64) (FetchResult, error) {
	t.Helper()
	return sourceFor(t, handler, secret, maxBytes).Fetch(context.Background(), known)
}

func TestHTTPSourceFetch(t *testing.T) {
	fake := &fakeDnspup{body: pullFixture(t, nil)}
	result, err := fetchFrom(t, fake, pullTestAPISecret, "", 0)
	if err != nil || result.NotModified || result.Release != pullFixtureRelease || result.Status != 200 ||
		len(result.SHA256) != 64 || result.Bytes != int64(len(fake.body)) || len(result.Collection.Facts) == 0 {
		t.Fatalf("200: %+v %v", result.Release, err)
	}
	if fake.lastKey != pullTestAPIKey || fake.lastSecret != pullTestAPISecret || fake.lastAuth != "" || fake.lastIfNone != "" || fake.lastMethod != "GET" {
		t.Fatalf("headers: key %q auth %q inm %q %s", fake.lastKey, fake.lastAuth, fake.lastIfNone, fake.lastMethod)
	}
	// Known release current: 304, If-None-Match sent.
	result, err = fetchFrom(t, fake, pullTestAPISecret, pullFixtureRelease, 0)
	if err != nil || !result.NotModified || result.Release != pullFixtureRelease || fake.lastIfNone != `"`+pullFixtureRelease+`"` {
		t.Fatalf("304: %+v %v (If-None-Match %q)", result, err, fake.lastIfNone)
	}
}

func TestHTTPSourceProbe(t *testing.T) {
	fake := &fakeDnspup{body: pullFixture(t, nil)}
	probe, err := sourceFor(t, fake, pullTestAPISecret, 0).Probe(context.Background())
	if err != nil || probe.Status != 200 || probe.Release != pullFixtureRelease || probe.State != "ready" ||
		probe.Bytes != int64(len(fake.body)) || fake.lastMethod != http.MethodHead || fake.lastIfNone != "" {
		t.Fatalf("probe: %+v %v (%s)", probe, err, fake.lastMethod)
	}
	// HEAD carries no body: the code comes from X-API-Error-Code.
	for _, test := range []struct {
		fake *fakeDnspup
		want error
		code string
	}{
		{&fakeDnspup{status: 403, code: "source_forbidden"}, ErrSourceForbidden, "source_forbidden"},
		{&fakeDnspup{status: 403, code: "tool_not_allowed"}, ErrSourceToolNotAllowed, "tool_not_allowed"},
		{&fakeDnspup{status: 503, code: "service_unavailable", header: map[string]string{"Retry-After": "3600"}}, ErrSourcePending, "service_unavailable"},
	} {
		probe, err := sourceFor(t, test.fake, pullTestAPISecret, 0).Probe(context.Background())
		if !errors.Is(err, test.want) || probe.ErrorCode != test.code {
			t.Errorf("probe %s: %+v %v", test.code, probe, err)
		}
	}
	if _, err := sourceFor(t, fake, "dnp_secret_fake_wrong_000000000000000000000000", 0).Probe(context.Background()); !errors.Is(err, ErrSourceAuth) {
		t.Fatalf("probe wrong secret: %v", err)
	}
}

func TestHTTPSourceFetchFailures(t *testing.T) {
	body := pullFixture(t, nil)
	wrongSecret := "dnp_secret_fake_wrong_000000000000000000000000"
	cases := []struct {
		name    string
		fake    *fakeDnspup
		secret  string
		max     int64
		want    error
		code    string
		pending time.Duration
	}{
		{name: "wrong secret", fake: &fakeDnspup{body: body}, secret: wrongSecret, want: ErrSourceAuth, code: "unauthorized"},
		{name: "code in body only", fake: &fakeDnspup{body: body, codeInBody: true}, secret: wrongSecret, want: ErrSourceAuth, code: "unauthorized"},
		{name: "domain-bound key", fake: &fakeDnspup{status: 401, code: "signature_required"}, want: ErrSourceDomainBinding, code: "signature_required"},
		{name: "source ip", fake: &fakeDnspup{status: 403, code: "source_forbidden"}, want: ErrSourceForbidden, code: "source_forbidden"},
		{name: "tool", fake: &fakeDnspup{status: 403, code: "tool_not_allowed"}, want: ErrSourceToolNotAllowed, code: "tool_not_allowed"},
		{name: "quota", fake: &fakeDnspup{status: 429, code: "quota_exceeded"}, want: ErrSourceQuota, code: "quota_exceeded"},
		{name: "content-length over limit", fake: &fakeDnspup{body: body}, max: int64(len(body)) - 1, want: ErrSourceTooLarge},
		{name: "streamed over limit", fake: &fakeDnspup{body: body, chunked: true}, max: int64(len(body)) - 1, want: ErrSourceTooLarge},
		{name: "generating", fake: &fakeDnspup{status: 503, code: "snapshot_generating", header: map[string]string{"Retry-After": "120", "X-IP-Intel-Status": "generating"}},
			want: ErrSourcePending, code: "snapshot_generating", pending: 120 * time.Second},
		{name: "busy", fake: &fakeDnspup{status: 429, code: "snapshot_busy", header: map[string]string{"Retry-After": "60"}}, want: ErrSourcePending,
			code: "snapshot_busy", pending: time.Minute},
		{name: "rate limited", fake: &fakeDnspup{status: 429, code: "rate_limited", header: map[string]string{"Retry-After": "60"}}, want: ErrSourcePending,
			code: "rate_limited", pending: time.Minute},
		{name: "server error", fake: &fakeDnspup{status: 500, code: "internal_error"}, want: ErrSourceUnreachable, code: "internal_error"},
		{name: "redirect not followed", fake: &fakeDnspup{status: 302, header: map[string]string{"Location": "https://evil.example/"}}, want: ErrSourceUnreachable},
		{name: "etag mismatch", fake: &fakeDnspup{body: body, etag: "ipx-000000000000000000000000"}, want: ErrSource},
		{name: "not gzip", fake: &fakeDnspup{body: []byte("<html>proxy error</html>")}, want: ErrSource},
		{name: "license not allowed", fake: &fakeDnspup{body: pullFixture(t, func(text string) string {
			return strings.Replace(text, `"license":"LicenseRef-tor-project-exitlist"`, `"license":"LicenseRef-tor-other"`, 1)
		})}, want: ErrLicense},
		{name: "itdog source denied", fake: &fakeDnspup{body: pullFixture(t, func(text string) string {
			return strings.Replace(text, `"id":"peeringdb"`, `"id":"itdog"`, 1)
		})}, want: ErrLicense},
	}
	for _, test := range cases {
		secret := test.secret
		if secret == "" {
			secret = pullTestAPISecret
		}
		result, err := fetchFrom(t, test.fake, secret, "", test.max)
		if !errors.Is(err, test.want) {
			t.Errorf("%s: err = %v, want %v", test.name, err, test.want)
			continue
		}
		if result.ErrorCode != test.code {
			t.Errorf("%s: error code %q, want %q", test.name, result.ErrorCode, test.code)
		}
		if test.pending != 0 && result.RetryAfter != test.pending {
			t.Errorf("%s: retry after %s", test.name, result.RetryAfter)
		}
		for _, credential := range []string{pullTestAPISecret, wrongSecret, pullTestAPIKey} {
			if strings.Contains(err.Error(), credential) {
				t.Errorf("%s: error leaks a credential: %v", test.name, err)
			}
		}
	}
}

func TestHTTPSourceTimeout(t *testing.T) {
	block := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(block)
	source, err := NewHTTPSource(HTTPSourceConfig{URL: server.URL, APIKey: pullTestAPIKey, APISecret: pullTestAPISecret, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Fetch(context.Background(), ""); !errors.Is(err, ErrSourceUnreachable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
}
