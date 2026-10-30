package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// Site access (D13-c0 ⑥, v7 SiteAccessServer / writeForceHTTPS /
// siteaccess.engine): forced HTTPS with its status and excluded names, host
// redirects, HSTS, the site's gzip, basic auth (credential not forwarded)
// and the maintenance page with its allowed networks; ACME HTTP-01 passes.
func checkSiteAccess(h *harness, secure edgesite.Site, roots *x509.CertPool, others ...edgesite.Site) {
	site := secure
	site.Revision++
	site.Hosts.Aliases = []string{"old.secure.d13.test", "plain.secure.d13.test"}
	site.Listeners = append([]edgesite.Listener{{Port: portPlain, AddressFamily: edgesite.FamilyIPv4}}, site.Listeners...)
	site.ForceHTTPS = &edgesite.ForceHTTPS{RedirectPort: portTLS, Status: 308, ExcludeHosts: []string{"plain.secure.d13.test"}}
	site.HSTS = &edgesite.HSTS{MaxAgeSeconds: 600}
	site.Access = &edgeconfig.SiteAccess{
		HostRedirects: []edgeconfig.HostRedirect{{SourceHost: "old.secure.d13.test", TargetHost: "www.d13.test",
			TargetScheme: "follow", Status: 302, PreserveURI: true}},
		Compression: &edgeconfig.SiteCompression{Enabled: true, Types: []string{"text/plain"}, MinLengthBytes: 16},
		BasicAuth: &edgeconfig.SiteBasicAuth{Realm: "staff", ExcludePathPrefixes: []string{"/public/"},
			Users: []edgeconfig.BasicAuthUser{edgeconfig.BasicAuthUserWithSalt("alice", "000102030405060708090a0b0c0d0e0f", "s3cret")}},
	}
	closed := makeSite(20, "closed.d13.test", 1, portPlain)
	closed.Access = &edgeconfig.SiteAccess{Maintenance: &edgeconfig.SiteMaintenancePage{Status: 503, ContentType: "text/plain",
		Body: "down", RetryAfter: 60, AllowedCIDRs: []string{"10.0.0.0/8"}}}
	limited := makeSite(22, "limited.d13.test", 1, portPlain)
	limited.Access = &edgeconfig.SiteAccess{Limits: &edgeconfig.SiteRequestLimits{ConnectionsPerIP: 2,
		RateBytesPerSecond: 256 << 10, RateAfterBytes: 128 << 10}}
	open := makeSite(21, "open.d13.test", 1, portPlain)
	open.Access = &edgeconfig.SiteAccess{Maintenance: &edgeconfig.SiteMaintenancePage{Status: 503, ContentType: "text/plain",
		Body: "down", AllowedCIDRs: []string{"127.0.0.1/32"}},
		Compression: &edgeconfig.SiteCompression{Enabled: false, Types: []string{}}}
	sites := []edgesite.Site{site, closed, open, limited}
	for _, other := range others {
		if other.SiteID != site.SiteID {
			sites = append(sites, other)
		}
	}
	h.apply("site-access-apply", sites...)

	alice := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))}
	r := fetch(portPlain, "secure.d13.test", "/a?b=1", nil, nil)
	check("force-https-308", r.status == 308 && r.header.Get("Location") == fmt.Sprintf("https://secure.d13.test:%d/a?b=1", portTLS) &&
		strings.Contains(r.body, "308 Permanent Redirect"), "%d %q %.60q %s", r.status, r.header.Get("Location"), r.body, r.err)
	r = fetch(portPlain, "secure.d13.test", "/.well-known/acme-challenge/x", alice, nil)
	check("force-https-acme-passes", r.status == 200 && strings.HasPrefix(r.body, "origin secure.d13.test"), "%d %.40q", r.status, r.body)
	r = fetch(portPlain, "old.secure.d13.test", "/p?q=2", nil, nil)
	check("host-redirect", r.status == 302 && r.header.Get("Location") == "http://www.d13.test/p?q=2", "%d %q", r.status, r.header.Get("Location"))
	r = fetch(portPlain, "plain.secure.d13.test", "/x", nil, nil)
	check("basic-auth-401", r.status == 401 && r.header.Get("WWW-Authenticate") == `Basic realm="staff", charset="UTF-8"` &&
		r.header.Get("Strict-Transport-Security") == "", "%d %q hsts %q", r.status, r.header.Get("WWW-Authenticate"), r.header.Get("Strict-Transport-Security"))
	wrong := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong"))}
	r = fetch(portPlain, "plain.secure.d13.test", "/x", wrong, nil)
	check("basic-auth-wrong-401", r.status == 401, "%d", r.status)
	r = fetch(portPlain, "plain.secure.d13.test", "/public/ping", nil, nil)
	check("basic-auth-excluded-prefix", r.status == 200, "%d", r.status)
	r = fetch(portPlain, "plain.secure.d13.test", "/whoami", alice, nil)
	check("basic-auth-ok-not-forwarded", r.status == 200 && strings.Contains(r.body, "auth=-"), "%d %.60q", r.status, r.body)
	gzipped := map[string]string{"Authorization": alice["Authorization"], "Accept-Encoding": "gzip"}
	r = fetch(portTLS, "secure.d13.test", "/z", gzipped, roots)
	check("https-gzip-hsts", r.status == 200 && r.header.Get("Content-Encoding") == "gzip" &&
		r.header.Get("Strict-Transport-Security") == "max-age=600", "%d enc %q hsts %q %s", r.status, r.header.Get("Content-Encoding"),
		r.header.Get("Strict-Transport-Security"), r.err)
	r = fetch(portTLS, "secure.d13.test", "/nope", nil, roots)
	check("https-401-hsts", r.status == 401 && r.header.Get("Strict-Transport-Security") == "max-age=600", "%d %q", r.status, r.header.Get("Strict-Transport-Security"))
	r = fetch(portPlain, "closed.d13.test", "/any", map[string]string{"Accept-Encoding": "gzip"}, nil)
	check("maintenance-503", r.status == 503 && r.body == "down" && r.header.Get("Retry-After") == "60" &&
		r.header.Get("Cache-Control") == "no-store", "%d %q %q", r.status, r.body, r.header.Get("Retry-After"))
	r = fetch(portPlain, "closed.d13.test", "/.well-known/acme-challenge/x", nil, nil)
	check("maintenance-acme-passes", r.status == 200, "%d", r.status)
	r = fetch(portPlain, "open.d13.test", "/any", map[string]string{"Accept-Encoding": "gzip"}, nil)
	check("maintenance-allowed-gzip-off", r.status == 200 && strings.HasPrefix(r.body, "origin open.d13.test") &&
		r.header.Get("Content-Encoding") == "", "%d enc %q %.30q", r.status, r.header.Get("Content-Encoding"), r.body)
	// a site without its own compression: the node default (no system: off)
	r = fetch(portPlain, "shop.d13.test", "/index.html", map[string]string{"Accept-Encoding": "gzip"}, nil)
	check("site-without-compression-plain", r.status == 200 && r.header.Get("Content-Encoding") == "", "%d enc %q", r.status, r.header.Get("Content-Encoding"))
	// access.limits: 3 concurrent requests from one address, 2 allowed (429)
	statuses := make(chan int, 3)
	for range 3 {
		go func() { statuses <- fetch(portPlain, "limited.d13.test", "/hold/x", nil, nil).status }()
	}
	counts := map[int]int{}
	for range 3 {
		counts[<-statuses]++
	}
	check("limits-connections-per-ip", counts[200] == 2 && counts[429] == 1, "%v", counts)
	r = fetch(portPlain, "limited.d13.test", "/hold/again", nil, nil)
	check("limits-connections-released", r.status == 200, "%d", r.status)
	// 1 MiB at 256 KiB/s after 128 KiB: about 3.5 s (unlimited: milliseconds)
	start := time.Now()
	r = fetch(portPlain, "limited.d13.test", "/big/rate", nil, nil)
	elapsed := time.Since(start)
	check("limits-rate", r.status == 200 && len(r.body) == 1<<20 && elapsed > 2500*time.Millisecond && elapsed < 8*time.Second,
		"%d %d bytes in %s", r.status, len(r.body), elapsed)
	start = time.Now()
	r = fetch(portPlain, "open.d13.test", "/big/free", nil, nil)
	check("limits-other-site-unlimited", r.status == 200 && time.Since(start) < time.Second, "%d in %s", r.status, time.Since(start))
	h.apply("site-access-remove", others...)
}

type fetched struct {
	status int
	header http.Header
	body   string
	err    string
}

// fetch: one request on a new connection, redirects not followed, the body
// as sent (no transparent gzip); roots != nil: HTTPS with SNI host.
func fetch(port int, host, path string, headers map[string]string, roots *x509.CertPool) fetched {
	scheme := "http"
	transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true}
	if roots != nil {
		scheme = "https"
		transport.TLSClientConfig = &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, port, path), nil)
	request.Host = host
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return fetched{err: err.Error()}
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return fetched{status: response.StatusCode, header: response.Header, body: string(body)}
}
