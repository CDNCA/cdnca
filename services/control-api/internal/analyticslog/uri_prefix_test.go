package analyticslog

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

// FX29/NF17: uri_path_match=prefix turns the URI filter into a ClickHouse
// startsWith match; exact stays the default.
func TestURIPathPrefixFilter(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	if !strings.Contains(accessPageSQL, "{uri_path_prefix:UInt8}") || !strings.Contains(blockEventPageSQL, "{uri_path_prefix:UInt8}") {
		t.Fatal("log SQL does not support a prefix URI match")
	}
	for name, filter := range map[string]Filter{
		"prefix_without_path": {From: now.Add(-time.Hour), To: now, URIPathPrefix: true},
	} {
		if validateFilter(filter) == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	var query url.Values
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		query = request.URL.Query()
	}))
	defer server.Close()
	client := newUnitClient(t, server, time.Second)
	filter := Filter{From: now.Add(-time.Hour), To: now, URIPath: "/static/", URIPathPrefix: true}
	if _, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, ""); err != nil {
		t.Fatal(err)
	}
	if query.Get("param_uri_path") != "/static/" || query.Get("param_uri_path_prefix") != "1" {
		t.Fatalf("prefix parameters = %#v", query)
	}
	exact := filter
	exact.URIPathPrefix = false
	if logFingerprint(scope{tenantID: tenantA}, exact, "access") == logFingerprint(scope{tenantID: tenantA}, filter, "access") {
		t.Fatal("cursor fingerprint ignores the URI match mode")
	}

	clientIP := netip.MustParseAddr("192.0.2.1")
	row := accessRow{URIPath: "/static/app.js"}
	if !accessRowMatches(row, clientIP, filter) || accessRowMatches(row, clientIP, exact) {
		t.Fatal("access row prefix match is wrong")
	}
	block := blockEventRow{URIPath: "/static/app.js", Action: "block"}
	if !blockEventRowMatches(block, clientIP, filter) || blockEventRowMatches(block, clientIP, exact) {
		t.Fatal("block row prefix match is wrong")
	}
}

func TestURIPathMatchQueryParameter(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	base := "from=" + url.QueryEscape(now.Add(-time.Hour).Format(time.RFC3339Nano)) +
		"&to=" + url.QueryEscape(now.Format(time.RFC3339Nano))
	for _, route := range []handlerRoute{{audience: AudienceTenant, kind: routeAccess}, {audience: AudienceTenant, kind: routeBlockEvent}} {
		request := httptest.NewRequest(http.MethodGet, "/x?"+base+"&uri_path=%2Fstatic%2F&uri_path_match=prefix", nil)
		parsed, err := parseQuery(request, route)
		if err != nil || !parsed.Filter.URIPathPrefix || parsed.Filter.URIPath != "/static/" {
			t.Fatalf("prefix query = %#v, %v", parsed.Filter, err)
		}
		request = httptest.NewRequest(http.MethodGet, "/x?"+base+"&uri_path=%2Fa&uri_path_match=exact", nil)
		if parsed, err = parseQuery(request, route); err != nil || parsed.Filter.URIPathPrefix {
			t.Fatalf("exact query = %#v, %v", parsed.Filter, err)
		}
		request = httptest.NewRequest(http.MethodGet, "/x?"+base+"&uri_path=%2Fa&uri_path_match=regex", nil)
		if _, err = parseQuery(request, route); err == nil {
			t.Fatal("unknown uri_path_match accepted")
		}
	}

	var body exportCreateBody
	if err := json.Unmarshal([]byte(`{"filter":{"from":"2026-07-23T11:00:00Z","to":"2026-07-23T12:00:00Z","uri_path":"/static/","uri_path_match":"prefix"}}`), &body); err != nil {
		t.Fatalf("export body does not accept uri_path_match: %v", err)
	}
	if body.Filter.URIPathMatch != "prefix" {
		t.Fatalf("export uri_path_match = %q", body.Filter.URIPathMatch)
	}
}
