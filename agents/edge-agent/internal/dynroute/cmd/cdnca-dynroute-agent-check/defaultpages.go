package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
)

// Built-in default pages: every response the node
// gives itself without a configured page (no site / theme page, no slot
// page) is the node's own HTML page (cdnca_filters.default_page): error code
// and title, the browser -> CDN node -> origin path, what happened / what
// can I do, request ID, node. Statuses are the existing ones.
//
// DEFAULT_PAGES_OUT=<dir> also writes each page body to <dir>/<case>.html
// (screenshots).
//
// The runtime is checkSlotPages' (health port for the ban list, node ID);
// the node has no node pages here.
func checkDefaultPages(h *harness, origin *originServer, others ...edgesite.Site) {
	guard := withSlotSecurity(makeSite(41, "guard-default.d13.test", 1, portPlain))
	traffic := makeSite(42, "traffic-default.d13.test", 1, portPlain)
	traffic.TrafficLimit = &edgesite.TrafficLimit{Period: "daily"}
	limited := makeSite(43, "conn-default.d13.test", 1, portPlain)
	limited.Limits.Connections = &edgesite.Connections{SubscriptionID: "0d130000-0000-4000-8000-0000000005c3", Max: 0}
	expired := makeSite(44, "expired-default.d13.test", 1, portPlain)
	expired.PackageExpired = true
	connect, err := slotConnectSite(45, "connect-default.d13.test", nil)
	check("default-connect-fixture", err == nil, "%v", err)
	connect.Errors = []edgesite.ErrorPage{} // no theme pages: the built-in ones answer
	sites := append([]edgesite.Site{guard, traffic, limited, expired, connect}, others...)
	h.input.NodePages = nil
	h.apply("default-pages-apply", sites...)

	out := os.Getenv("DEFAULT_PAGES_OUT")
	page := func(name string, status int, r fetched, title string) {
		ok := r.status == status && strings.HasPrefix(r.body, "<!DOCTYPE html>") && strings.Contains(r.body, title) &&
			strings.Contains(r.body, fmt.Sprintf("错误代码 %d", status)) && strings.Contains(r.body, "请求 ID / Request ID: <code>") &&
			!strings.Contains(r.body, "openresty") && !strings.Contains(strings.ToLower(r.body), "cloudflare") &&
			r.header.Get("Content-Type") == "text/html; charset=utf-8" &&
			r.header.Get("Content-Length") == fmt.Sprint(len(r.body)) &&
			strings.HasSuffix(r.header.Get("Content-Security-Policy"), "; style-src '"+styleHash(r.body)+"'") &&
			r.header.Get("Cache-Control") == "no-store, max-age=0"
		check("default-page-"+name, ok, "%d want %d %q %.200q %v", r.status, status, title, r.body, r.header)
		if out != "" && r.body != "" {
			_ = os.MkdirAll(out, 0o755)
			_ = os.WriteFile(filepath.Join(out, name+".html"), []byte(r.body), 0o644)
		}
	}

	// no site: unknown domain / IP address / no Host (421, 400 as before)
	page("unknown_site", 421, fetch(portPlain, "309slrvf.cname.d13.test", "/", nil, nil), "域名未接入本 CDN")
	page("node_ip_access", 421, fetch(portPlain, "127.0.0.1", "/", nil, nil), "不允许通过 IP 直接访问")
	status, body, err := rawRequest(portPlain, "GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n")
	check("default-page-no_host", status == 400 && strings.Contains(body, "请求缺少 Host") && strings.Contains(body, "错误代码 400"),
		"%d %.200q %v", status, body, err)
	if out != "" {
		if _, html, found := strings.Cut(body, "\r\n\r\n"); found {
			_ = os.WriteFile(filepath.Join(out, "no_host.html"), []byte(html), 0o644)
		}
	}
	status, body, err = rawRequest(portPlain, "GET / HTTP/1.0\r\n\r\n")
	check("default-page-no_host-http10", status == 421 && strings.Contains(body, "请求缺少 Host"), "%d %.200q %v", status, body, err)
	// the requested Host is shown on the page (escaped; nginx refuses a Host
	// with markup characters before Lua)
	r := fetch(portPlain, "unknown.d13.test", "/", nil, nil)
	check("default-page-unknown-host-shown", r.status == 421 && strings.Contains(r.body, "CDN node · ") &&
		strings.Contains(r.body, "Origin server · unknown.d13.test"), "%d %.200q", r.status, r.body)
	// HEAD: headers only
	head := request("HEAD", portPlain, "unknown.d13.test", "/")
	check("default-page-head", head.status == 421 && head.body == "", "%d %q", head.status, head.body)

	// a site's own responses
	page("package_expired", 403, fetch(portPlain, "expired-default.d13.test", "/x", nil, nil), "网站套餐已到期")
	check("default-expired-no-origin", origin.count("expired-default.d13.test", "/x") == 0, "%d", origin.count("expired-default.d13.test", "/x"))
	page("traffic_exceeded", 509, fetch(portPlain, "traffic-default.d13.test", "/x", nil, nil), "网站流量已超出限制")
	page("connection_limit", 503, fetch(portPlain, "conn-default.d13.test", "/x", nil, nil), "连接数超出限制")
	page("http_403", 403, fetch(portPlain, "guard-default.d13.test", "/acl-block", nil, nil), "访问被拒绝")
	page("http_502", 502, fetch(portPlain, "connect-default.d13.test", "/x", nil, nil), "源站无法连接")
	page("http_504", 504, fetch(portPlain, "connect-default.d13.test", "/slow/x", nil, nil), "源站响应超时")
	// an origin's own error is never replaced
	r = fetch(portPlain, "guard-default.d13.test", "/origin-403", nil, nil)
	check("default-origin-403-untouched", r.status == 403 && r.body == origin403Body, "%d %.80q", r.status, r.body)

	// blacklist (ban list snapshot on the health port)
	status, err = postBans(securityban.RuntimeSnapshot{Revision: 10, Releases: []securityban.RuntimeRelease{},
		Bans: []securityban.RuntimeBan{{SiteID: guard.SiteID, Client: "127.0.0.1", Until: time.Now().Add(10 * time.Minute).Unix()}}})
	check("default-blacklist-snapshot", status == 200 && err == nil, "%d %v", status, err)
	r = fetch(portPlain, "guard-default.d13.test", "/x", nil, nil)
	page("blacklist", 403, r, "您的 IP 已被封禁")
	check("default-blacklist-ban-header", r.header.Get("X-Cdnca-Ban") == "listed" && r.header.Get("Retry-After") != "", "%v", r.header)
	_, _ = postBans(securityban.RuntimeSnapshot{Revision: 11, Bans: []securityban.RuntimeBan{}, Releases: []securityban.RuntimeRelease{}})
}

// styleHash is the CSP source of the page's one <style> (what a browser
// checks against style-src).
func styleHash(body string) string {
	_, rest, _ := strings.Cut(body, "<style>")
	style, _, _ := strings.Cut(rest, "</style>")
	sum := sha256.Sum256([]byte(style))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}
