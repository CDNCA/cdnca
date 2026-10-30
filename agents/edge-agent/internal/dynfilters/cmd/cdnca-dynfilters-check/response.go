package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// Response rules (docs/edge/dynroute-filters.md §2.1): one
// site with the "pages" site's error pages and an ordered rule list; the
// origin's /resp/ and /cached/ answer ?s=<status> with ?h=Name:Value headers
// (origin.go), /cached/ through a proxy_cache location (nginx.conf).
const (
	siteRs   = "0d9a0000-0000-4000-8000-000000000109"
	respHost = "resp.example.test"
)

func responseRules() []edgeconfig.SiteResponseRule {
	status := func(from, to int) []edgeconfig.StatusRange { return []edgeconfig.StatusRange{{From: from, To: to}} }
	header := func(name, op, value string) []edgeconfig.ResponseHeaderCondition {
		return []edgeconfig.ResponseHeaderCondition{{Name: name, Op: op, Value: value}}
	}
	return []edgeconfig.SiteResponseRule{
		// headers on every 2xx: drop X-Powered-By, set and add
		{ID: "hdr", Statuses: status(200, 299), Action: edgeconfig.ResponseActionHeaders, HeaderActions: []edgeconfig.ResponseHeaderAction{
			{Kind: edgeconfig.ResponseHeaderDelete, Name: "x-powered-by"},
			{Kind: edgeconfig.ResponseHeaderSet, Name: "x-resp-rule", Value: "on"},
			{Kind: edgeconfig.ResponseHeaderAdd, Name: "x-multi", Value: "added"}}},
		// an origin that leaks its server (regex on a header) is blocked
		{ID: "leak", Headers: header("x-debug", edgeconfig.ResponseHeaderRegex, "^(?i)stack"), Action: edgeconfig.ResponseActionBlock, Status: 451},
		// a header that exactly equals a value: logged, evaluation goes on
		{ID: "audit", Headers: header("x-audit", edgeconfig.ResponseHeaderEquals, "1"), Action: edgeconfig.ResponseActionLog},
		// a status list (two single statuses): the site's 503 page
		{ID: "page", Statuses: []edgeconfig.StatusRange{{From: 500, To: 500}, {From: 502, To: 502}},
			Action: edgeconfig.ResponseActionErrorPage, Status: 503},
		// error page of a status the site has no page for: built-in
		{ID: "nopage", Statuses: status(418, 418), Action: edgeconfig.ResponseActionErrorPage, Status: 599},
		// a header that is absent on a 4xx: block with 403 (no-page fallback
		// is the built-in text: a block never uses the site's page)
		{ID: "absent", Statuses: status(400, 499), Headers: header("x-allowed", edgeconfig.ResponseHeaderAbsent, ""),
			Action: edgeconfig.ResponseActionBlock, Status: 403},
		// a cached 200 carrying X-Block is blocked only from the origin
		{ID: "cached", Headers: header("x-block", edgeconfig.ResponseHeaderExists, ""), Action: edgeconfig.ResponseActionBlock, Status: 403},
	}
}

func respSite(n *node, revision int64, rules []edgeconfig.SiteResponseRule) edgesite.Site {
	site := makeSite(siteRs, respHost, revision)
	site.Errors = sitePages(n)
	if len(rules) != 0 {
		site.Access = &edgeconfig.SiteAccess{ResponseRules: rules}
	}
	return site
}

func lastLogLine(host, uri string) string {
	data, _ := os.ReadFile(filepath.Join(*stateRoot, "nginx", "logs", "resp-rules.log"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		if strings.HasPrefix(lines[index], host+" "+uri+" ") {
			return lines[index]
		}
	}
	return ""
}

// logLine waits for the access log line (written after the response).
func logLine(host, uri string) string {
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if line := lastLogLine(host, uri); line != "" || time.Now().After(deadline) {
			return line
		}
	}
}

func checkResponseRules(n *node) {
	fmt.Println("== response rules")
	sites := append(baseSites(n), respSite(n, 1, responseRules()))
	if err := n.activate(sites); err != nil {
		check("activate-response", false, "%v", err)
		return
	}
	get := func(path string) exchange { return raw(plain, "GET", respHost, path, nil, "") }

	answer := get("/resp/hdr?h=X-Powered-By:php&h=X-Multi:origin")
	check("resp-headers", answer.Status == 200 && answer.Headers["x-powered-by"] == "" && answer.Headers["x-resp-rule"] == "on" &&
		answer.Headers["x-multi"] == "origin, added" && answer.Body == "resp-body /resp/hdr\n" && answer.Headers["x-origin-header"] == "yes",
		"set/add/delete, body untouched: %s", answer)
	h2 := probe("h2", respHost, "/resp/hdr2?h=X-Powered-By:php")
	check("resp-headers-h2", h2.Status == 200 && h2.Headers["x-powered-by"] == "" && h2.Headers["x-resp-rule"] == "on", "%d %v", h2.Status, h2.Headers)
	h3 := probe("h3", respHost, "/resp/hdr3?h=X-Powered-By:php")
	check("resp-headers-h3", h3.Status == 200 && h3.Proto == "HTTP/3.0" && h3.Headers["x-powered-by"] == "" && h3.Headers["x-resp-rule"] == "on",
		"%s %d %v", h3.Proto, h3.Status, h3.Headers)
	answer = get("/resp/nostatus?s=302&h=X-Powered-By:php&h=Location:/x")
	check("resp-headers-status-cond", answer.Status == 302 && answer.Headers["x-powered-by"] == "php" && answer.Headers["x-resp-rule"] == "",
		"2xx only: %s", answer)

	answer = get("/resp/leak?h=X-Debug:StackTrace%20at%20main")
	check("resp-block-regex", answer.Status == 451 && answer.Body == "Request could not be completed.\n" &&
		answer.Headers["x-debug"] == "" && answer.Headers["x-origin-header"] == "" && answer.Headers["cache-control"] == "no-store, max-age=0" &&
		answer.Framing == "length", "built-in page, nothing of the origin: %s", answer)
	line := logLine(respHost, "/resp/leak")
	check("resp-block-log", strings.Contains(line, " 451 emit=1 type=response action=block rule=leak page=1"), "%q", line)
	answer = get("/resp/noleak?h=X-Debug:none")
	check("resp-regex-no-match", answer.Status == 200 && answer.Headers["x-debug"] == "none", "%s", answer)

	answer = get("/resp/audit?h=X-Audit:1")
	line = logLine(respHost, "/resp/audit")
	check("resp-log", answer.Status == 200 && answer.Headers["x-audit"] == "1" && answer.Headers["x-resp-rule"] == "on" &&
		strings.Contains(line, " 200 emit=1 type=response action=log rule=audit page=0"), "goes on: %s %q", answer, line)
	answer = get("/resp/audit2?h=X-Audit:10")
	line = logLine(respHost, "/resp/audit2")
	check("resp-equals-exact", answer.Status == 200 && strings.Contains(line, " emit=0 "), "%q", line)

	for _, status := range []string{"500", "502"} {
		answer = get("/resp/page?s=" + status)
		check("resp-error-page-"+status, answer.Status == 503 && answer.Body == pageBodies["origin_response|503"] &&
			answer.Headers["content-type"] == "application/json" && answer.Headers["x-origin-header"] == "", "site 503 page: %s", answer)
	}
	answer = get("/resp/page?s=501")
	check("resp-error-page-list", answer.Status == 501 && answer.Body == "resp-body /resp/page\n", "501 not in the list: %s", answer)
	h2 = probe("h2", respHost, "/resp/page?s=500")
	check("resp-error-page-h2", h2.Status == 503 && h2.Body == pageBodies["origin_response|503"], "%d %q", h2.Status, h2.Body)
	answer = get("/resp/nopage?s=418")
	check("resp-error-page-builtin", answer.Status == 599 && answer.Body == "Service temporarily unavailable.\n", "%s", answer)

	answer = get("/resp/absent?s=404")
	check("resp-block-absent", answer.Status == 403 && answer.Body == "Request could not be completed.\n", "%s", answer)
	// 410: the site has no page for it, so the origin's answer passes
	answer = get("/resp/absent2?s=410&h=X-Allowed:1")
	check("resp-absent-present", answer.Status == 410 && answer.Body == "resp-body /resp/absent2\n", "%s", answer)
	head := raw(plain, "HEAD", respHost, "/resp/absent3?s=404", nil, "")
	check("resp-block-head", head.Status == 403 && head.Body == "", "%s", head)

	// The edge's own responses are not evaluated: an edge exit 418 (the
	// nopage rule would turn an origin 418 into 599, absent into 403).
	answer = raw(plain, "GET", respHost, "/resp/edge", map[string]string{"X-Test-Edge-Exit": "418"}, "")
	line = logLine(respHost, "/resp/edge")
	check("resp-edge-own-skipped", answer.Status == 418 && strings.Contains(line, " 418 emit=0 "), "%s %q", answer, line)
	answer = raw(plain, "GET", respHost, "/resp/module", map[string]string{"X-Test-Module-Page": "1"}, "")
	check("resp-module-page-skipped", answer.Status == 403 && answer.Body == "Request blocked\n", "%s", answer)

	// Cached responses: headers rules run on a HIT too,
	// block/log/error_page only on the origin's
	// response; a replaced response is not stored.
	first := get("/cached/a?h=X-Powered-By:php")
	second := get("/cached/a?h=X-Powered-By:php")
	check("resp-cached-headers", first.Headers["x-test-cache"] == "MISS" && second.Headers["x-test-cache"] == "HIT" &&
		second.Headers["x-powered-by"] == "" && second.Headers["x-resp-rule"] == "on", "MISS then HIT, both rewritten: %s | %s", first, second)
	first = get("/cached/b?h=X-Block:1")
	second = get("/cached/b?h=X-Block:1")
	check("resp-block-not-cached", first.Status == 403 && second.Status == 403 && second.Headers["x-test-cache"] != "HIT",
		"a blocked response is not stored: %s | %s", first, second)
	// A cached 200 that a later rule would block: published without the
	// rule first, cached, then the rule arrives; the HIT is served.
	cachedRules := []edgeconfig.SiteResponseRule{{ID: "hdr", Statuses: []edgeconfig.StatusRange{{From: 200, To: 299}},
		Action: edgeconfig.ResponseActionHeaders, HeaderActions: []edgeconfig.ResponseHeaderAction{{Kind: edgeconfig.ResponseHeaderSet, Name: "x-resp-rule", Value: "on"}}}}
	if err := n.activate(append(baseSites(n), respSite(n, 2, cachedRules))); err != nil {
		check("activate-response-2", false, "%v", err)
		return
	}
	fill := get("/cached/c?h=X-Block:1")
	if err := n.activate(append(baseSites(n), respSite(n, 3, responseRules()))); err != nil {
		check("activate-response-3", false, "%v", err)
		return
	}
	hit := get("/cached/c?h=X-Block:1")
	check("resp-hit-not-blocked", fill.Status == 200 && hit.Status == 200 && hit.Headers["x-test-cache"] == "HIT" &&
		hit.Headers["x-block"] == "1" && hit.Headers["x-resp-rule"] == "on", "%s | %s", fill, hit)

	// Without rules nothing changes; removing them needs no reload.
	if err := n.activate(append(baseSites(n), respSite(n, 4, nil))); err != nil {
		check("activate-response-4", false, "%v", err)
		return
	}
	answer = get("/resp/leak2?h=X-Debug:StackTrace&h=X-Powered-By:php")
	check("resp-removed", answer.Status == 200 && answer.Headers["x-powered-by"] == "php" && answer.Headers["x-resp-rule"] == "", "%s", answer)
	if err := n.activate(baseSites(n)); err != nil {
		check("activate-response-cleanup", false, "%v", err)
	}
}
