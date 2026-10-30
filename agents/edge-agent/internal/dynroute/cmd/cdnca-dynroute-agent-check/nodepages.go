package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// Node pages (D13-b2 交接 2): the scopes' global unknown_site page answers
// an unknown Host with its status, the no_host page (400) a request without
// a Host; without pages both are a bare 421. A configured site is untouched.
func checkNodePages(h *harness, sites ...edgesite.Site) {
	unknownBody, noHostBody := "{\"error\":\"unknown_site\"}\n", "<p>host required</p>\n"
	h.input.NodePages = []dynroute.NodePage{
		{Category: siteobject.NodePageUnknownSite, Status: 404, MIMEType: "application/json", Body: []byte(unknownBody)},
		{Category: siteobject.NodePageNoHost, Status: 400, MIMEType: "text/html", Body: []byte(noHostBody)},
	}
	applied := h.apply("node-pages-apply", sites...)
	check("node-pages-reload", applied.Reloaded, "reloaded %v", applied.Reloaded)
	a := get(portPlain, "unknown.d13.test", "/")
	check("node-page-unknown-404", a.status == 404 && a.body == unknownBody, "%d %q %s", a.status, a.body, a.err)
	status, body, err := rawRequest(portPlain, "GET / HTTP/1.0\r\n\r\n")
	check("node-page-no-host-400", status == 400 && strings.HasSuffix(body, noHostBody) && strings.Contains(body, "text/html"),
		"%d %q %v", status, body, err)
	// HTTP/1.1 without or with an empty Host is refused by the nginx core
	// while parsing, before any Lua phase: the skeleton's error_page 400
	// sends it to the no_host location (B11).
	status, body, err = rawRequest(portPlain, "GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n")
	check("node-page-empty-host-400", status == 400 && strings.HasSuffix(body, noHostBody) && strings.Contains(body, "text/html"),
		"%d %q %v", status, body, err)
	status, body, err = rawRequest(portPlain, "GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
	check("node-page-missing-host-400", status == 400 && strings.HasSuffix(body, noHostBody), "%d %q %v", status, body, err)
	// a 400 of a configured site's own processing keeps nginx's page
	status, body, err = rawRequest(portPlain, "GET / HTTP/1.1\r\nHost: shop.d13.test\r\nContent-Length: x\r\nConnection: close\r\n\r\n")
	check("node-page-site-400-untouched", status == 400 && !strings.HasSuffix(body, noHostBody), "%d %q %v", status, body, err)
	a = get(portPlain, "shop.d13.test", "/index.html")
	check("node-pages-site-untouched", a.status == 200, "%d", a.status)

	h.input.NodePages = nil
	h.apply("node-pages-removed-apply", sites...)
	a = get(portPlain, "unknown.d13.test", "/")
	status, _, err = rawRequest(portPlain, "GET / HTTP/1.0\r\n\r\n")
	check("node-pages-removed-421", a.status == 421 && status == 421, "unknown %d no host %d %v", a.status, status, err)
}

// rawRequest sends one hand-written request (no Host header, which
// net/http always adds) and returns the status and the whole response.
func rawRequest(port int, request string) (int, string, error) {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return 0, "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(connection, request); err != nil {
		return 0, "", err
	}
	raw, _ := io.ReadAll(connection)
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(raw))), nil)
	if err != nil {
		return 0, string(raw), err
	}
	_ = response.Body.Close()
	return response.StatusCode, string(raw), nil
}
