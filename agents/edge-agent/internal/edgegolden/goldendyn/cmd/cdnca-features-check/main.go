// Command cdnca-features-check is the real OpenResty smoke of three
// features on a dynamic routing node (tests/dynroute-features/run.sh starts
// it in the node runtime image, one --rm --network none container):
//   - rum: real user monitoring: the script tag in sampled
//     200 text/html, Accept-Encoding to the origin only for sampled requests,
//     the script and collect paths (size, Origin, per IP limit), and the
//     cache holding the origin's bytes without the tag (§5.2.1);
//   - c3: third party human verification: with the provider
//     unreachable an external rule degrades to the built-in check and
//     "unavailable" never counts as a failed attempt;
//   - install: a challenge policy installed by the production
//     challenge.ArtifactInstaller under the state root's challenge directory
//     is preloaded by the node, intercepts and lets a solved visitor through
//     (challenge_root).
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	luaRoot = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	state   = flag.String("state", "/tmp/feat", "state directory")
	workers = flag.Int("workers", 2, "worker_processes")
	only    = flag.String("only", "rum,c3,install", "parts to run")
)

const (
	edge       = 8080
	originAddr = "127.0.0.1:19921"
	answerPort = 18099
	scope      = "0f3a0000-0000-4000-8000-000000000001"
	tenant     = "0f3a0000-0000-4000-8000-000000000002"
	policyID   = "0f3a0000-0000-4000-8000-0000000000a1"
	policyRev  = 7
)

var failures int

func check(id string, ok bool, format string, args ...any) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failures++
	}
	fmt.Printf("%s %s %s\n", status, id, fmt.Sprintf(format, args...))
}

// originServer: HTML pages, a 404 page, text and the challenge target; it
// remembers the Accept-Encoding of every request and how often a path came.
type originServer struct {
	mu   sync.Mutex
	ae   map[string]string
	hits map[string]int
}

func (o *originServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	o.ae[r.URL.Path] = r.Header.Get("Accept-Encoding")
	o.hits[r.URL.Path]++
	o.mu.Unlock()
	switch r.URL.Path {
	case "/page.html", "/cached.html", "/missing.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/cached.html" {
			w.Header().Set("Cache-Control", "public, max-age=60")
		}
		if r.URL.Path == "/missing.html" {
			w.WriteHeader(http.StatusNotFound)
		}
		_, _ = io.WriteString(w, "<!doctype html><html><head><title>"+r.URL.Path+"-marker</title></head><body>hello</body></html>")
	case "/plain.txt":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "plain text <head> here\n")
	default:
		_, _ = io.WriteString(w, "origin-ok\n")
	}
}

func (o *originServer) seen(path string) (string, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.ae[path], o.hits[path]
}

type reply struct {
	status int
	header http.Header
	body   string
}

// visitor is one client address (a loopback alias) with its cookies.
type visitor struct {
	source  string
	cookies map[string]string
	http    *http.Client
}

func newVisitor(source string) *visitor {
	dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	return &visitor{source: source, cookies: map[string]string{}, http: &http.Client{Timeout: 20 * time.Second,
		Transport:     &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (v *visitor) send(method, host, path, body string, headers map[string]string) reply {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", edge, path), reader)
	request.Host = host
	request.Header.Set("User-Agent", "Mozilla/5.0 probe")
	request.Header.Set("Accept", "text/html")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	pairs := make([]string, 0, len(v.cookies))
	for name, value := range v.cookies {
		pairs = append(pairs, name+"="+value)
	}
	sort.Strings(pairs)
	if len(pairs) != 0 {
		request.Header.Set("Cookie", strings.Join(pairs, "; "))
	}
	result, err := v.http.Do(request)
	if err != nil {
		return reply{status: -1, body: err.Error()}
	}
	defer result.Body.Close()
	content, _ := io.ReadAll(result.Body)
	for _, cookie := range result.Cookies() {
		v.cookies[cookie.Name] = cookie.Value
	}
	return reply{status: result.StatusCode, header: result.Header, body: string(content)}
}

func (v *visitor) get(host, path string, headers map[string]string) reply {
	return v.send("GET", host, path, "", headers)
}

func main() {
	flag.Parse()
	origin := &originServer{ae: map[string]string{}, hits: map[string]int{}}
	listener, err := net.Listen("tcp", originAddr)
	if err != nil {
		fmt.Println("FAIL origin", err)
		os.Exit(1)
	}
	go func() { _ = http.Serve(listener, origin) }()
	for _, part := range strings.Split(*only, ",") {
		switch part {
		case "rum":
			rumRun(origin)
		case "c3":
			c3Run()
		case "install":
			installRun()
		}
	}
	fmt.Printf("failures=%d\n", failures)
	if failures != 0 {
		os.Exit(1)
	}
}
