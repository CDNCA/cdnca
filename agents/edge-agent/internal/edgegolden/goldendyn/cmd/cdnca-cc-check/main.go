// Command cdnca-cc-check runs the security coverage the retired v7 rule
// enforcement scripts had (scripts/security/rule-enforcement-probe.sh,
// rule-enforcement-bench.sh, cc-browser-e2e.sh; deleted in dr-d13-c3e) on a
// real OpenResty dynamic routing node. tests/dynroute-cc/run.sh starts it in
// the node runtime image (--rm --network none) with the site objects the
// control plane's own conversion (cmd/cdnca-site-objects-v2) built from the
// release the real compile chain wrote (control-api
// TestRuleEnforcementAuditRelease): every CC rule group of the signed system
// catalog, the WAF engine combinations and the benchmark sites, on one
// shared server.
//
// Parts (-only, comma separated; default all but serve):
//   - cc:      5秒盾 (cc_rule:10001): page, proof of work, wait, one-time
//     token, pass cookie, /24 binding, UA binding, ban after 5 failures;
//   - modes:   every other verification rule group solved the way its page
//     asks (JS, click, rotate, easy click, easy slider, slider; captcha
//     answered wrong), then passed;
//   - params:  the 5秒盾 group with changed catalog values (PoW 20 bits,
//     wait 2 s, 2 failures, ban 30 s, /32 binding) behaves accordingly;
//     PL2 profile blocks admin'#;
//   - rate:    宽松 (cc_rule:6, 5 s 300 requests / 50 per URI);
//   - agg:     challenge pages / 429s of one client are one security line
//     per minute with a count, a ban one line (sec-log-agg; waits for the
//     minute's flush, about a minute);
//   - engines: self-developed detection / OWASP CRS / both (block: either
//     engine blocks; log only: both pass and each records its own hits);
//   - bench:   request cost of no policy / all CRS sets PL1 / PL2 / PL3
//     (one worker, 8 keep-alive clients in the same container);
//   - serve:   serve the node until killed (headless browser run).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldenrelease"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

var (
	luaRoot     = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	objectsDir  = flag.String("objects", "/cc/objects", "cdnca-site-objects-v2 output (sites.json + sha256/)")
	modSecurity = flag.String("modsecurity", "/usr/local/openresty/modsecurity", "engine extension directory")
	state       = flag.String("state", "/tmp/cc", "state directory")
	workers     = flag.Int("workers", 1, "worker_processes")
	only        = flag.String("only", "", "comma separated parts: cc,modes,params,rate,agg,engines,bench,serve")
	benchN      = flag.Int("bench-requests", 4000, "bench requests per round")
	benchC      = flag.Int("bench-concurrency", 8, "bench concurrent keep-alive connections")
	benchRounds = flag.Int("bench-rounds", 3, "bench measured rounds (median)")
	replay      = flag.String("replay", "", "cookie file: send it with -replay-ua to cc /article?id=7 from 127.0.0.1, print the status, exit")
	replayUA    = flag.String("replay-ua", "", "User-Agent file of -replay")
)

const (
	edge   = 8080 // the release's listener port
	origin = "127.0.0.1:9000"
	shared = "shared"
)

var failures int

// registry is the D12 attribution the agent registers before activation.
var registry = dyntelemetry.NewRegistry()

// auditVersion stands in for the release's config version (site objects do
// not carry it; the agent registers the publication's).
const auditVersion = "rule-audit-1"

// check prints PASS|FAIL <id> expected=<..> actual=<..> <note>, the retired
// probe's line format.
func check(id string, expected, actual any, note string) {
	status := "PASS"
	if fmt.Sprint(expected) != fmt.Sprint(actual) {
		status = "FAIL"
		failures++
	}
	fmt.Printf("%s %s expected=%v actual=%v %s\n", status, id, expected, actual, note)
}

func host(name string) string { return name + ".audit.example.test" }

// ---------------------------------------------------------------- node

func readObject(digest string) ([]byte, error) {
	return os.ReadFile(filepath.Join(*objectsDir, "sha256", digest[:2], digest[2:4], digest))
}

func loadSites() ([]siteindex.Object, []edgesite.Site, error) {
	raw, err := os.ReadFile(filepath.Join(*objectsDir, "sites.json"))
	if err != nil {
		return nil, nil, err
	}
	index := map[string]string{}
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, nil, err
	}
	ids := make([]string, 0, len(index))
	for id := range index {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var objects []siteindex.Object
	var sites []edgesite.Site
	for _, id := range ids {
		content, err := readObject(index[id])
		if err != nil {
			return nil, nil, err
		}
		object, err := siteindex.DecodeObject(index[id], content)
		if err != nil {
			return nil, nil, err
		}
		object.Referenced = map[string][]byte{}
		for _, digest := range object.Site.ReferencedDigests() {
			if object.Referenced[digest], err = readObject(digest); err != nil {
				return nil, nil, fmt.Errorf("site %s object %s: %v", id, digest, err)
			}
		}
		objects = append(objects, object)
		sites = append(sites, object.Site)
	}
	return objects, sites, nil
}

func openresty(args ...string) error {
	output, err := exec.Command("openresty", append([]string{"-p", *state + "/", "-c", "nginx.conf"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("openresty %v: %v %s", args, err, output)
	}
	return nil
}

func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

func sharedPath(name string) string { return filepath.Join(*state, shared, name) }

// startNode renders the dynamic routing skeleton (telemetry on, the managed
// WAF engine for the sites that use it), starts OpenResty and activates the
// site objects through the site index activator, as the agent does.
func startNode() error {
	objects, sites, err := loadSites()
	if err != nil {
		return err
	}
	_ = os.RemoveAll(*state)
	for _, dir := range []string{"logs", "run", edgeskeleton.SecurityFlushDirectory, "site-index", "site-objects", "tls-pool", shared + "/cache", shared + "/" + edgeconfig.DynamicRoutingTelemetryDir} {
		if err := os.MkdirAll(filepath.Join(*state, dir), 0o777); err != nil {
			return err
		}
	}
	for _, name := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		if err := os.MkdirAll(sharedPath(name+"-temp"), 0o777); err != nil {
			return err
		}
	}
	bundle := rulecatalog.CRSRulesBundle()
	files, err := rulecatalog.DecodeWAFEngineBundle(*bundle)
	if err != nil {
		return err
	}
	profiles, err := goldenrelease.CRSProfiles()
	if err != nil {
		return err
	}
	waf, err := dynwaf.Prepare(dynwaf.Input{Sites: sites, Profiles: profiles,
		CRSText: &edgeconfig.CRSRuleText{Version: bundle.Version, Files: files},
		Engine: &dynwaf.Engine{ModulePath: filepath.Join(*modSecurity, "modules", "ngx_http_modsecurity_module.so"),
			UnicodeMapPath: filepath.Join(*modSecurity, "unicode.mapping")},
		Root: filepath.Join(*state, "managed-waf"), AuditLog: sharedPath("modsecurity-audit.log")})
	if err != nil {
		return fmt.Errorf("managed WAF: %v", err)
	}
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		return err
	}
	keys := 0
	for _, site := range sites {
		keys += len(site.IndexEntries())
	}
	certificate, key := filepath.Join(*state, "placeholder.crt"), filepath.Join(*state, "placeholder.key")
	if err := dyntls.WritePlaceholder(certificate, key, -1); err != nil {
		return err
	}
	conf, err := edgeskeleton.Render(edgeskeleton.Input{Ports: ports, IndexKeys: keys, ManagedWAF: waf.Skeleton, Telemetry: true,
		Paths: edgeskeleton.Paths{SharedRoot: filepath.Join(*state, shared), LuaRoot: *luaRoot, StateRoot: *state,
			PlaceholderCertificate: certificate, PlaceholderKey: key, OriginTrustPlaceholder: certificate}})
	if err != nil {
		return err
	}
	conf = []byte(strings.Replace(string(conf), "worker_processes auto;\n", "worker_processes "+strconv.Itoa(*workers)+";\n", 1))
	if err := os.WriteFile(filepath.Join(*state, "nginx.conf"), conf, 0o644); err != nil {
		return err
	}
	if err := openresty(); err != nil {
		return err
	}
	control := siteindex.NewControl(filepath.Join(*state, "run", "cdnca-site-admin.sock"))
	activator := &siteindex.Activator{Control: control,
		Files:   siteindex.Files{Root: filepath.Join(*state, "site-index"), Access: siteindex.Access{GID: workerGID()}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(*state, "site-objects"), Access: siteindex.Access{GID: workerGID()}},
		Prepare: func(first, last uint64) error {
			scopes := map[string]string{}
			for _, site := range sites {
				scopes[site.ConfigurationScopeID] = auditVersion
			}
			return registry.Register(first, last, scopes)
		}}
	ctx := context.Background()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := control.Status(ctx); err == nil {
			break
		} else if time.Now().After(deadline) {
			return err
		}
	}
	activation, err := activator.Activate(ctx, objects)
	if err != nil {
		return err
	}
	fmt.Printf("INFO node: %d sites, %d managed WAF tiers, telemetry on\n", len(sites), len(waf.Skeleton.Tiers))
	return activator.WaitGeneration(ctx, activation.Generation)
}

func stop() { _ = openresty("-s", "stop"); time.Sleep(300 * time.Millisecond) }

// serveOrigin: 200 "origin-ok" for everything (the retired probe's origin).
func serveOrigin() error {
	listener, err := net.Listen("tcp", origin)
	if err != nil {
		return err
	}
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.Copy(io.Discard, request.Body)
			_, _ = io.WriteString(writer, "origin-ok\n")
		}))
	}()
	return nil
}

// ---------------------------------------------------------------- client

const userAgent = "Mozilla/5.0 probe"

type response struct {
	status int
	header http.Header
	body   string
}

// client is one visitor: its source address (loopback alias) and cookies.
type client struct {
	source  string
	cookies map[string]string
	http    *http.Client
}

func newClient(source string) *client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	return &client{source: source, cookies: map[string]string{}, http: &http.Client{
		Transport:     &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       20 * time.Second}}
}

// send: method, host, path, form body ("" = none), extra headers.
func (c *client) send(method, hostname, path, body string, headers map[string]string) response {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", edge, path), reader)
	request.Host = hostname
	request.Header.Set("User-Agent", userAgent)
	if body != "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	if len(c.cookies) != 0 && request.Header.Get("Cookie") == "" {
		pairs := make([]string, 0, len(c.cookies))
		for name, value := range c.cookies {
			pairs = append(pairs, name+"="+value)
		}
		sort.Strings(pairs)
		request.Header.Set("Cookie", strings.Join(pairs, "; "))
	}
	result, err := c.http.Do(request)
	if err != nil {
		return response{status: -1, body: err.Error()}
	}
	defer result.Body.Close()
	content, _ := io.ReadAll(result.Body)
	for _, cookie := range result.Cookies() {
		c.cookies[cookie.Name] = cookie.Value
	}
	return response{status: result.StatusCode, header: result.Header, body: string(content)}
}

func (c *client) get(hostname, path string) response { return c.send("GET", hostname, path, "", nil) }

func (c *client) code(hostname, path string) int { return c.get(hostname, path).status }

func field(page, name string) string {
	match := regexp.MustCompile(name + `="([^"]*)"`).FindStringSubmatch(page)
	if match == nil {
		return ""
	}
	return match[1]
}

func token(page string) string {
	match := regexp.MustCompile(`name="token" value="([^"]*)"`).FindStringSubmatch(page)
	if match == nil {
		return ""
	}
	return match[1]
}

// solvePoW finds the counter every client must compute: SHA-256(salt:n)
// with at least bits leading zero bits (ccv2 engine pow_ok).
func solvePoW(salt string, bits int) string {
	for n := 0; ; n++ {
		sum := sha256.Sum256([]byte(salt + ":" + strconv.Itoa(n)))
		zeros := 0
		for _, b := range sum {
			if b == 0 {
				zeros += 8
				continue
			}
			for b&0x80 == 0 {
				zeros++
				b <<= 1
			}
			break
		}
		if zeros >= bits {
			return strconv.Itoa(n)
		}
	}
}

func pagePoW(page string) string {
	bits, _ := strconv.Atoi(field(page, "data-bits"))
	return solvePoW(field(page, "data-salt"), bits)
}

func verify(c *client, hostname, body string) response {
	return c.send("POST", hostname, "/_guard/verify", body, nil)
}

func challengeMode(r response) string {
	mode := r.header.Get("X-Cdnca-Challenge")
	if mode == "" {
		mode = "none"
	}
	return fmt.Sprintf("%s(%d)", mode, r.status)
}

// ---------------------------------------------------------------- cc (5秒盾)

func ccRun() {
	C := host("cc")
	visitor := newClient("127.0.0.1")
	first := visitor.get(C, "/article?id=7")
	check("CC-1", 503, first.status, "首个未验证请求弹出验证页")
	check("CC-2", "delay", first.header.Get("X-Cdnca-Challenge"), "验证页类型为 5 秒等待")
	check("CC-POW-0", "18", field(first.body, "data-bits"), "页面下发的工作量证明难度来自目录参数（18 位）")
	// Failures and bans are per client IP: each negative case its own source.
	fresh := func(source string) (*client, string) {
		c := newClient(source)
		return c, c.get(C, "/article?id=7").body
	}
	c21, page := fresh("127.0.0.21")
	time.Sleep(5200 * time.Millisecond)
	check("CC-POW-1", 403, verify(c21, C, "token="+token(page)+"&answer=").status, "等满 5 秒但不做工作量证明（直刷）被拒绝")
	c22, page := fresh("127.0.0.22")
	check("CC-3", 403, verify(c22, C, "token="+token(page)+"&pow="+pagePoW(page)).status, "工作量证明正确但未等满 5 秒提交被拒绝")
	c23, page := fresh("127.0.0.23")
	counter, _ := strconv.Atoi(pagePoW(page))
	time.Sleep(5200 * time.Millisecond)
	check("CC-POW-2", 403, verify(c23, C, "token="+token(page)+"&pow="+strconv.Itoa(counter+1)).status, "错误的工作量证明被拒绝")
	c24, page := fresh("127.0.0.24")
	salt := field(page, "data-salt")
	page = c24.get(C, "/article?id=7").body
	answer := solvePoW(salt, 18)
	time.Sleep(5200 * time.Millisecond)
	check("CC-POW-3", 403, verify(c24, C, "token="+token(page)+"&pow="+answer).status, "用另一个页面的盐算出的答案被拒绝（盐绑定一次性 token）")

	page = visitor.get(C, "/article?id=7").body
	body := "token=" + token(page) + "&pow=" + pagePoW(page)
	time.Sleep(5200 * time.Millisecond)
	passed := verify(visitor, C, body)
	location := strings.TrimPrefix(passed.header.Get("Location"), "http://"+C)
	check("CC-4", "303 /article?id=7", fmt.Sprintf("%d %s", passed.status, location), "做完工作量证明并等满 5 秒后通过、跳回原页面")
	check("CC-REPLAY", 403, verify(newClient("127.0.0.1"), C, body).status, "同一 token 与答案重放被拒绝（一次性）")
	check("CC-5", 200, visitor.code(C, "/article?id=7"), "通过后携带白名单 Cookie 放行")
	ok := 0
	for range 20 {
		if visitor.code(C, "/list") == 200 {
			ok++
		}
	}
	check("CC-6", 20, ok, "白名单内 20 次连续请求全部放行")
	cookie := visitor.cookies["__cdnca_cc_pass"]
	check("CC-COOKIE", true, strings.HasPrefix(cookie, "v2."), "通行 Cookie 为 v2（HMAC-SHA256）")
	tampered := cookie[:len(cookie)-1] + map[bool]string{true: "1", false: "0"}[strings.HasSuffix(cookie, "0")]
	check("CC-7", 503, newClient("127.0.0.1").send("GET", C, "/article?id=7", "", map[string]string{"Cookie": "__cdnca_cc_pass=" + tampered}).status, "篡改 Cookie 签名重新验证")
	with := func(source string, headers map[string]string) int {
		c := newClient(source)
		h := map[string]string{"Cookie": "__cdnca_cc_pass=" + cookie}
		for k, v := range headers {
			h[k] = v
		}
		return c.send("GET", C, "/article?id=7", "", h).status
	}
	check("CC-IP-1", 200, with("127.0.0.9", nil), "同一 /24 网段换 IP 仍有效（目录参数 bind_ipv4_prefix=24）")
	check("CC-IP-2", 503, with("127.0.1.5", nil), "Cookie 换到其它网段的 IP 失效")
	check("CC-8", 503, with("127.0.0.1", map[string]string{"User-Agent": "curl/8 other-agent"}), "Cookie 换 UA 无效")
	banned := newClient("127.0.0.1")
	last := 0
	for range 6 {
		last = banned.code(C, "/article?id=7")
	}
	check("CC-9", 403, last, "60 秒内验证失败超过 5 次拉黑")
	check("CC-10", 403, with("127.0.0.1", nil), "拉黑期间带 Cookie 也拒绝")
}

// ---------------------------------------------------------------- params

// paramsRun: the 5秒盾 group with changed catalog values (PoW 20 bits, wait
// 2 s, 2 failures, ban 30 s, /32 binding), and the CRS PL2 profile.
func paramsRun() {
	P := host("params")
	visitor := newClient("127.0.0.1")
	page := visitor.get(P, "/a").body
	check("PARAM-1", "20", field(page, "data-bits"), "PoW 难度随目录参数改为 20 位")
	body := "token=" + token(page) + "&pow=" + solvePoW(field(page, "data-salt"), 20)
	time.Sleep(2200 * time.Millisecond)
	check("PARAM-2", 303, verify(visitor, P, body).status, "等待时间随目录参数改为 2 秒（2.2 秒后提交即通过）")
	check("PARAM-3", 200, visitor.code(P, "/a"), "通过后放行")
	other := newClient("127.0.0.9")
	other.cookies = visitor.cookies
	check("PARAM-4", 503, other.code(P, "/a"), "绑定改为 /32 后同网段换 IP 也失效")
	c31 := newClient("127.0.0.31")
	last := 0
	for range 3 {
		last = c31.code(P, "/a")
	}
	check("PARAM-5", 403, last, "失败次数随目录参数改为 2 次：第 3 次未通过即拉黑")
	retry, _ := strconv.Atoi(c31.get(P, "/a").header.Get("Retry-After"))
	check("PARAM-6", true, retry > 0 && retry <= 30, fmt.Sprintf("拉黑时长随目录参数改为 30 秒（Retry-After=%d）", retry))
	check("WAFP-3", 403, newClient("127.0.0.1").code(host("wafpl2"), "/?user=admin%27%23"), "CRS 增强档位（PL2）下 admin'# 被拦截")
}

// ---------------------------------------------------------------- rate (宽松)

// burst sends count requests on one keep-alive connection, starting on a
// 5 s window edge (the fixed window is aligned to epoch seconds / 5).
func burst(hostname string, count int, path func(int) string) []int {
	transport := &http.Transport{MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, DisableCompression: true}
	c := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	for time.Now().Unix()%5 != 0 || time.Now().Nanosecond() > 300e6 {
		time.Sleep(20 * time.Millisecond)
	}
	codes := make([]int, 0, count)
	for index := 1; index <= count; index++ {
		request, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", edge, path(index)), nil)
		request.Host = hostname
		request.Header.Set("User-Agent", userAgent)
		result, err := c.Do(request)
		if err != nil {
			codes = append(codes, -1)
			continue
		}
		_, _ = io.Copy(io.Discard, result.Body)
		result.Body.Close()
		codes = append(codes, result.StatusCode)
	}
	transport.CloseIdleConnections()
	return codes
}

func blocked(status int) string {
	if status == 403 || status == 429 {
		return "blocked"
	}
	return fmt.Sprintf("pass(%d)", status)
}

func rateRun() {
	codes := burst(host("rate"), 301, func(n int) string { return "/p" + strconv.Itoa(n) })
	check("RATE-1", "pass(200)", blocked(codes[299]), "5 秒内第 300 次（不同 URL）未超限放行")
	check("RATE-2", "blocked", blocked(codes[300]), "第 301 次超过 300 次阈值被拦截")
	codes = burst(host("uri"), 51, func(n int) string { return "/same?n=" + strconv.Itoa(n) })
	check("RATE-3", "pass(200)", blocked(codes[49]), "同一 URL 5 秒内第 50 次放行")
	check("RATE-4", "blocked", blocked(codes[50]), "同一 URL 5 秒内第 51 次超过单 URL 50 次阈值被拦截")
}

// ---------------------------------------------------------------- agg

type securityLine struct {
	Type     string `json:"security_type"`
	Action   string `json:"action"`
	ClientIP string `json:"client_ip"`
	Host     string `json:"host"`
	Count    uint32 `json:"count"`
}

func securityLines(hostname, source string) []securityLine {
	raw, _ := os.ReadFile(sharedPath(filepath.Join(filepath.FromSlash(edgeconfig.DynamicRoutingTelemetryDir), "security.jsonl")))
	var lines []securityLine
	for _, text := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var line securityLine
		if json.Unmarshal([]byte(text), &line) == nil && line.Host == hostname && line.ClientIP == source {
			lines = append(lines, line)
		}
	}
	return lines
}

func describe(lines []securityLine) string {
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		parts = append(parts, fmt.Sprintf("%s/%s count=%d", line.Type, line.Action, line.Count))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// aggRun (sec-log-agg): within one minute, 10 challenge pages of one client,
// a reload, 5 more: one security line with count=15 (the reload keeps the
// shared dictionary and the new worker 0 writes it: nothing counted before
// the reload is lost); a 429 rate limit ban is one temporary_ban line (the
// ban's own request) and its 429s one aggregated block line; after the
// minute the flush writes them.
func aggRun() {
	for time.Now().Second() > 30 {
		time.Sleep(500 * time.Millisecond) // the requests stay inside one minute
	}
	A := host("agg")
	challenged := newClient("127.0.0.61")
	pages := 0
	for range 10 {
		if r := challenged.get(A, "/agg"); r.status == 503 && r.header.Get("X-Cdnca-Challenge") != "" {
			pages++
		}
	}
	check("AGG-PAGES", 10, pages, "同一 IP 一分钟内 10 次未验证请求都返回验证页")
	if err := openresty("-s", "reload"); err != nil {
		check("AGG-RELOAD", nil, err, "分钟内 reload")
	}
	time.Sleep(1500 * time.Millisecond) // old workers gone, new worker 0 has its timer
	pages = 0
	for range 5 {
		if r := challenged.get(A, "/agg"); r.status == 503 && r.header.Get("X-Cdnca-Challenge") != "" {
			pages++
		}
	}
	check("AGG-PAGES-RELOAD", 5, pages, "reload 后同一分钟再 5 次仍返回验证页")
	// 宽松 (5 s 50 per URI, ban 360 s): request 51 bans, the next 10 are
	// 429s; its own source (rate bans 127.0.0.1 on this site)
	limited := newClient("127.0.0.62")
	for time.Now().Unix()%5 != 0 || time.Now().Nanosecond() > 300e6 {
		time.Sleep(20 * time.Millisecond)
	}
	rejected := 0
	for index := 1; index <= 61; index++ {
		if code := limited.code(host("uri"), "/agg?n="+strconv.Itoa(index)); index > 50 && code == 429 {
			rejected++
		}
	}
	check("AGG-429", 11, rejected, "超过单 URL 阈值的第 51 次封禁、其后 10 次均 429")
	check("AGG-PENDING", "", describe(securityLines(A, "127.0.0.61")), "分钟结束前挑战页不逐条写安全日志")
	wait := time.Until(time.Now().Truncate(time.Minute).Add(time.Minute)) + 7*time.Second
	fmt.Printf("INFO agg: waiting %s for the minute flush\n", wait.Round(time.Second))
	time.Sleep(wait)
	check("SEC-LOG-AGG-CHALLENGE", "cc/challenge count=15", describe(securityLines(A, "127.0.0.61")),
		"挑战 10 次 + reload + 5 次 → 1 行 count=15（reload 不丢计数）")
	check("SEC-LOG-AGG-429", "cc/block count=10, cc/temporary_ban count=0", describe(securityLines(host("uri"), "127.0.0.62")),
		"429 10 次 → 1 行 count=10；临时封禁逐条（1 行，无 count）")
}

// ---------------------------------------------------------------- modes

var shapeOrder = map[string]int{"圆形": 1, "方形": 2, "三角形": 3, "菱形": 4}

// answerFor reads the page the way a visitor solves it (the retired probe's
// solve()).
func answerFor(mode, page string) string {
	switch mode {
	case "js", "delay":
		return ""
	case "easy_click":
		return field(page, "data-a")
	case "easy_slider":
		return "100"
	case "slider":
		if match := regexp.MustCompile(`把滑块拖到 (\d+)% 的位置`).FindStringSubmatch(page); match != nil {
			return match[1]
		}
	case "rotate":
		angle, _ := strconv.Atoi(field(page, "data-base"))
		return strconv.Itoa(360 - angle)
	case "click":
		match := regexp.MustCompile(`请点击 <strong>([^<]*)</strong>`).FindStringSubmatch(page)
		ids := regexp.MustCompile(`data-id="([0-9a-f]*)"`).FindAllStringSubmatch(page, -1)
		if match != nil && len(ids) == 4 {
			return ids[shapeOrder[match[1]]-1][1]
		}
	case "captcha":
		return "WRONG" // the characters exist only as SVG dots
	}
	return ""
}

func solve(id, name, want string) {
	H := host(name)
	visitor := newClient("127.0.0.1")
	first := visitor.get(H, "/p?x=1")
	check(id+"-page", want, challengeMode(first), "首次访问弹出对应验证")
	mode := first.header.Get("X-Cdnca-Challenge")
	check(id+"-nopow", 403, verify(newClient("127.0.0.1"), H, "token="+token(first.body)+"&answer=x").status, "不做工作量证明直接提交被拒绝")
	page := visitor.get(H, "/p?x=1").body
	body := "token=" + token(page) + "&answer=" + answerFor(mode, page) + "&pow=" + pagePoW(page)
	time.Sleep(600 * time.Millisecond)
	result := verify(visitor, H, body)
	if mode == "captcha" {
		check(id+"-wrong", 403, result.status, "验证码答错被拒绝（字符只在 SVG 点阵里，脚本无法直接读出）")
		return
	}
	check(id+"-verify", 303, result.status, "按页面要求作答后通过")
	check(id+"-pass", 200, visitor.code(H, "/p?x=1"), "通过后放行")
	if mode == "slider" || mode == "rotate" {
		// a wrong position is refused (tolerance 4 / 12)
		c := newClient("127.0.0.40")
		page := c.get(H, "/p?x=1").body
		right, _ := strconv.Atoi(answerFor(mode, page))
		wrong := strconv.Itoa((right + 40) % 100)
		if mode == "rotate" {
			wrong = strconv.Itoa((right + 90) % 360)
		}
		time.Sleep(600 * time.Millisecond)
		check(id+"-off", 403, verify(c, H, "token="+token(page)+"&answer="+wrong+"&pow="+pagePoW(page)).status, "位置偏离要求被拒绝")
	}
}

func modesRun() {
	solve("G1", "g1", "js(503)")
	solve("G10000", "g10000", "click(503)")
	solve("G10003", "g10003", "rotate(503)")
	solve("G10004", "g10004", "easy_click(503)")
	solve("G10005", "g10005", "easy_slider(503)")
	solve("G2", "g2", "slider(503)")
	solve("G4", "g4", "captcha(503)")
}

// ---------------------------------------------------------------- engines

type payload struct{ id, method, path, body string }

// enginePayloads: the retired probe's corpus (E = attack, N = normal).
var enginePayloads = []payload{
	{"E01", "GET", "/?id=1%27%20OR%20%271%27%3D%271", ""},
	{"E02", "GET", "/?id=1%20UNION%20SELECT%20username,password%20FROM%20users", ""},
	{"E03", "GET", "/?id=1%2527%2520OR%25201%253D1--", ""},
	{"E04", "GET", "/?id=1%27%20AND%20SLEEP(5)--", ""},
	{"E05", "GET", "/?id=1;%20DROP%20TABLE%20users--", ""},
	{"E06", "GET", "/?user=admin%27%23", ""},
	{"E07", "GET", "/?id=1%27/**/UnIoN/**/SeLeCt/**/1,2--", ""},
	{"E08", "GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", ""},
	{"E09", "GET", "/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", ""},
	{"E10", "GET", "/?next=javascript:alert(1)", ""},
	{"E11", "GET", "/?q=%253Csvg%252Fonload%253Dalert(1)%253E", ""},
	{"E12", "GET", "/?q=%3Cdetails%20open%20ontoggle%3Dalert(1)%3E", ""},
	{"E13", "GET", "/?u=%3Ca%20href%3D%22jav%26%23x09%3Bascript:alert(1)%22%3Ex%3C/a%3E", ""},
	{"E14", "POST", "/login", "user=admin%27%20OR%201%3D1--&pass=x"},
	{"E15", "JSON", "/api", `{"id":"1 UNION SELECT password FROM users"}`},
	{"E16", "POST", "/comment", "body=%3Ciframe%20src%3D//evil%3E"},
	{"N01", "GET", "/?q=hello+world", ""},
	{"N02", "GET", "/?name=O%27Brien", ""},
	{"N03", "GET", "/?q=select+a+card+or+union+membership", ""},
	{"N04", "JSON", "/api", `{"comment":"I'd like 2 items -- thanks"}`},
	{"N05", "POST", "/form", "user=alice&bio=Tom+%26+Jerry+fan"},
	{"N06", "GET", "/?url=https%3A%2F%2Fexample.com%2Fa%3Fb%3D1", ""},
}

// sendPayload prefixes the path with /probe-<tag> so each engine's own log
// can be searched for it.
func sendPayload(hostname, tag string, p payload) int {
	c := newClient("127.0.0.1")
	path := "/probe-" + tag + p.path
	switch p.method {
	case "POST":
		return c.send("POST", hostname, path, p.body, nil).status
	case "JSON":
		return c.send("POST", hostname, path, p.body, map[string]string{"Content-Type": "application/json"}).status
	}
	return c.code(hostname, path)
}

func verdict(status int) string {
	if status == 403 {
		return "block"
	}
	return "pass"
}

func enginesRun() {
	attacks, selfHits, crsHits, dualHits := 0, 0, 0, 0
	selfBlocked := map[string]bool{}
	crsBlocked := map[string]bool{}
	for _, p := range enginePayloads {
		s := verdict(sendPayload(host("self"), p.id, p))
		c := verdict(sendPayload(host("waf"), p.id, p))
		d := verdict(sendPayload(host("dual"), p.id, p))
		fmt.Printf("ENGINE %s self=%s crs=%s dual=%s\n", p.id, s, c, d)
		if strings.HasPrefix(p.id, "N") {
			check(p.id+"-FP", "pass/pass/pass", s+"/"+c+"/"+d, "正常请求两套引擎都不误报")
			continue
		}
		attacks++
		expected := "pass"
		if s == "block" || c == "block" {
			expected = "block"
		}
		if s == "block" {
			selfHits++
			selfBlocked[p.id] = true
		}
		if c == "block" {
			crsHits++
			crsBlocked[p.id] = true
		}
		if d == "block" {
			dualHits++
		}
		check(p.id+"-OR", expected, d, fmt.Sprintf("两者都开：任一引擎拦截即拦截（自研=%s CRS=%s）", s, c))
	}
	fmt.Printf("ENGINE-SUMMARY attacks=%d self=%d crs=%d dual=%d\n", attacks, selfHits, crsHits, dualHits)
	// Both engines log only: every request passes, each engine records its
	// own hits (self-developed: the security log; CRS: the audit log).
	for _, p := range enginePayloads {
		check(p.id+"-LOG", 200, sendPayload(host("duallog"), p.id+"L", p), "两者仅记录：放行")
	}
	time.Sleep(time.Second)
	securityLog, _ := os.ReadFile(sharedPath(filepath.Join(filepath.FromSlash(edgeconfig.DynamicRoutingTelemetryDir), "security.jsonl")))
	auditLog, _ := os.ReadFile(sharedPath("modsecurity-audit.log"))
	selfLogged, crsLogged := 0, 0
	for _, p := range enginePayloads {
		if !strings.HasPrefix(p.id, "E") {
			continue
		}
		marker := "/probe-" + p.id + "L/"
		selfLines, crsLines := 0, 0
		for _, line := range strings.Split(string(securityLog), "\n") {
			if strings.Contains(line, `"path":"`+marker) && strings.Contains(line, `"action":"log"`) {
				selfLines++
			}
		}
		for _, line := range strings.Split(string(auditLog), "\n") {
			if strings.Contains(line, marker) && strings.Contains(line, "cdnca waf log waf_set:crs_") {
				crsLines++
			}
		}
		if selfLines > 0 && selfBlocked[p.id] {
			selfLogged++
		}
		if crsLines > 0 && crsBlocked[p.id] {
			crsLogged++
		}
		fmt.Printf("ENGINE-LOG %s self_logged=%d crs_logged=%d\n", p.id, selfLines, crsLines)
	}
	lines := strings.Count(strings.TrimSpace(string(securityLog)), "\n")
	if len(strings.TrimSpace(string(securityLog))) > 0 {
		lines++
	}
	fmt.Printf("INFO security.jsonl lines=%d (blocks of every site above included)\n", lines)
	check("ENG-LOG-SELF", selfHits, selfLogged, "仅记录模式下自研检测命中都写入安全日志")
	check("ENG-LOG-CRS", crsHits, crsLogged, "仅记录模式下 CRS 命中都写入 ModSecurity 审计日志")
	check("ENG-SELFALL", 403, newClient("127.0.0.1").code(host("selfall"), "/?c=1%3Bcat%20/etc/hosts"), "全部 10 个自研规则集：命令注入拦截")
}

// ---------------------------------------------------------------- agent

// agentRun: every security line the node wrote goes the agent's way to the
// event spool (dyntelemetry.Normalize back to the site's v7 line, then
// eventspool.ParseSourceLineBound, what the spool accepts and uploads); the
// CC and WAF blocks of the parts that ran are among them (sec-log-fix).
func agentRun(wantCC, wantWAF bool) {
	time.Sleep(500 * time.Millisecond)
	raw, _ := os.ReadFile(sharedPath(filepath.Join(filepath.FromSlash(edgeconfig.DynamicRoutingTelemetryDir), "security.jsonl")))
	sites := &dyntelemetry.ObjectSites{Root: filepath.Join(*state, "site-objects"), Limit: 1 << 20}
	total, bad := 0, 0
	kinds := map[string]int{}
	counted := map[string]uint32{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		total++
		result, err := dyntelemetry.Normalize([]byte(line), registry, sites, "0d120000-0000-4000-8000-00000000cc01")
		if err == nil {
			var envelope eventspool.Envelope
			if envelope, err = eventspool.ParseSourceLineBound(result.Line, result.CapturePolicy, result.Identity); err == nil {
				if envelope.Type != eventspool.EventSecurity || envelope.ConfigVersionID != auditVersion {
					err = fmt.Errorf("type %s version %s", envelope.Type, envelope.ConfigVersionID)
				}
				kinds[envelope.SecurityType+"/"+envelope.Action]++
				if envelope.Count > 0 {
					counted[envelope.SecurityType+"/"+envelope.Action] += envelope.Count
				}
			}
		}
		if err != nil {
			bad++
			if bad <= 3 {
				fmt.Printf("INFO agent refused: %v\n  %s\n", err, line)
			}
		}
	}
	fmt.Printf("INFO agent security events: %d lines, by type/action %v, aggregated requests %v\n", total, kinds, counted)
	check("SEC-LOG-AGENT", 0, bad, "安全日志每一行都被 agent 归属还原并被事件池接受（上报）")
	count := func(kind string) int {
		n := 0
		for key, value := range kinds {
			if strings.HasPrefix(key, kind+"/") {
				n += value
			}
		}
		return n
	}
	if wantCC {
		check("SEC-LOG-CC", true, count("cc") > 0, "CC 拦截写入安全日志并被 agent 上报")
	}
	if parts := strings.Split(*only, ","); len(*only) == 0 || slices.Contains(parts, "agg") {
		check("SEC-LOG-AGG-AGENT", true, counted["cc/challenge"] >= 10 && counted["cc/block"] >= 10,
			"聚合行（带 count）被 agent 归属还原、事件池接受且保留计数")
	}
	if wantWAF {
		check("SEC-LOG-WAF", true, count("waf") > 0, "WAF 拦截写入安全日志并被 agent 上报")
	}
}

// ---------------------------------------------------------------- bench

type benchResult struct {
	p50, p99, rps float64
	statuses      map[int]int
}

// load: total requests over conc keep-alive connections (the retired
// bench's load.lua: same request, warm-up round, median by req/s).
func load(hostname, method, path, body string) benchResult {
	round := func() benchResult {
		per := *benchN / *benchC
		latencies := make(chan float64, per**benchC)
		statuses := make(chan int, per**benchC)
		started := time.Now()
		done := make(chan struct{})
		for range *benchC {
			go func() {
				defer func() { done <- struct{}{} }()
				transport := &http.Transport{MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, DisableCompression: true}
				c := &http.Client{Transport: transport, Timeout: 10 * time.Second}
				defer transport.CloseIdleConnections()
				for range per {
					var reader io.Reader
					if body != "" {
						reader = strings.NewReader(body)
					}
					request, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", edge, path), reader)
					request.Host = hostname
					request.Header.Set("User-Agent", "Mozilla/5.0 bench")
					if body != "" {
						request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					}
					at := time.Now()
					result, err := c.Do(request)
					if err != nil {
						statuses <- -1
						continue
					}
					_, _ = io.Copy(io.Discard, result.Body)
					result.Body.Close()
					latencies <- float64(time.Since(at).Microseconds())
					statuses <- result.StatusCode
				}
			}()
		}
		for range *benchC {
			<-done
		}
		elapsed := time.Since(started).Seconds()
		close(latencies)
		close(statuses)
		var values []float64
		for value := range latencies {
			values = append(values, value)
		}
		sort.Float64s(values)
		counts := map[int]int{}
		for status := range statuses {
			counts[status]++
		}
		at := func(q float64) float64 {
			if len(values) == 0 {
				return 0
			}
			return values[min(len(values)-1, int(q*float64(len(values))))]
		}
		return benchResult{p50: at(0.5), p99: at(0.99), rps: float64(len(values)) / elapsed, statuses: counts}
	}
	round() // warm-up
	results := make([]benchResult, 0, *benchRounds)
	for range *benchRounds {
		results = append(results, round())
	}
	sort.Slice(results, func(i, j int) bool { return results[i].rps < results[j].rps })
	return results[len(results)/2]
}

func benchRun() {
	const (
		benign = "/search?q=customer+review+text+with+words+and+123+numbers&page=2&sort=price"
		form   = "user=alice&comment=%E8%BF%99%E4%B8%AA%E4%BA%A7%E5%93%81%E5%BE%88%E5%A5%BD%EF%BC%8C%E4%B8%8B%E6%AC%A1%E8%BF%98%E4%BC%9A%E4%B9%B0&rating=5"
		attack = "/item?id=1%27%20UNION%20SELECT%20password%20FROM%20users--"
	)
	fmt.Printf("BENCH workers=%d requests=%d concurrency=%d rounds=%d (median by req/s)\n", *workers, *benchN, *benchC, *benchRounds)
	for _, name := range []string{"plain", "wafall", "wafallpl2", "wafallpl3"} {
		for _, variant := range []struct{ label, method, path, body string }{
			{"GET  benign", "GET", benign, ""}, {"POST form  ", "POST", "/signup", form}, {"GET  attack", "GET", attack, ""}} {
			r := load(host(name), variant.method, variant.path, variant.body)
			codes := make([]string, 0, len(r.statuses))
			for code, count := range r.statuses {
				codes = append(codes, fmt.Sprintf("%dx%d", code, count))
			}
			sort.Strings(codes)
			fmt.Printf("BENCH %-10s %s p50 %.0f us  p99 %.0f us  %.0f req/s  status %s\n", name, variant.label, r.p50, r.p99, r.rps, strings.Join(codes, ","))
		}
	}
}

// ---------------------------------------------------------------- main

func main() {
	flag.Parse()
	if *replay != "" {
		// BROWSER=1: the browser's pass cookie from the container's own
		// loopback (another network than the browser's) against the running
		// node; prints the status only.
		cookie, _ := os.ReadFile(*replay)
		ua, _ := os.ReadFile(*replayUA)
		c := newClient("127.0.0.1")
		fmt.Println(c.send("GET", host("cc"), "/article?id=7", "", map[string]string{
			"Cookie": "__cdnca_cc_pass=" + strings.TrimSpace(string(cookie)), "User-Agent": strings.TrimSpace(string(ua))}).status)
		return
	}
	if err := serveOrigin(); err != nil {
		fmt.Println("FAIL origin", err)
		os.Exit(1)
	}
	if err := startNode(); err != nil {
		fmt.Println("FAIL start", err)
		os.Exit(1)
	}
	parts := map[string]bool{}
	for _, part := range strings.Split(*only, ",") {
		if part != "" {
			parts[part] = true
		}
	}
	if parts["serve"] {
		fmt.Println("READY")
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
		<-signals
		stop()
		return
	}
	defer stop()
	all := len(parts) == 0
	for _, part := range []struct {
		name string
		run  func()
	}{{"cc", ccRun}, {"modes", modesRun}, {"params", paramsRun}, {"rate", rateRun}, {"agg", aggRun}, {"engines", enginesRun}, {"bench", benchRun}} {
		if all && part.name == "bench" {
			continue // explicit only: it measures, it does not check
		}
		if all || parts[part.name] {
			part.run()
		}
	}
	if all || parts["cc"] || parts["rate"] || parts["agg"] || parts["engines"] {
		agentRun(all || parts["cc"] || parts["rate"] || parts["agg"], all || parts["engines"])
	}
	raw, _ := os.ReadFile(sharedPath("error.log"))
	bad := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "[crit]") || strings.Contains(line, "[alert]") || strings.Contains(line, "[emerg]") {
			bad++
			if bad <= 5 {
				fmt.Println("INFO error.log", line)
			}
		}
	}
	check("ERROR-LOG", 0, bad, "error.log 无 crit/alert/emerg")
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures != 0 {
		os.Exit(1)
	}
}
