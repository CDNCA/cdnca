package main

// -only adaptive: the adaptive managed WAF of ADR 0011 RI-03 on a real
// node (c3 context, grey zone challenge and floor, shape signal, automatic
// exclusions in an exclusion bucket location, sampled audit). Sites: s (严格防护,
// grey challenge on, a typed parameter and an automatic exclusion), o
// (严格防护, grey challenge off), p (标准防护 with the same waf_adapt entry:
// never challenges, Q3), f (严格防护, grey challenge on, grey floor 6). The
// waf_adapt entries go through the node control socket (POST /waf-adapt/),
// as the agent writes them; the exclusions are in the skeleton.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// greyValue scores one CRS PL2 critical hit (941380, 5) and nothing at PL1:
// on 严格防护 strong 0, weak 5 < 10, the grey zone (eval: passed by every
// tier, probe rules [941380]).
const greyValue = "{{name}}"

// adaptiveCost: the adaptive path's per request cost on real requests
// (RI-03 item 5): the same clean query on o (严格防护: detectors, waf_adapt
// entry, two-level scoring; grey challenge off so nothing is challenged)
// and on s (the same plus shape on a typed parameter and its bucket location
// with an automatic exclusion), each against p (标准防护: none of it),
// interleaved rounds of -requests sequential requests, p50 / p99 of the
// rounds' medians. Informational (load dependent): INFO and ADAPTIVE lines.
func adaptiveCost() {
	type sampleSet struct{ p50, p99 []float64 }
	paths := map[string]string{"o.waf.test": "/item/7?id=123&q=hello+world", "s.waf.test": "/item/7?id=123&q=hello+world",
		"p.waf.test": "/item/7?id=123&q=hello+world"}
	headers := map[string]string{"Accept": "application/json"}
	results := map[string]*sampleSet{}
	for round := range *rounds {
		for _, host := range []string{"p.waf.test", "o.waf.test", "s.waf.test"} {
			for range 200 {
				send(http.MethodGet, host, paths[host], "", headers)
			}
			durations := make([]float64, 0, *requests)
			for range *requests {
				started := time.Now()
				if r := send(http.MethodGet, host, paths[host], "", headers); r.status != 200 {
					check("adaptive cost "+host, false, "status %d", r.status)
					return
				}
				durations = append(durations, float64(time.Since(started).Microseconds()))
			}
			sort.Float64s(durations)
			at := func(q float64) float64 { return durations[min(len(durations)-1, int(q*float64(len(durations))))] }
			if results[host] == nil {
				results[host] = &sampleSet{}
			}
			results[host].p50 = append(results[host].p50, at(0.5))
			results[host].p99 = append(results[host].p99, at(0.99))
			fmt.Printf("INFO adaptive cost round %d %s p50=%.0fus p99=%.0fus\n", round, host, at(0.5), at(0.99))
		}
	}
	median := func(values []float64) float64 {
		sorted := append([]float64(nil), values...)
		sort.Float64s(sorted)
		return sorted[len(sorted)/2]
	}
	summary := map[string]any{"requests_per_round": *requests, "rounds": *rounds}
	for host, set := range results {
		summary[strings.TrimSuffix(host, ".waf.test")] = map[string]float64{"p50_us": median(set.p50), "p99_us": median(set.p99)}
	}
	for _, host := range []string{"o", "s"} {
		summary[host+"_extra_p50_us"] = median(results[host+".waf.test"].p50) - median(results["p.waf.test"].p50)
		summary[host+"_extra_p99_us"] = median(results[host+".waf.test"].p99) - median(results["p.waf.test"].p99)
	}
	encoded, _ := json.Marshal(summary)
	fmt.Printf("ADAPTIVE %s\n", encoded)
}

// controlPost posts body to path on the node control socket.
func controlPost(path string, body any) (int, string) {
	socket := filepath.Join(*state, "run", "cdnca-site-admin.sock")
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	encoded, _ := json.Marshal(body)
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Post("http://control"+path, "application/json", bytes.NewReader(encoded))
	if err != nil {
		return 0, err.Error()
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(raw)
}

type reply struct {
	status  int
	headers http.Header
	body    string
}

var noRedirect = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func send(method, host, path, body string, headers map[string]string) reply {
	return sendFrom(noRedirect, method, host, path, body, headers)
}

// spread is a client per local source address 127.0.1.<1-250>: a bulk of
// grey zone requests that stands for many clients stays below the repeated
// grey zone source threshold (edgeconfig.DynamicWAFRepeat, per site x
// address).
var spread = func() []*http.Client {
	clients := make([]*http.Client, 250)
	for index := range clients {
		dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 1, byte(index+1))}}
		clients[index] = &http.Client{Transport: &http.Transport{DisableKeepAlives: true, DialContext: dialer.DialContext},
			Timeout: 20 * time.Second, CheckRedirect: noRedirect.CheckRedirect}
	}
	return clients
}()

// sendSpread is send from source address index (mod 250).
func sendSpread(index int, method, host, path, body string, headers map[string]string) reply {
	return sendFrom(spread[index%len(spread)], method, host, path, body, headers)
}

func sendFrom(client *http.Client, method, host, path, body string, headers map[string]string) reply {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", edge, path), reader)
	request.Host = host
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return reply{}
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return reply{status: response.StatusCode, headers: response.Header, body: string(raw)}
}

// passCookie is the grey zone pass cookie a reply sets ("" when none).
func passCookie(r reply) string {
	for _, value := range r.headers.Values("Set-Cookie") {
		if strings.HasPrefix(value, "__cdnca_waf_grey=") {
			return strings.SplitN(value, ";", 2)[0]
		}
	}
	return ""
}

var powData = regexp.MustCompile(`name="token" value="([0-9a-f]{32})".*data-salt="([0-9a-f]+)" data-bits="([0-9]+)"`)

// solve answers a grey zone challenge page as its script would: finds the
// proof of work and posts it to the verification path; returns the pass.
func solve(host string, page reply, headers map[string]string) string {
	match := powData.FindStringSubmatch(page.body)
	if match == nil {
		return ""
	}
	want, _ := strconv.Atoi(match[3])
	counter := proofOfWork(match[2], want)
	form := url.Values{"token": {match[1]}, "pow": {counter}}.Encode()
	verifyHeaders := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for name, value := range headers {
		verifyHeaders[name] = value
	}
	return passCookie(send(http.MethodPost, host, "/.cdnca/waf/verify", form, verifyHeaders))
}

func adaptiveRun() {
	all := profiles()
	strict, standard := profileNamed(all, "system/crs-pl2"), profileNamed(all, "system/crs-pl1")
	sites := []edgesite.Site{
		makeSite(60, "s.waf.test", &wafSpec{profile: strict}),
		makeSite(61, "o.waf.test", &wafSpec{profile: strict}),
		makeSite(62, "p.waf.test", &wafSpec{profile: standard}),
		makeSite(63, "f.waf.test", &wafSpec{profile: strict}),
	}
	// automatic exclusion of 941380 on ARGS:note on s only (its exclusion bucket)
	siteTargets = map[string][]edgeconfig.DynamicWAFTarget{siteID(60): {{Rule: 941380, Location: "args", Name: "note"}}}
	defer func() { siteTargets = nil }()
	if _, err := startNode(sites, true); err != nil {
		check("adaptive start", false, "%v", err)
		return
	}
	defer stop()
	// typed parameter id (number) on /item/{n}
	typed := []autodefense.WAFTypedParam{{Key: autodefense.WAFParamKey("/item/{n}", "args", "id"), Type: "number", MaxLenBucket: 4}}
	entry := func(site string, grey bool, floor int) map[string]any {
		typed := typed
		if site == siteID(60) {
			// waf-cookie-fp2: s's learned cookie profile (cookieChecks)
			typed = append(slices.Clone(typed), profiledCookie)
			slices.SortFunc(typed, func(a, b autodefense.WAFTypedParam) int { return strings.Compare(a.Key, b.Key) })
		}
		out := map[string]any{"site_id": site, "grey_challenge": grey, "grey_floor": floor, "typed_params": typed}
		if site == siteID(63) {
			// ri-wire Cookie 名集合: f is cookie mature and knows pref, sid
			out["cookie_names"] = knownCookieNames
		}
		return out
	}
	badNames := entry(siteID(63), true, 0)
	badNames["cookie_names"] = []string{"XYZ"}
	bad, _ := controlPost("/waf-adapt/", map[string]any{"sites": []any{badNames}})
	check("adaptive write bad cookie names", bad == 400, "POST /waf-adapt/ cookie_names XYZ: %d", bad)
	bad, _ = controlPost("/waf-adapt/", map[string]any{"sites": []any{entry(siteID(63), true, edgeconfig.DynamicWAFMaxGreyFloor+1)}})
	check("adaptive write bad floor", bad == 400, "POST /waf-adapt/ grey_floor 100: %d", bad)
	status, text := controlPost("/waf-adapt/", map[string]any{"sites": []any{entry(siteID(60), true, 0), entry(siteID(61), false, 0),
		entry(siteID(62), true, 0), entry(siteID(63), true, autodefense.GreyFloorFromP99(autodefense.GreyFloorProfile{Mature: true,
			Requests: autodefense.MinGreyFloorRequests, WeakP99: 5}, 10))}})
	check("adaptive write", status == 204, "POST /waf-adapt/ %d %s", status, text)
	browser := map[string]string{"Accept": "text/html"}
	grey := "/t?v=" + url.QueryEscape(greyValue)

	// c3 parses: a clean request passes on every site
	for _, host := range []string{"s.waf.test", "o.waf.test", "p.waf.test", "f.waf.test"} {
		r := send(http.MethodGet, host, "/t?v=hello", "", browser)
		check("c3 clean "+host, r.status == 200, "clean request %d", r.status)
	}
	// grey zone GET: challenged on s, passes with the pass cookie
	page := send(http.MethodGet, "s.waf.test", grey, "", browser)
	check("grey GET challenged", page.status == 503 && page.headers.Get("X-Cdnca-WAF") == "challenge" && powData.MatchString(page.body),
		"status %d header %q", page.status, page.headers.Get("X-Cdnca-WAF"))
	pass := solve("s.waf.test", page, browser)
	check("grey GET verify", pass != "", "pass cookie %q", pass)
	withPass := map[string]string{"Accept": "text/html", "Cookie": pass}
	again := send(http.MethodGet, "s.waf.test", grey, "", withPass)
	check("grey GET with pass", again.status == 200 && strings.HasPrefix(again.body, "ok s.waf.test"), "status %d body %.40q", again.status, again.body)
	forged := send(http.MethodGet, "s.waf.test", grey, "", map[string]string{"Accept": "text/html", "Cookie": "__cdnca_waf_grey=9999999999.00"})
	check("grey GET forged pass", forged.status == 503, "status %d", forged.status)
	// the pass never relaxes a strong score
	strong := send(http.MethodGet, "s.waf.test", sqli, "", withPass)
	check("strong with pass", strong.status == 403, "status %d", strong.status)
	// grey zone form POST: 307 to the same URL with the probe cookie, then
	// the same POST with it gets the pass and goes on with method and body
	form := "v=" + url.QueryEscape(greyValue)
	formHeaders := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	first := send(http.MethodPost, "s.waf.test", "/form", form, formHeaders)
	probe := ""
	for _, value := range first.headers.Values("Set-Cookie") {
		if strings.HasPrefix(value, "__cdnca_waf_probe=") {
			probe = strings.SplitN(value, ";", 2)[0]
		}
	}
	check("grey POST 307", first.status == 307 && first.headers.Get("Location") == "/form" && probe != "", "status %d location %q probe %q",
		first.status, first.headers.Get("Location"), probe)
	formHeaders["Cookie"] = probe
	second := send(http.MethodPost, "s.waf.test", "/form", form, formHeaders)
	postPass := passCookie(second)
	check("grey POST probe", second.status == 307 && postPass != "", "status %d pass %q", second.status, postPass)
	formHeaders["Cookie"] = postPass
	third := send(http.MethodPost, "s.waf.test", "/form", form, formHeaders)
	check("grey POST with pass", third.status == 200 && strings.HasPrefix(third.body, "ok s.waf.test"), "status %d", third.status)
	// API-like requests are never challenged
	for name, headers := range map[string]map[string]string{
		"json accept": {"Accept": "application/json"}, "authorization": {"Authorization": "Bearer x"}, "xhr": {"X-Requested-With": "XMLHttpRequest"},
	} {
		r := send(http.MethodGet, "s.waf.test", grey, "", headers)
		check("api not challenged "+name, r.status == 200, "status %d", r.status)
	}
	jsonBody := send(http.MethodPost, "s.waf.test", "/api", `{"v":"`+greyValue+`"}`, map[string]string{"Content-Type": "application/json"})
	check("api not challenged json body", jsonBody.status == 200, "status %d", jsonBody.status)
	// grey challenge off (o) and 标准防护 (p, Q3): the grey zone passes
	for _, host := range []string{"o.waf.test", "p.waf.test"} {
		r := send(http.MethodGet, host, grey, "", browser)
		check("grey passes "+host, r.status == 200, "status %d", r.status)
	}
	// automatic exclusion: 941380 on ARGS:note is removed on s (passes even
	// for a browser), not for another parameter, not on another site
	note := send(http.MethodGet, "s.waf.test", "/t?note="+url.QueryEscape(greyValue), "", browser)
	check("target exclusion", note.status == 200, "excluded target %d", note.status)
	other := send(http.MethodGet, "s.waf.test", "/t?other="+url.QueryEscape(greyValue), "", browser)
	check("target exclusion other param", other.status == 503, "other parameter %d", other.status)
	otherSite := send(http.MethodGet, "f.waf.test", "/t?note=%3Cscript%3Ealert(1)%3C/script%3E", "", browser)
	check("target exclusion other site", otherSite.status == 403, "same parameter on f %d", otherSite.status)
	strongNote := send(http.MethodGet, "s.waf.test", "/t?note=%3Cscript%3Ealert(1)%3C/script%3E", "", browser)
	check("target exclusion keeps other rules", strongNote.status == 403, "XSS in the excluded parameter %d", strongNote.status)
	// grey floor 6 on f (p99 5 of a matured profile): the weak score 5 of
	// the grey sample is below it and passes; a strong score still blocks
	floorGrey := send(http.MethodGet, "f.waf.test", grey, "", browser)
	check("grey floor passes", floorGrey.status == 200, "weak 5 under floor 6: %d", floorGrey.status)
	floorStrong := send(http.MethodGet, "f.waf.test", sqli, "", browser)
	check("grey floor keeps blocks", floorStrong.status == 403, "strong score %d", floorStrong.status)
	// shape: id is typed number on /item/{n}; alone a weak signal passes,
	// with a weak CRS hit it reaches the weak threshold (two signals:
	// repeatValue's 942380 weighs 5, shape 5)
	clean := send(http.MethodGet, "s.waf.test", "/item/7?id=123", "", map[string]string{"Accept": "application/json"})
	check("shape fits", clean.status == 200, "status %d", clean.status)
	alone := send(http.MethodGet, "s.waf.test", "/item/7?id=abc", "", map[string]string{"Accept": "application/json"})
	check("shape alone passes", alone.status == 200, "status %d", alone.status)
	// alone it is the grey zone: a browser-like request is challenged
	aloneBrowser := send(http.MethodGet, "s.waf.test", "/item/7?id=abc", "", browser)
	check("shape alone grey", aloneBrowser.status == 503, "status %d", aloneBrowser.status)
	both := send(http.MethodGet, "s.waf.test", "/item/7?id="+url.QueryEscape(repeatValue), "", map[string]string{"Accept": "application/json"})
	check("shape with weak hit blocks", both.status == 403, "status %d", both.status)
	standardShape := send(http.MethodGet, "p.waf.test", "/item/7?id="+url.QueryEscape(greyValue), "", map[string]string{"Accept": "application/json"})
	check("shape off on 标准防护", standardShape.status == 200, "status %d", standardShape.status)

	// sampled audit: grey zone transactions are written about 1/16, parts
	// A and H only; every block is written
	cookieChecks()
	auditPath := filepath.Join(*state, goldendyn.SharedDirectory, "modsecurity-audit.log")
	before := fileSize(auditPath)
	const greyRequests = 640
	for index := 0; index < greyRequests; index++ {
		sendSpread(index, http.MethodGet, "o.waf.test", grey, "", browser)
	}
	time.Sleep(200 * time.Millisecond)
	records := auditRecords(auditPath, before)
	greyRecords, partsOK, names := 0, true, map[string]bool{}
	for _, record := range records {
		if !strings.Contains(record, `"o.waf.test"`) && !strings.Contains(record, siteID(61)) {
			continue
		}
		greyRecords++
		if strings.Contains(record, `"request":{"method"`) && strings.Contains(record, `"headers":{"Accept"`) {
			partsOK = false // part B (request headers) must be gone
		}
		for _, name := range auditVariableNames(record) {
			names[name] = true
		}
	}
	check("audit sample rate", greyRecords >= greyRequests/16/3 && greyRecords <= greyRequests/16*3, "%d of %d grey zone transactions written", greyRecords, greyRequests)
	check("audit parts A H", partsOK, "sampled records without request headers")
	check("audit variable names", names["ARGS:v"] && len(names) <= 4, "names %v (values dropped)", names)
	before = fileSize(auditPath)
	for index := 0; index < 20; index++ {
		send(http.MethodGet, "o.waf.test", sqli, "", browser)
	}
	time.Sleep(200 * time.Millisecond) // the audit log is written after the response
	blocks := 0
	for _, record := range auditRecords(auditPath, before) {
		if strings.Contains(record, "cdnca waf block ") {
			blocks++
		}
	}
	check("audit blocks", blocks == 20, "%d of 20 blocks written", blocks)
	adaptiveCost()
	for _, line := range errorLines() {
		check("adaptive error log", false, "%s", line)
	}
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func auditRecords(path string, offset int64) []string {
	raw, _ := os.ReadFile(path)
	if int64(len(raw)) <= offset {
		return nil
	}
	var records []string
	for _, line := range strings.Split(string(raw[offset:]), "\n") {
		if strings.HasPrefix(line, "{") {
			records = append(records, line)
		}
	}
	return records
}

// auditDataVariable is the variable a message's data names (PoC-2: "Matched
// Data: <value> found within <VARIABLE>: <value>"); the values are dropped.
var auditDataVariable = regexp.MustCompile(`within ((?:ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_HEADERS|REQUEST_FILENAME|REQUEST_URI|REQUEST_BODY|XML)(?::[A-Za-z0-9_.\[\]-]{1,64})?)`)

// auditVariableNames reads the variable names of a record's messages.
func auditVariableNames(record string) []string {
	var value struct {
		Transaction struct {
			Messages []struct {
				Details struct {
					Data string `json:"data"`
				} `json:"details"`
			} `json:"messages"`
		} `json:"transaction"`
	}
	if json.Unmarshal([]byte(record), &value) != nil {
		return nil
	}
	var names []string
	for _, message := range value.Transaction.Messages {
		if match := auditDataVariable.FindStringSubmatch(message.Details.Data); match != nil {
			names = append(names, match[1])
		}
	}
	return names
}

// proofOfWork is the challenge page script's search: the first counter whose
// SHA-256 of "<salt>:<counter>" has at least want leading zero bits.
func proofOfWork(salt string, want int) string {
	for counter := 0; ; counter++ {
		sum := sha256.Sum256([]byte(salt + ":" + strconv.Itoa(counter)))
		zeros := 0
		for _, b := range sum {
			if b == 0 {
				zeros += 8
				continue
			}
			zeros += bits.LeadingZeros8(b)
			break
		}
		if zeros >= want {
			return strconv.Itoa(counter)
		}
	}
}
