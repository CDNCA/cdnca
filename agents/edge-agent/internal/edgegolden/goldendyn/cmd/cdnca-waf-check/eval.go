package main

// -only eval: the paired attack / benign evaluation of the WAF tiers.
// Every corpus request goes to
// each tier site (仅记录 / 标准防护 / 严格防护 / 极严格防护), to a probe site
// that runs every rule set at paranoia 4 in log mode (the request's full
// CRS rule vector, from the audit log) and to one site per node detector
// (cdnca_waf.lua operator detect). Attack corpus: the tiers run's 58
// samples and the OWASP CRS regression tests whose first stage expects
// their own rule (scripts/security/crscorpus, -corpus file). Benign corpus:
// benignCorpus. Output: one EVAL line per request (JSON) and a TPR/FPR line
// per tier (EVALSUM).

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

var corpusFile = flag.String("corpus", "", "CRS regression attack corpus (crscorpus JSON); empty: the built-in attacks only")

var evalDetectors = []string{"sqli", "xss", "ssti", "java_deser", "php_deser", "ssrf", "cmd"}

// rawStatus sends one HTTP/1.1 request as is (CRS test URIs are not always
// valid for net/url) and returns the status code; a grey zone challenge
// (X-Cdnca-WAF: challenge, ADR 0011 RI-03) is statusChallenged.
func rawStatus(host, method, uri string, headers map[string]string, body string) int {
	return rawExchange(host, method, uri, headers, body, false)
}

// rawExchange is rawStatus; drain reads the answer to the end of the
// connection (Connection: close): nginx closes it after the log phase, so
// the request's audit record is then written.
func rawExchange(host, method, uri string, headers map[string]string, body string, drain bool) int {
	dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: rawSource()}}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", edge))
	if err != nil {
		return 0
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	var request strings.Builder
	fmt.Fprintf(&request, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, uri, host)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&request, "%s: %s\r\n", name, headers[name])
	}
	if body != "" || method == "POST" || method == "PUT" || method == "PATCH" {
		fmt.Fprintf(&request, "Content-Length: %d\r\n", len(body))
	}
	request.WriteString("Connection: close\r\n\r\n")
	request.WriteString(body)
	if _, err := conn.Write([]byte(request.String())); err != nil {
		return 0
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	fields := strings.Fields(line)
	if err != nil || len(fields) < 2 {
		return 0
	}
	code, _ := strconv.Atoi(fields[1])
	for {
		header, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(header) == "" {
			break
		}
		if strings.EqualFold(strings.TrimSpace(header), "X-Cdnca-WAF: challenge") {
			code = statusChallenged
		}
	}
	if drain {
		_, _ = io.Copy(io.Discard, reader)
	}
	return code
}

// rawSources is the next local source address of rawExchange: each corpus
// request stands for its own client, so the evaluation measures one request
// and not the repeated grey zone source (waf-gap6 S2, per site x address,
// threshold 20 a minute) a single sender would become. 127.2.0.0/16
// (65,024 addresses, x.y.0 / x.y.255 skipped), apart from the 127.0.0.x
// allow CIDR sources and sendSpread's 127.0.1.x.
var rawSources atomic.Uint64

func rawSource() net.IP {
	index := rawSources.Add(1) % (254 * 256)
	return net.IPv4(127, 2, byte(index/254), byte(index%254+1))
}

// statusChallenged stands for a grey zone challenge answer.
const statusChallenged = -1

// variants is how a corpus request is sent: a value as a query argument and
// as a form field, a whole request as it is.
func variants(request evalRequest) []evalRequest {
	if request.Value == "" {
		return []evalRequest{request}
	}
	query, form := request, request
	query.Method, query.URI = "GET", "/t?v="+url.QueryEscape(request.Value)
	form.Method, form.URI, form.Data = "POST", "/t", "v="+url.QueryEscape(request.Value)
	form.Headers = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	return []evalRequest{query, form}
}

// sendAll: blocked if any variant is answered 403; rules: the CRS rule IDs
// the probe logged for any variant (when probe).
func sendAll(host string, request evalRequest, probe bool) (bool, []int) {
	blocked, _, rules := sendAllChallenge(host, request, probe)
	return blocked, rules
}

// sendAllChallenge also reports whether a variant got the grey zone
// challenge (none was blocked).
func sendAllChallenge(host string, request evalRequest, probe bool) (bool, bool, []int) {
	blocked, challenged, rules := false, false, map[int]bool{}
	for _, variant := range variants(request) {
		_, offset := auditRules(0)
		switch rawStatus(host, variant.Method, variant.URI, variant.Headers, variant.Data) {
		case 403:
			blocked = true
		case statusChallenged:
			challenged = true
		}
		if probe {
			counts, _ := auditRules(offset)
			for id := range counts {
				n, _ := strconv.Atoi(id)
				rules[n] = true
			}
		}
	}
	ids := make([]int, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return blocked, challenged && !blocked, ids
}

// probeProfile is 极严格防护's sets at paranoia 4, log only: every CRS
// rule of the ten classes scores, the detectors run, nothing blocks.
func probeProfile(base edgeconfig.CRSProfile) edgeconfig.CRSProfile {
	probe := base
	probe.Ref = edgeconfig.CRSProfileRef{PackID: "system/crs-eval-probe", Version: "0.0.1", SHA256: strings.Repeat("e", 64)}
	probe.Name = "eval probe"
	probe.Sets = nil
	for _, set := range base.Sets {
		set.Paranoia, set.Action = 4, edgeconfig.ManagedWAFActionLog
		// two-level (the base's strong paranoia, weak line out of reach):
		// its sites get the detector verdicts (DetectProfiles), whose
		// signal rules 30080+ the audit record names
		set.WeakThreshold = 1000
		probe.Sets = append(probe.Sets, set)
	}
	return probe
}

func attackCorpus() []evalRequest {
	attacks, _ := tierSamples()
	var corpus []evalRequest
	for _, group := range []string{"classic", "ssti", "java_deser", "php_deser"} {
		for index, value := range attacks[group] {
			corpus = append(corpus, evalRequest{ID: "attack-" + group + "-" + strconv.Itoa(index), Category: "value:" + group, Value: value, Attack: true})
		}
	}
	if *corpusFile == "" {
		return corpus
	}
	raw, err := os.ReadFile(*corpusFile)
	var crs []evalRequest
	if err != nil || json.Unmarshal(raw, &crs) != nil {
		check("eval corpus", false, "read %s: %v", *corpusFile, err)
		return corpus
	}
	for _, request := range crs {
		request.Attack, request.Category = true, "crs:"+strconv.Itoa(request.Rule)[:3]
		corpus = append(corpus, request)
	}
	return corpus
}

type evalResult struct {
	evalRequest
	Tiers []bool `json:"tiers"`
	// Challenged: the tier answered the grey zone challenge (a browser-like
	// request without a pass; 严格/极严格 with grey challenge on)
	Challenged []bool   `json:"challenged"`
	Rules      []int    `json:"rules"`
	Detectors  []string `json:"detectors"`
}

func evalRun() {
	if *gateBase != "" {
		gateRun()
		return
	}
	all := profiles()
	tierPacks := []string{"system/crs-pl1-log", "system/crs-pl1", "system/crs-pl2", "system/crs-pl3"}
	names := []string{"仅记录", "标准防护", "严格防护", "极严格防护"}
	probe := probeProfile(profileNamed(all, "system/crs-pl3"))
	all[probe.Ref.SHA256] = probe
	evalProfiles = all
	sites := []edgesite.Site{}
	for index, pack := range tierPacks {
		sites = append(sites, makeSite(40+index, fmt.Sprintf("eval%d.waf.test", index), &wafSpec{profile: profileNamed(all, pack)}))
	}
	if *corpusSet == "std" {
		// the tier sites only: the public datasets' numbers are per tier
		// (-std-probe: the probe site as well, the only one requests go to)
		if *stdProbe {
			sites = append(sites, makeSite(49, "probe.waf.test", &wafSpec{profile: probe}))
		}
		if _, err := startNode(sites, true); err != nil {
			check("eval start", false, "%v", err)
			return
		}
		defer stop()
		if rawStatus("eval0.waf.test", "GET", "/t?v=hello", nil, "") != 200 {
			check("eval start", false, "clean request not 200")
			return
		}
		if *stdProbe {
			stdProbeRun()
		} else {
			stdRun(names)
		}
		for _, line := range errorLines() {
			check("eval error log", false, "%s", line)
		}
		return
	}
	sites = append(sites, makeSite(49, "probe.waf.test", &wafSpec{profile: probe}))
	for index, detector := range evalDetectors {
		site := makeSite(50+index, detectorHost(detector), nil)
		site.Security.Rules = detectorPolicy(detector)
		sites = append(sites, site)
	}
	if _, err := startNode(sites, true); err != nil {
		check("eval start", false, "%v", err)
		return
	}
	defer stop()
	if rawStatus("eval0.waf.test", "GET", "/t?v=hello", nil, "") != 200 {
		check("eval start", false, "clean request not 200")
		return
	}
	// every tier site has grey challenge on: only the packs whose sets
	// challenge (严格/极严格, Q3) ever do
	adapt := []any{}
	for index := range tierPacks {
		adapt = append(adapt, map[string]any{"site_id": siteID(40 + index), "grey_challenge": true})
	}
	if status, text := controlPost("/waf-adapt/", map[string]any{"sites": adapt}); status != 204 {
		check("eval waf-adapt", false, "%d %s", status, text)
	}
	corpus := append(attackCorpus(), benignCorpus()...)
	type tally struct{ attacks, blocked, challenged, benign, falsePositives, benignChallenged int }
	tallies := make([]tally, len(tierPacks))
	for _, request := range corpus {
		result := evalResult{evalRequest: request, Tiers: make([]bool, len(tierPacks)), Challenged: make([]bool, len(tierPacks)), Detectors: []string{}}
		for index := range tierPacks {
			result.Tiers[index], result.Challenged[index], _ = sendAllChallenge(fmt.Sprintf("eval%d.waf.test", index), request, false)
			if request.Attack {
				tallies[index].attacks++
				if result.Tiers[index] {
					tallies[index].blocked++
				}
				if result.Challenged[index] {
					tallies[index].challenged++
				}
			} else {
				tallies[index].benign++
				if result.Tiers[index] {
					tallies[index].falsePositives++
				}
				if result.Challenged[index] {
					tallies[index].benignChallenged++
				}
			}
		}
		_, result.Rules = sendAll("probe.waf.test", request, true)
		for _, detector := range evalDetectors {
			if blocked, _ := sendAll(detectorHost(detector), request, false); blocked {
				result.Detectors = append(result.Detectors, detector)
			}
		}
		encoded, _ := json.Marshal(result)
		fmt.Printf("EVAL %s\n", encoded)
	}
	for index, t := range tallies {
		fmt.Printf("EVALSUM tier=%s attacks=%d blocked=%d tpr=%.4f challenged=%d tpr_with_challenge=%.4f benign=%d fp=%d fpr=%.4f benign_challenged=%d challenge_rate=%.4f\n",
			names[index], t.attacks, t.blocked, float64(t.blocked)/float64(max(t.attacks, 1)), t.challenged,
			float64(t.blocked+t.challenged)/float64(max(t.attacks, 1)), t.benign, t.falsePositives, float64(t.falsePositives)/float64(max(t.benign, 1)),
			t.benignChallenged, float64(t.benignChallenged)/float64(max(t.benign, 1)))
	}
	for _, line := range errorLines() {
		check("eval error log", false, "%s", line)
	}
}
