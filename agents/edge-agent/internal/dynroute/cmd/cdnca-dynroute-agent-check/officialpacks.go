package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// The official system packs as seeded by license
// migration 097 (scripts/security/datasets/rulepacks, copied by run.sh into
// -official), mounted on a real OpenResty:
//
//   - system/bot-bad-ua (waf_v2 inspect user_agent contains, both sides
//     lower-cased): action block refuses the listed bot in any letter case,
//     a browser User-Agent passes;
//   - system/cc-404-burst (cc_v2 status_404_count 10 / 60 s): action
//     reject_429 refuses a client after its 10th 404 (from the 2nd request
//     over the threshold, see the pack description) unless it is a crawler
//     the site's CC policy trusts (the pack policy carries the site's
//     trusted_crawlers, rulepackprecheck).

// officialPackSecurity mounts the named official packs with params.
func (fixture *rulePackFixture) officialPackSecurity(dir string, packs map[string]rulepack.Params) (edgesite.Security, error) {
	requests := make([]rulepack.MountRequest, 0, len(packs))
	for name, params := range packs {
		text, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			return edgesite.Security{}, err
		}
		compiled, err := rulepack.Compile(text)
		if err != nil {
			return edgesite.Security{}, fmt.Errorf("%s: %w", name, err)
		}
		fixture.objects[compiled.SHA256] = compiled.Canonical
		requests = append(requests, rulepack.MountRequest{Pack: compiled, Priority: rulepack.DefaultPriority, Params: params})
	}
	resolution := rulepack.Resolve(requests, rulepack.Target{})
	if resolution.Security == nil {
		return edgesite.Security{}, fmt.Errorf("official pack resolution conflicts: %+v", resolution.Conflicts)
	}
	encoded, _ := json.Marshal(resolution.Security)
	var mounts struct {
		Mounts         []edgesite.RuleMount `json:"mounts"`
		ResolvedSHA256 string               `json:"resolved_sha256"`
	}
	if err := json.Unmarshal(encoded, &mounts); err != nil {
		return edgesite.Security{}, err
	}
	return edgesite.Security{Mounts: mounts.Mounts, ResolvedSHA256: mounts.ResolvedSHA256}, nil
}

// siteCCPolicy is a site's own CC policy without rules, trusting crawlers
// (the client in the check is 127.0.0.1): the binding and its canonical
// bytes (a referenced object).
func siteCCPolicy(site edgesite.Site, port int, crawlers []edgeconfig.CCV2TrustedCrawler) (edgesite.CCBinding, []byte, error) {
	id := site.SiteID
	policy := edgeconfig.CCV2Policy{SchemaVersion: edgeconfig.CCV2SchemaVersion, TenantScopeID: site.ConfigurationScopeID,
		SiteID: site.SiteID, PolicyID: id, PolicyVersion: 1, BindingID: id, BindingRevision: 1, PublicationID: id,
		Enabled: true, TrustedProxies: []string{}, Allowlist: []string{}, Rules: []edgeconfig.CCV2Rule{},
		TrustedCrawlers: crawlers}
	canonical, err := edgeconfig.CanonicalCCV2Policy(policy)
	if err != nil {
		return edgesite.CCBinding{}, nil, err
	}
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])
	return edgesite.CCBinding{Ports: []int{port}, SourceSHA256: digest,
		Policy: edgesite.Ref{Kind: edgesite.RefCCPolicy, ID: id, Revision: 1, SHA256: digest}}, canonical, nil
}

// getUA is get with a User-Agent.
func getUA(port int, host, path, userAgent string) answer {
	request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	request.Host = host
	request.Header.Set("User-Agent", userAgent)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		return answer{err: err.Error()}
	}
	defer response.Body.Close()
	return answer{status: response.StatusCode}
}

// burst404 sends n requests for missing paths and returns their statuses.
func burst404(port int, host, userAgent string, n int) []int {
	statuses := make([]int, 0, n)
	for index := range n {
		statuses = append(statuses, getUA(port, host, fmt.Sprintf("/missing-%d", index), userAgent).status)
	}
	return statuses
}

func officialChecks(h *harness, packs *rulePackFixture, sites []edgesite.Site, mounted edgesite.Site) {
	block, _ := json.Marshal("block")
	reject, _ := json.Marshal("reject_429")
	security, err := packs.officialPackSecurity(*official, map[string]rulepack.Params{
		"system-bot-bad-ua": {"action": block}, "system-cc-404-burst": {"action": reject}})
	check("rulepack-official-fixture", err == nil, "%v", err)
	if err != nil {
		return
	}
	const bots, crawler = "bots.d13.test", "crawler.d13.test"
	plain := withMounts(makeSite(8, bots, 1, portPlain), security)
	// The same packs on a site whose CC policy trusts "examplebot" from 127.0.0.1.
	trusting := withMounts(makeSite(9, crawler, 1, portPlain), security)
	binding, policy, err := siteCCPolicy(trusting, portPlain, []edgeconfig.CCV2TrustedCrawler{
		{Name: "examplebot", UserAgentTokens: []string{"ExampleBot"}, Networks: []string{"127.0.0.0/8"}}})
	check("rulepack-official-site-cc", err == nil, "%v", err)
	if err != nil {
		return
	}
	trusting.Security.CC = []edgesite.CCBinding{binding}
	// The node's shared object store holds referenced objects (the gateway
	// fetch puts them there); the agent also hands them to the rule pack
	// precheck through Object.Referenced.
	if err := siteObjects.Put(binding.Policy.SHA256, policy); err != nil {
		check("rulepack-official-site-cc-object", false, "%v", err)
		return
	}
	h.input.Objects = objects(append(append([]edgesite.Site(nil), sites...), mounted, plain, trusting)...)
	for index := range h.input.Objects {
		if h.input.Objects[index].Site.SiteID == trusting.SiteID {
			h.input.Objects[index].Referenced = map[string][]byte{binding.Policy.SHA256: policy}
		}
	}
	result, err := h.runtime.Apply(h.ctx, h.input)
	check("rulepack-official-apply", err == nil, "generation %d %v", result.Activation.Generation, err)
	if err != nil {
		return
	}
	browser := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
	upper := getUA(portPlain, bots, "/index.html", "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)")
	lower := getUA(portPlain, bots, "/index.html", "mozilla/5.0 (compatible; ahrefsbot/7.0)")
	mixed := getUA(portPlain, bots, "/index.html", "Mozilla/5.0 (compatible; AHREFSBOT/7.0)")
	human := getUA(portPlain, bots, "/index.html", browser)
	check("rulepack-official-bad-ua", upper.status == 403 && lower.status == 403 && mixed.status == 403 && human.status == 200,
		"AhrefsBot %d ahrefsbot %d AHREFSBOT %d browser %d", upper.status, lower.status, mixed.status, human.status)
	// 10 404s are counted; the 11th only counts over the threshold
	// (fixed_window requests 1), the 12th is refused.
	counted := burst404(portPlain, bots, browser, 12)
	refused := getUA(portPlain, bots, "/index.html", browser)
	check("rulepack-official-404-burst", counted[9] == 404 && counted[10] == 404 && counted[11] == 429 && refused.status == 429,
		"statuses %v then %d", counted, refused.status)
	// The site trusts examplebot from 127.0.0.1: the pack exempts it too.
	exempt := burst404(portPlain, crawler, "ExampleBot/1.0 (+https://example.com/bot)", 14)
	after := getUA(portPlain, crawler, "/index.html", "ExampleBot/1.0")
	exemptOK := after.status == 200
	for _, status := range exempt {
		exemptOK = exemptOK && status == 404
	}
	// Without the crawler token the same client is limited on that site.
	others := burst404(portPlain, crawler, browser, 12)
	check("rulepack-official-404-crawler-exempt", exemptOK && others[11] == 429,
		"crawler %v then %d, browser %v", exempt, after.status, others)
	importedChecks(h, packs, append(append([]edgesite.Site(nil), sites...), mounted, plain, trusting), binding, policy, trusting.SiteID)
}

// importedChecks: the packs converted from naxsi and
// device-detector (-official/imported, gen_imported_packs.py) with action
// block on one site: a request carrying a converted feature is refused
// (naxsi-strong: an input:// wrapper in a parameter; naxsi-websec: /.git/
// path; bot-dd-scraper: a scraper User-Agent in any letter case) while a
// browser, the known-good crawlers Googlebot / bingbot / Baiduspider and the
// paths naxsi whitelists (/robots.txt) pass.
func importedChecks(h *harness, packs *rulePackFixture, sites []edgesite.Site, binding edgesite.CCBinding, policy []byte, trustingID string) {
	block, _ := json.Marshal("block")
	security, err := packs.officialPackSecurity(filepath.Join(*official, "imported"), map[string]rulepack.Params{
		"system-naxsi-strong": {"action": block}, "system-naxsi-websec": {"action": block}, "system-bot-dd-scraper": {"action": block}})
	check("rulepack-imported-fixture", err == nil, "%v", err)
	if err != nil {
		return
	}
	const host = "imported.d13.test"
	site := withMounts(makeSite(10, host, 1, portPlain), security)
	h.input.Objects = objects(append(sites, site)...)
	for index := range h.input.Objects {
		if h.input.Objects[index].Site.SiteID == trustingID {
			h.input.Objects[index].Referenced = map[string][]byte{binding.Policy.SHA256: policy}
		}
	}
	result, err := h.runtime.Apply(h.ctx, h.input)
	check("rulepack-imported-apply", err == nil, "generation %d %v", result.Activation.Generation, err)
	if err != nil {
		return
	}
	browser := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
	sqli := getUA(portPlain, host, "/index.html?page=input%3A%2F%2Fx", browser)
	git := getUA(portPlain, host, "/.git/config", browser)
	robots := getUA(portPlain, host, "/robots.txt", browser)
	plainPage := getUA(portPlain, host, "/index.html?q=it%27s+(fine)", browser)
	check("rulepack-imported-naxsi", sqli.status == 403 && git.status == 403 && robots.status != 403 && plainPage.status == 200,
		"input:// %d /.git/config %d /robots.txt %d quote+paren %d", sqli.status, git.status, robots.status, plainPage.status)
	scraper := getUA(portPlain, host, "/index.html", "Mozilla/5.0 (compatible; BitSightBot/1.0)")
	upper := getUA(portPlain, host, "/index.html", "Mozilla/5.0 (compatible; BITSIGHTBOT/1.0)")
	good := map[string]string{
		"googlebot":   "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"bingbot":     "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"baiduspider": "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
		"browser":     browser,
	}
	passed := map[string]int{}
	goodOK := true
	for name, userAgent := range good {
		passed[name] = getUA(portPlain, host, "/index.html", userAgent).status
		goodOK = goodOK && passed[name] == 200
	}
	check("rulepack-imported-bot-ua", scraper.status == 403 && upper.status == 403 && goodOK,
		"BitSightBot %d BITSIGHTBOT %d good %v", scraper.status, upper.status, passed)
}
