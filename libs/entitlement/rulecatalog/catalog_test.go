package rulecatalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goldenInstallationID = "00000000-0000-4000-8000-0000000000a1"

func goldenKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func seedCatalog() Catalog { return Catalog{Schema: CatalogSchema, Items: CompetitorSeed()} }

func TestCompetitorSeedMatchesCapture(t *testing.T) {
	counts := map[string]int{}
	names := map[string]string{}
	for _, item := range CompetitorSeed() {
		counts[item.Kind]++
		names[item.SystemKey] = item.Name
	}
	if counts[KindCCRuleGroup] != 11 || counts[KindCCMatcher] != 3 || counts[KindCCFilter] != 17 || counts[KindWAFRuleSet] != 0 {
		t.Fatalf("seed counts = %v, want 11/3/17/0", counts)
	}
	for key, want := range map[string]string{
		"cc_rule:10002": "关闭", "cc_rule:6": "宽松", "cc_rule:1": "JS验证", "cc_rule:10001": "5秒盾",
		"cc_rule:10000": "点击验证", "cc_rule:2": "滑块验证", "cc_rule:4": "验证码", "cc_rule:10003": "旋转图片",
		"cc_rule:10004": "点击验证(简单)", "cc_rule:10005": "滑块验证(简单)", "cc_rule:3": "临时白名单",
		"cc_matcher:3": "匹配所有资源", "cc_matcher:4": "匹配静态资源", "cc_matcher:5": "匹配内置资源",
		"cc_filter:1": "302跳转60-5", "cc_filter:8": "浏览器识别60-5", "cc_filter:9": "请求速率5-300-50",
		"cc_filter:10001": "5秒盾60-5", "cc_filter:10004": "滑动过滤(简单)60-5",
	} {
		if names[key] != want {
			t.Fatalf("seed %s name = %q, want %q", key, names[key], want)
		}
	}
	if _, _, err := CanonicalCatalog(seedCatalog()); err != nil {
		t.Fatalf("seed catalog invalid: %v", err)
	}
	for _, item := range CompetitorSeed() {
		switch item.SystemKey {
		case "cc_rule:3":
			if !item.Hidden || item.Sort != 100 || item.Body.CCRuleGroup.Entries[0].Filter1Key != "cc_filter:11" {
				t.Fatalf("临时白名单 = %+v", item)
			}
		case "cc_rule:10002":
			if len(item.Body.CCRuleGroup.Entries) != 0 {
				t.Fatalf("关闭 has entries: %+v", item.Body.CCRuleGroup)
			}
		case "cc_rule:6":
			entry := item.Body.CCRuleGroup.Entries[0]
			if entry != (CCRuleGroupEntry{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:9", Action: "block", Mode: "break", Enabled: true}) {
				t.Fatalf("宽松 entry = %+v", entry)
			}
		case "cc_filter:9":
			if filter := item.Body.CCFilter; filter.Type != "req_rate" || filter.WithinSecond != 5 || filter.MaxReq != 300 || filter.MaxReqPerURI != 50 {
				t.Fatalf("请求速率5-300-50 = %+v", item.Body.CCFilter)
			}
		case "cc_matcher:5":
			if len(item.Body.CCMatcher.Conditions[0].Values) != 6 {
				t.Fatalf("匹配内置资源 values = %v", item.Body.CCMatcher.Conditions[0].Values)
			}
		}
	}
}

func TestCatalogValidationRejectsMalformedItems(t *testing.T) {
	mutations := map[string]func(*Catalog){
		"unsorted":      func(c *Catalog) { c.Items[0], c.Items[1] = c.Items[1], c.Items[0] },
		"dangling":      func(c *Catalog) { c.Items = removeKey(c.Items, "cc_filter:9") },
		"kind prefix":   func(c *Catalog) { c.Items[0].SystemKey = "cc_rule:zz" },
		"two bodies":    func(c *Catalog) { c.Items[0].Body.CCMatcher = &CCMatcherBody{Conditions: []CCMatcherCondition{}} },
		"filter type":   func(c *Catalog) { itemByKey(c, "cc_filter:9").Body.CCFilter.Type = "five_second" },
		"nil extra":     func(c *Catalog) { itemByKey(c, "cc_filter:9").Body.CCFilter.Extra = nil },
		"bad action":    func(c *Catalog) { itemByKey(c, "cc_rule:6").Body.CCRuleGroup.Entries[0].Action = "challenge" },
		"name space":    func(c *Catalog) { c.Items[0].Name = " x" },
		"revision zero": func(c *Catalog) { c.Items[0].Revision = 0 },
		"newline value": func(c *Catalog) { itemByKey(c, "cc_matcher:5").Body.CCMatcher.Conditions[0].Values[0] = "a\nb" },
		"empty waf set": func(c *Catalog) {
			c.Items = append(c.Items, Item{SystemKey: "waf_set:z", Kind: KindWAFRuleSet, Name: "w", Revision: 1, Body: ItemBody{WAFRuleSet: &WAFRuleSetBody{Rules: []WAFRule{}}}})
		},
		"nil items": func(c *Catalog) { c.Items = nil },
		"schema":    func(c *Catalog) { c.Schema = "x" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			catalog := seedCatalog()
			mutate(&catalog)
			if _, _, err := CanonicalCatalog(catalog); !errors.Is(err, ErrInvalidCatalog) {
				t.Fatalf("CanonicalCatalog() error = %v, want ErrInvalidCatalog", err)
			}
		})
	}
	waf := seedCatalog()
	waf.Items = append(waf.Items, sampleWAFItem())
	SortItems(waf.Items)
	if _, _, err := CanonicalCatalog(waf); err != nil {
		t.Fatalf("WAF rule set rejected: %v", err)
	}
}

func TestReportCanonicalizationAndPrivacy(t *testing.T) {
	owner := OwnerHash(goldenInstallationID, "00000000-0000-4000-8000-0000000000c1")
	if owner == OwnerHash("00000000-0000-4000-8000-0000000000a2", "00000000-0000-4000-8000-0000000000c1") || len(owner) != 64 {
		t.Fatal("owner hash is not installation salted")
	}
	group := func(id string) json.RawMessage {
		return json.RawMessage(`{"id":"` + id + `","scope_id":"00000000-0000-4000-8000-0000000000d1","owner_hash":"` + owner +
			`","name":"g","description":"","enabled":true,"default_action":"allow","rules":[],"version":1}`)
	}
	report := Report{WAFPolicies: []json.RawMessage{}, CCRuleGroups: []json.RawMessage{
		group("00000000-0000-4000-8000-0000000000e2"), group("00000000-0000-4000-8000-0000000000e1")},
		CCMatchers: []json.RawMessage{}, CCFilters: []json.RawMessage{}}
	canonical, digest, err := CanonicalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(canonical.CCRuleGroups[0]), "e1") {
		t.Fatalf("rule groups not sorted: %s", canonical.CCRuleGroups[0])
	}
	_, again, _ := CanonicalReport(canonical)
	if again != digest {
		t.Fatal("canonical report digest is not stable")
	}
	for name, raw := range map[string]string{
		"display name": `{"id":"00000000-0000-4000-8000-0000000000e3","owner_hash":"` + owner + `","owner":{"display_name":"jason"}}`,
		"raw owner":    `{"id":"00000000-0000-4000-8000-0000000000e3","owner_hash":"jason"}`,
		"system":       `{"id":"00000000-0000-4000-8000-0000000000e3","owner_hash":"` + owner + `","system_rule":true}`,
		"no owner":     `{"id":"00000000-0000-4000-8000-0000000000e3"}`,
	} {
		bad := report
		bad.CCRuleGroups = []json.RawMessage{json.RawMessage(raw)}
		if _, _, err := CanonicalReport(bad); !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	missing := report
	missing.CCFilters = nil
	if _, _, err := CanonicalReport(missing); !errors.Is(err, ErrInvalidReport) {
		t.Fatal("nil section accepted")
	}
}

// Golden vectors of the custom rule report. The same bytes are committed in
// services/license-service/internal/licensing/testdata and verified there
// with the service's own wiring; both pin this digest.
const GoldenProofsSHA256 = "47fc19e8f67fe831cfb2c862acc8779f47e59f6c5373fc5c50910d54cdad4128"

type goldenProofs struct {
	InstallationPublicKey string        `json:"installation_public_key"`
	Report                ReportRequest `json:"report"`
	ReportDigest          string        `json:"report_digest"`
	OwnerHash             string        `json:"owner_hash"`
}

func goldenProofFile(t *testing.T) []byte {
	t.Helper()
	installation := goldenKey(0x42)
	owner := OwnerHash(goldenInstallationID, "00000000-0000-4000-8000-0000000000c1")
	report, digest, err := CanonicalReport(Report{WAFPolicies: []json.RawMessage{json.RawMessage(`{"id":"00000000-0000-4000-8000-0000000000f1","owner_hash":"` + owner + `","kind":"x"}`)}[:0],
		CCRuleGroups: []json.RawMessage{json.RawMessage(`{"id":"00000000-0000-4000-8000-0000000000e1","scope_id":"00000000-0000-4000-8000-0000000000d1","owner_hash":"` + owner + `","name":"自定义规则组","description":"","enabled":true,"default_action":"allow","rules":[],"version":1}`)},
		CCMatchers:   []json.RawMessage{json.RawMessage(`{"id":"00000000-0000-4000-8000-0000000000e2","owner_hash":"` + owner + `","name":"m","field":"path","operator":"prefix","values":["/api"],"enabled":true,"version":1}`)},
		CCFilters:    []json.RawMessage{json.RawMessage(`{"id":"00000000-0000-4000-8000-0000000000e3","owner_hash":"` + owner + `","name":"f","type":"req_rate","parameters":{"max_req":10},"enabled":true,"version":1}`)}})
	if err != nil {
		t.Fatal(err)
	}
	reportRequest := ReportRequest{Schema: ReportSchema, InstallationID: goldenInstallationID, Sequence: 1,
		ObservedAt: 1_900_000_002, Report: report, RequestID: "00000000-0000-4000-8000-0000000000f9"}
	reportRequest.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(installation, ReportProofMessage(reportRequest, digest)))
	proofs, err := json.MarshalIndent(goldenProofs{
		InstallationPublicKey: base64.RawURLEncoding.EncodeToString(installation.Public().(ed25519.PublicKey)),
		Report:                reportRequest, ReportDigest: hex.EncodeToString(digest[:]), OwnerHash: owner,
	}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return append(proofs, '\n')
}

func TestGoldenVectors(t *testing.T) {
	proofs := goldenProofFile(t)
	path := filepath.Join("testdata", "security-rule-catalog-proofs.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, proofs, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(golden, proofs) {
		t.Fatal("report golden drifted; regenerate with UPDATE_GOLDEN=1 and update every copy")
	}
	if sum := sha256.Sum256(golden); hex.EncodeToString(sum[:]) != GoldenProofsSHA256 {
		t.Fatalf("report golden sha256 = %x, pinned %s", sum, GoldenProofsSHA256)
	}
}

func sampleWAFItem() Item {
	return Item{SystemKey: "waf_set:basic", Kind: KindWAFRuleSet, Name: "基础防护", Revision: 1, Body: ItemBody{WAFRuleSet: &WAFRuleSetBody{Rules: []WAFRule{{
		ID: "r1", Name: "阻断扫描器", Enabled: true, Action: "block", MatcherGroups: []WAFMatcherGroup{{ID: "g1",
			Matchers: []WAFMatcher{{Field: "user_agent", Operator: "contain", Transform: "lowercase", Value: "sqlmap"}}}},
	}}}}}
}

func removeKey(items []Item, key string) []Item {
	result := []Item{}
	for _, item := range items {
		if item.SystemKey != key {
			result = append(result, item)
		}
	}
	return result
}

func itemByKey(catalog *Catalog, key string) *Item {
	for index := range catalog.Items {
		if catalog.Items[index].SystemKey == key {
			return &catalog.Items[index]
		}
	}
	panic(key)
}
