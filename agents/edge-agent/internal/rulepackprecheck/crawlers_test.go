package rulepackprecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// The CC pack policy carries the site's own
// trusted crawlers (cc-404-burst and every other CC pack rule exempts a
// verified crawler the site trusts); a site CC policy the node cannot read
// is refused rather than running the packs without its exemptions.
func TestPlansCarriesTheSiteTrustedCrawlersIntoTheCCPackPolicy(t *testing.T) {
	document := goldenDocument(t)
	var security struct {
		Mounts         []edgesite.RuleMount `json:"mounts"`
		ResolvedSHA256 string               `json:"resolved_sha256"`
	}
	if err := json.Unmarshal(document, &security); err != nil {
		t.Fatal(err)
	}
	google := edgeconfig.CCV2TrustedCrawler{Name: "google", UserAgentTokens: []string{"Googlebot"},
		RDNSSuffixes: []string{"google.com", "googlebot.com"}}
	openai := edgeconfig.CCV2TrustedCrawler{Name: "openai", UserAgentTokens: []string{"GPTBot"}, Networks: []string{"20.171.206.0/24"}}
	policy := func(id string, crawlers ...edgeconfig.CCV2TrustedCrawler) (edgesite.CCBinding, []byte) {
		value := edgeconfig.CCV2Policy{SchemaVersion: edgeconfig.CCV2SchemaVersion, TenantScopeID: testScope, SiteID: testSite,
			PolicyID: id, PolicyVersion: 1, BindingID: id, BindingRevision: 1, PublicationID: id, Enabled: true,
			TrustedProxies: []string{}, Allowlist: []string{}, Rules: []edgeconfig.CCV2Rule{}, TrustedCrawlers: crawlers}
		canonical, err := edgeconfig.CanonicalCCV2Policy(value)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(canonical)
		digest := hex.EncodeToString(sum[:])
		return edgesite.CCBinding{Ports: []int{80}, SourceSHA256: digest,
			Policy: edgesite.Ref{Kind: edgesite.RefCCPolicy, ID: id, Revision: 1, SHA256: digest}}, canonical
	}
	first, firstBytes := policy("0d130000-0000-4000-8000-0000000000a1", google, openai)
	second, secondBytes := policy("0d130000-0000-4000-8000-0000000000a2", openai)
	second.Ports = []int{443}
	site := edgesite.Site{ConfigurationScopeID: testScope, SiteID: testSite, Security: edgesite.Security{
		CC: []edgesite.CCBinding{first, second}, Mounts: security.Mounts, ResolvedSHA256: security.ResolvedSHA256}}
	vault := &memoryVault{objects: objects(t), plans: map[string][]byte{}}
	referenced := map[string][]byte{first.Policy.SHA256: firstBytes, second.Policy.SHA256: secondBytes}
	if _, err := (Plans{Vault: vault}).Prepare([]edgesite.Site{site}, referenced, nil, nil); err != nil {
		t.Fatal(err)
	}
	pack, err := edgeconfig.DecodeCCV2Policy(vault.plans[security.ResolvedSHA256+"."+testSite+".cc.json"])
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.TrustedCrawlers) != 2 || pack.TrustedCrawlers[0].Name != "google" || pack.TrustedCrawlers[1].Name != "openai" ||
		len(pack.Rules) != 1 {
		t.Fatalf("CC pack policy crawlers = %+v", pack.TrustedCrawlers)
	}
	// Without a site CC policy the pack policy has no crawlers.
	bare := site
	bare.Security.CC = []edgesite.CCBinding{}
	if _, err := (Plans{Vault: vault}).Prepare([]edgesite.Site{bare}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if pack, _ := edgeconfig.DecodeCCV2Policy(vault.plans[security.ResolvedSHA256+"."+testSite+".cc.json"]); pack.TrustedCrawlers != nil {
		t.Fatalf("crawlers without a site policy: %+v", pack.TrustedCrawlers)
	}
	if _, err := (Plans{Vault: vault}).Prepare([]edgesite.Site{site}, map[string][]byte{}, nil, nil); !errors.Is(err, ErrRejected) {
		t.Fatalf("unreadable site CC policy: %v", err)
	}
}
