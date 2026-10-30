package securitypublication

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/crawlerdefaults"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// §3: a site crawler named like a default one also
// verifies by the downloaded official IP ranges (dataset/trusted-crawlers);
// crawlers the dataset does not name stay as configured.
func TestCompileCCV2MergesOfficialCrawlerRanges(t *testing.T) {
	policy := v6PolicyForTest()
	runtime, err := securitypolicy.CompileRuntimeSnapshot(policy, testSiteID)
	if err != nil {
		t.Fatal(err)
	}
	dataset := &crawlerdefaults.Dataset{Schema: crawlerdefaults.DatasetSchema, Crawlers: []edgeconfig.CCV2TrustedCrawler{
		{Name: "google", UserAgentTokens: []string{"Googlebot"}, Networks: []string{"2001:4860:4801:10::/64", "66.249.64.0/27"},
			RDNSSuffixes: []string{"googlebot.com"}}}}
	bindings, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{{
		BindingID: uuid.MustParse("018f1000-0000-7000-8000-000000000030"), BindingRevision: 1,
		PublicationID:         uuid.MustParse("018f1000-0000-7000-8000-000000000031"),
		RuntimeSnapshotSHA256: runtime.SHA256, Snapshot: runtime.Snapshot, TrustedCrawlers: dataset}})
	if err != nil {
		t.Fatal(err)
	}
	crawlers := map[string]edgeconfig.CCV2TrustedCrawler{}
	for _, crawler := range bindings.Site.CCV2.Policy.TrustedCrawlers {
		crawlers[crawler.Name] = crawler
	}
	// 66.249.64.0/27 is inside the site's 66.249.64.0/19: aggregated away.
	if got := strings.Join(crawlers["google"].Networks, ","); got != "2001:4860:4801:10::/64,66.249.64.0/19" {
		t.Fatalf("google networks = %s", got)
	}
	if len(crawlers["baidu"].Networks) != 0 || strings.Join(crawlers["baidu"].RDNSSuffixes, ",") != "baidu.com,baidu.jp" {
		t.Fatalf("baidu = %+v", crawlers["baidu"])
	}
	if _, err := edgeconfig.CanonicalCCV2Policy(bindings.Site.CCV2.Policy); err != nil {
		t.Fatal(err)
	}
}
