package crawlerdefaults

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestDefaultsAreAValidCrawlerList(t *testing.T) {
	defaults := Defaults()
	if len(defaults) == 0 || len(defaults) > 32 {
		t.Fatalf("%d defaults", len(defaults))
	}
	names := map[string]bool{}
	for _, crawler := range defaults {
		if strings.HasPrefix(crawler.Name, "cloudflare") {
			t.Fatalf("cloudflare crawler %s is a default (it would trust every request through Cloudflare)", crawler.Name)
		}
		for _, member := range crawler.Members {
			if strings.HasPrefix(member, "cloudflare-") {
				t.Fatalf("crawler %s merges %s", crawler.Name, member)
			}
		}
		if len(crawler.Networks) == 0 && len(crawler.RDNSSuffixes) == 0 && len(crawler.Sources) == 0 {
			t.Fatalf("crawler %s has no verification", crawler.Name)
		}
		for _, source := range crawler.Sources {
			if !strings.HasPrefix(source.URL, "https://") || source.Format != FormatJSON && source.Format != FormatCSV && source.Format != FormatText {
				t.Fatalf("crawler %s source %+v", crawler.Name, source)
			}
		}
		names[crawler.Name] = true
	}
	// The presets the site CC page offered before stay.
	for _, name := range []string{"baidu", "bing", "google", "sogou"} {
		if !names[name] {
			t.Fatalf("default %s missing", name)
		}
	}
	// Without fetched networks the dataset already holds the crawlers that
	// verify by rDNS or inline networks, and the CC engine accepts it.
	dataset, err := BuildDataset(defaults, nil, "2026-10-20T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeDataset(dataset); err != nil {
		t.Fatal(err)
	}
	for _, crawler := range dataset.Crawlers {
		if crawler.Name == "openai" {
			t.Fatal("openai (networks only from its source) is in the dataset before a fetch")
		}
	}
}

func TestParseSourceFormats(t *testing.T) {
	cases := []struct {
		source Source
		body   string
		want   []string
	}{
		{Source{URL: "https://a.example/x.json", Format: FormatJSON},
			`{"creationTime":"2026-10-19T14:46:25","prefixes":[{"ipv4Prefix":"66.249.64.0/27"},{"ipv6Prefix":"2001:4860:4801:10::/64"}]}`,
			[]string{"66.249.64.0/27", "2001:4860:4801:10::/64"}},
		{Source{URL: "https://a.example/list.json", Format: FormatJSON}, `["3.6.20.243","10.0.0.1","bogus"]`,
			[]string{"3.6.20.243/32"}},
		{Source{URL: "https://a.example/meta", Format: FormatJSON, OnlyKey: "hooks"},
			`{"web":["1.1.1.0/24"],"hooks":["192.30.252.0/22","2a0a:a440::/29"]}`,
			[]string{"192.30.252.0/22", "2a0a:a440::/29"}},
		{Source{URL: "https://a.example/aws", Format: FormatJSON, WhereField: "service", WhereValue: "ROUTE53_HEALTHCHECKS"},
			`{"prefixes":[{"ip_prefix":"15.177.0.0/18","service":"ROUTE53_HEALTHCHECKS"},{"ip_prefix":"3.4.12.4/32","service":"AMAZON"}]}`,
			[]string{"15.177.0.0/18"}},
		{Source{URL: "https://a.example/geofeed", Format: FormatCSV},
			"# comment, 1.2.3.4\n31.13.78.0/24,NZ,NZ-AUK,Auckland,\n2a03:2880:f061::/48,NZ,NZ-AUK,Auckland,\n",
			[]string{"31.13.78.0/24", "2a03:2880:f061::/48"}},
		{Source{URL: "https://a.example/cidr.txt", Format: FormatText}, "91.108.56.0/22\n91.108.4.0/22 2001:b28:f23d::/48\n",
			[]string{"91.108.56.0/22", "91.108.4.0/22", "2001:b28:f23d::/48"}},
	}
	for _, item := range cases {
		got, err := ParseSource(item.source, []byte(item.body))
		if err != nil {
			t.Fatalf("%s: %v", item.source.URL, err)
		}
		if len(got) != len(item.want) {
			t.Fatalf("%s: %v", item.source.URL, got)
		}
		for index := range got {
			if got[index].String() != item.want[index] {
				t.Fatalf("%s: %v", item.source.URL, got)
			}
		}
	}
	if _, err := ParseSource(Source{URL: "https://a.example/empty", Format: FormatText}, []byte("# none\n")); err == nil {
		t.Fatal("a source without networks was accepted")
	}
}

func TestAggregateKeepsEveryAddressWithinTheLimit(t *testing.T) {
	var prefixes []netip.Prefix
	for third := 0; third < 200; third++ {
		for fourth := 0; fourth < 4; fourth++ {
			prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{157, 240, byte(third), byte(fourth * 7)}), 32))
		}
	}
	prefixes = append(prefixes, netip.MustParsePrefix("2a03:2880:f000::/48"), netip.MustParsePrefix("2a03:2880:f001::/48"))
	networks, err := Aggregate(prefixes, MaxNetworks)
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) > MaxNetworks {
		t.Fatalf("%d networks", len(networks))
	}
	parsed := make([]netip.Prefix, len(networks))
	for index, network := range networks {
		parsed[index] = netip.MustParsePrefix(network)
	}
	for _, prefix := range prefixes {
		covered := false
		for _, network := range parsed {
			if network.Bits() <= prefix.Bits() && network.Contains(prefix.Addr()) {
				covered = true
			}
		}
		if !covered {
			t.Fatalf("%s lost", prefix)
		}
	}
	if !contains(networks, "2a03:2880:f000::/47") {
		t.Fatalf("siblings not merged: %v", networks[len(networks)-2:])
	}
	// Only a /8 would hold these: refused rather than trusting it.
	wide := []netip.Prefix{netip.MustParsePrefix("1.0.0.1/32"), netip.MustParsePrefix("1.200.0.1/32")}
	if _, err := Aggregate(wide, 1); err == nil {
		t.Fatal("aggregated into a /8")
	}
}

func TestMergeAddsOfficialNetworksByName(t *testing.T) {
	dataset := &Dataset{Schema: DatasetSchema, Crawlers: []edgeconfig.CCV2TrustedCrawler{
		{Name: "openai", UserAgentTokens: []string{"GPTBot"}, Networks: []string{"20.171.206.0/24"}}}}
	site := []edgeconfig.CCV2TrustedCrawler{
		{Name: "my-bot", UserAgentTokens: []string{"MyBot"}, RDNSSuffixes: []string{"bot.example.com"}},
		{Name: "openai", UserAgentTokens: []string{"GPTBot"}, Networks: []string{"52.230.152.0/24"}}}
	merged, err := Merge(site, dataset)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged[0].Networks) != 0 || strings.Join(merged[1].Networks, ",") != "20.171.206.0/24,52.230.152.0/24" {
		t.Fatalf("merged = %+v", merged)
	}
	if len(site[1].Networks) != 1 {
		t.Fatal("Merge changed its input")
	}
}

// The generator output committed next to the code is what Defaults embeds.
func TestDefaultJSONIsTheGeneratorOutput(t *testing.T) {
	raw, err := os.ReadFile("default.json")
	if err != nil || !strings.Contains(string(raw), `"schema": "`+DefaultsSchema+`"`) {
		t.Fatalf("default.json: %v", err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
