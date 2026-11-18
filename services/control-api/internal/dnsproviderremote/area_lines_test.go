package dnsproviderremote

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/geoarea"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// v2AreaCodes is the two-level geoarea code list (continents and regions, global
// apart) as the dispatch fixed it; written out here so the test does not
// depend on the libs/geoarea version.
var v2AreaCodes = []string{
	"asia", "east_asia", "southeast_asia", "south_asia", "west_asia", "central_asia",
	"europe", "northern_europe", "western_europe", "southern_europe", "eastern_europe",
	"africa", "northern_africa", "western_africa", "eastern_africa", "middle_africa", "southern_africa",
	"north_america", "northern_america", "central_america", "caribbean", "south_america",
	"oceania", "australia_new_zealand", "melanesia", "micronesia", "polynesia",
}

// Every provider x every macro area: the unified line written (AreaLine)
// and, where the provider has its own line, the provider code it maps to.
// Columns: area, own line (DNSPod writes it verbatim), Aliyun code, the
// continent line Huawei / DNS.LA / DNS.COM fall back to (they have no
// regions). Sources and dates: docs/dns/provider-line-capabilities.md.
func TestAreaLineEveryProviderEveryArea(t *testing.T) {
	rows := []struct{ area, line, aliyun, continent string }{
		{"asia", LineAsia, "os_asia", LineAsia},
		{"east_asia", "东亚地区", "os_eastern_asia", LineAsia},
		{"southeast_asia", "东南亚地区", "os_south_eastern_asia", LineAsia},
		{"south_asia", "南亚地区", "os_southern_asia", LineAsia},
		{"west_asia", "西亚地区", "os_western_asia", LineAsia},
		{"central_asia", "中亚地区", "os_central_asia", LineAsia},
		{"europe", LineEurope, "os_euro", LineEurope},
		{"northern_europe", "北欧地区", "os_northern_europe", LineEurope},
		{"western_europe", "西欧地区", "os_western_europe", LineEurope},
		{"southern_europe", "南欧地区", "os_southern_europe", LineEurope},
		{"eastern_europe", "东欧地区", "os_eastern_europe", LineEurope},
		{"africa", LineAfrica, "os_africa", LineAfrica},
		{"northern_africa", "北非地区", "os_northern_africa", LineAfrica},
		{"western_africa", "西非地区", "os_western_africa", LineAfrica},
		{"eastern_africa", "东非地区", "os_eastern_africa", LineAfrica},
		{"middle_africa", "中非地区", "os_middle_africa", LineAfrica},
		{"southern_africa", "南非地区", "os_southern_africa", LineAfrica},
		{"north_america", LineNorthAmerica, "os_namerica", LineNorthAmerica},
		{"northern_america", "北美地区", "os_northern_america", LineNorthAmerica},
		{"central_america", "中美地区", "os_sentral_america", LineNorthAmerica},
		{"caribbean", "加勒比地区", "os_caribbean", LineNorthAmerica},
		{"south_america", LineSouthAmerica, "os_samerica", LineSouthAmerica},
		{"oceania", LineOceania, "os_oceanica", LineOceania},
		{"australia_new_zealand", "澳大利亚和新西兰地区", "os_australia_newzaland", LineOceania},
		{"melanesia", "美拉尼西亚地区", "os_melanesia", LineOceania},
		{"micronesia", "密克罗尼西亚地区", "os_micronesia", LineOceania},
		{"polynesia", "波利尼西亚地区", "os_polynesia", LineOceania},
	}
	huaweiCodes := map[string]string{LineAsia: "AP", LineEurope: "EU", LineNorthAmerica: "NA",
		LineSouthAmerica: "LA", LineAfrica: "AF", LineOceania: "OA"}
	dnsLACodes := map[string]string{LineAsia: "84613318538699776", LineEurope: "84613318593225728",
		LineNorthAmerica: "84613318853272576", LineSouthAmerica: "84613318790358016",
		LineAfrica: "84613318651945984", LineOceania: "84613318937158656"}
	type want struct{ line, code string }
	cases := map[string]map[string]want{}
	add := func(provider, area, line, code string) {
		if cases[provider] == nil {
			cases[provider] = map[string]want{}
		}
		cases[provider][area] = want{line, code}
	}
	for _, row := range rows {
		add(providerAliyun, row.area, row.line, row.aliyun)
		add(providerDNSPodCN, row.area, row.line, row.line)
		add(providerHuawei, row.area, row.continent, huaweiCodes[row.continent])
		add(providerDNSLA, row.area, row.continent, dnsLACodes[row.continent])
		add(providerDNSCom, row.area, row.continent, row.continent) // view_id matched by name
		// Providers with 境外 but no area line fall back to it.
		for _, provider := range []string{providerJDCloud, providerCustomHTTP, providerPlugin} {
			code, _ := providerLineCode(provider, LineOverseas)
			add(provider, row.area, LineOverseas, code)
		}
	}
	if codes := slices.Sorted(slices.Values(AreaCodes())); len(rows) != len(v2AreaCodes) ||
		!slices.Equal(codes, slices.Sorted(slices.Values(v2AreaCodes))) {
		t.Fatalf("AreaCodes() = %v, want %v", AreaCodes(), v2AreaCodes)
	}
	for _, capability := range ProviderCapabilityMatrix() {
		provider := capability.ProviderType
		if line, ok := AreaLine(provider, "global"); !ok || line != LineDefault {
			t.Fatalf("AreaLine(%s, global) = %q, %v; want 默认", provider, line, ok)
		}
		expected, ok := cases[provider]
		if !ok {
			// No line support: every area is answered by the default line.
			for _, area := range v2AreaCodes {
				if line, ok := AreaLine(provider, area); !ok || line != LineDefault {
					t.Fatalf("AreaLine(%s, %s) = %q, %v; want 默认", provider, area, line, ok)
				}
			}
			continue
		}
		for area, item := range expected {
			line, ok := AreaLine(provider, area)
			if !ok || line != item.line {
				t.Fatalf("AreaLine(%s, %s) = %q, %v; want %q", provider, area, line, ok, item.line)
			}
			code, ok := providerLineCode(provider, line)
			if !ok || code != item.code {
				t.Fatalf("%s %s: code %q, %v; want %q", provider, line, code, ok, item.code)
			}
			if !slices.Contains(SupportedLines(provider), line) {
				t.Fatalf("SupportedLines(%s) lacks %s", provider, line)
			}
		}
	}
	// Every code of the linked libs/geoarea resolves (v1 now, v2 once merged).
	for _, area := range geoarea.Areas {
		if _, ok := AreaLine(providerAliyun, area.Code); !ok {
			t.Fatalf("geoarea code %s has no area line", area.Code)
		}
	}
	for _, area := range []string{"antarctica", "", "Asia"} {
		if _, ok := AreaLine(providerAliyun, area); ok {
			t.Fatalf("unknown area code %q resolved", area)
		}
	}
}

// SupportedLines lists exactly the area lines the provider maps itself, after
// the five basic lines and before the province lines; the existing lines and
// their codes are unchanged.
func TestSupportedLinesAreaLines(t *testing.T) {
	all := []string{LineAsia, LineEastAsia, LineSoutheastAsia, LineSouthAsia, LineWestAsia, LineCentralAsia,
		LineEurope, "北欧地区", "西欧地区", "南欧地区", "东欧地区",
		LineNorthAmerica, "北美地区", "中美地区", "加勒比地区", LineSouthAmerica,
		LineAfrica, "北非地区", "西非地区", "东非地区", "中非地区", "南非地区",
		LineOceania, "澳大利亚和新西兰地区", "美拉尼西亚地区", "密克罗尼西亚地区", "波利尼西亚地区"}
	continents := []string{LineAsia, LineEurope, LineNorthAmerica, LineSouthAmerica, LineAfrica, LineOceania}
	want := map[string][]string{
		providerAliyun: all, providerDNSPodCN: all, providerHuawei: continents, providerDNSLA: continents,
		providerDNSCom: continents,
	}
	for _, capability := range ProviderCapabilityMatrix() {
		provider := capability.ProviderType
		got := SupportedLines(provider)
		var areas []string
		for _, line := range got {
			if slices.Contains(all, line) {
				areas = append(areas, line)
			}
		}
		if !slices.Equal(areas, want[provider]) {
			t.Fatalf("SupportedLines(%s) area lines = %v, want %v", provider, areas, want[provider])
		}
		if len(areas) > 0 && !slices.Equal(got[5:5+len(areas)], areas) {
			t.Fatalf("SupportedLines(%s) order = %v", provider, got)
		}
		config := completeTestConfig(reconcileHTTPProviderConfig(provider))
		if provider == providerDNSCom {
			config.Credentials[DNSComPlanField] = DNSComPlanEnterprise
		}
		for _, line := range all {
			operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
				Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: line}
			err := validateProviderReconcileOperation(config, operation)
			if supported := slices.Contains(got, line); supported != (err == nil) {
				t.Fatalf("%s line %s: supported=%v validation=%v", provider, line, supported, err)
			}
		}
	}
	for provider, codes := range map[string]map[string]string{
		providerAliyun: {LineDefault: "default", LineOverseas: "oversea"},
		providerHuawei: {LineDefault: "default_view", LineOverseas: "Abroad"},
		providerDNSLA:  {LineDefault: "", LineOverseas: "84613317016167424"},
	} {
		for line, code := range codes {
			if got, _ := providerLineCode(provider, line); got != code {
				t.Fatalf("%s %s = %q, want %q", provider, line, got, code)
			}
		}
	}
}

// Provider codes read back as the area line; DNS.COM free plan refuses the
// continent lines before any request.
func TestAreaLineReadBackAndPlan(t *testing.T) {
	if got := aliyunLine("os_south_eastern_asia"); got != LineSoutheastAsia {
		t.Fatalf("aliyun read back = %q", got)
	}
	if got := huaweiLine("AP"); got != LineAsia {
		t.Fatalf("huawei read back = %q", got)
	}
	if got := dnsLALine("84613318593225728", "eurabr"); got != LineEurope {
		t.Fatalf("dns.la read back = %q", got)
	}
	if got := huaweiLine("OA"); got != LineOceania {
		t.Fatalf("huawei OA read back = %q", got)
	}
	if got := aliyunLine("os_sentral_america"); got != "中美地区" {
		t.Fatalf("aliyun 中美 read back = %q", got)
	}
	if got := dnsLALine("84613318937158656", "oceabr"); got != LineOceania {
		t.Fatalf("dns.la 大洋洲 read back = %q", got)
	}
	config := completeTestConfig(reconcileHTTPProviderConfig(providerDNSCom))
	operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: LineEurope}
	if err := validateProviderReconcileOperation(config, operation); ErrorCodeOf(err) != CodeLineNotInPlan {
		t.Fatalf("free DNS.COM 欧洲 = %v", err)
	}
}
