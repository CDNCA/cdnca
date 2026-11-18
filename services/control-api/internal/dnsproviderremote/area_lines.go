package dnsproviderremote

// Macro-area lines (two levels: continent ->
// region): nodes of a 大区 region answer the visitors of that area. Like the
// other unified lines, the unified value is the DNSPod line name (大洲 /
// 地理亚区, 专业版 and up); other providers map it in providerLineCodes.
// docs/dns/provider-line-capabilities.md lists the sources (queried
// 2026-11-18, rechecked 2026-11-19):
//   - 阿里云 地域线路-境外 https://help.aliyun.com/zh/dns/pubz-regional-route-outside-china
//     (English page identical): 大洲 os_asia/os_euro/os_namerica/os_samerica/
//     os_africa/os_oceanica and the 亚区 table, which has every region below.
//     os_sentral_america and os_australia_newzaland are spelled as documented.
//   - DNSPod https://docs.dnspod.cn/dns/dns-record-line/ : 大洲 (亚洲 … 大洋洲)
//     and 地理亚区 (东亚地区 … 波利尼西亚地区), every region below.
//   - 华为云: AP 全球_亚太地区, OA 大洋洲, EU, NA, LA 南美洲, AF (official table
//     behind a human check; dnsmgr huawei_line.json and GoEdge
//     provider_huawei_dns.go agree). No regions.
//   - DNS.LA GET https://api.dns.la/api/allLineList : 海外 > 亚洲 asiabr, 欧洲
//     eurabr, 北美洲 namabr, 南美洲 samabr, 非洲 afrabr, 大洋洲 oceabr. No regions.
//   - DNS.COM: 大洲 lines of the enterprise plan (dnsComEnterpriseLines, view_id
//     by name). No regions.
//   - 京东云 lists 大洲 sub-lines but publishes no viewValue for them: not mapped.
//
// A provider without an area's own line writes the closest one above it
// (AreaLine): the region's continent, then 境外, then 默认.
const (
	LineAsia          = "亚洲"
	LineEastAsia      = "东亚地区"
	LineSoutheastAsia = "东南亚地区"
	LineSouthAsia     = "南亚地区"
	LineWestAsia      = "西亚地区"
	LineCentralAsia   = "中亚地区"
	LineEurope        = "欧洲"
	LineNorthAmerica  = "北美洲"
	LineSouthAmerica  = "南美洲"
	LineAfrica        = "非洲"
	LineOceania       = "大洋洲"
)

// areaGlobal is the geoarea code of 全球: answered by the default line.
const areaGlobal = "global"

// areaLineTable: area code (libs/geoarea, kept as literals so this package
// builds against any geoarea version), its unified line, the line above it,
// and the Aliyun / Huawei / DNS.LA codes ("" = the provider has no such
// line). Rows are grouped by continent; the v1 lines keep their relative
// order (SupportedLines lists them in table order).
var areaLineTable = []struct {
	area, line, parent    string
	aliyun, huawei, dnsLA string
}{
	{"asia", LineAsia, LineOverseas, "os_asia", "AP", "84613318538699776"},
	{"east_asia", LineEastAsia, LineAsia, "os_eastern_asia", "", ""},
	{"southeast_asia", LineSoutheastAsia, LineAsia, "os_south_eastern_asia", "", ""},
	{"south_asia", LineSouthAsia, LineAsia, "os_southern_asia", "", ""},
	{"west_asia", LineWestAsia, LineAsia, "os_western_asia", "", ""},
	{"central_asia", LineCentralAsia, LineAsia, "os_central_asia", "", ""},
	{"europe", LineEurope, LineOverseas, "os_euro", "EU", "84613318593225728"},
	{"northern_europe", "北欧地区", LineEurope, "os_northern_europe", "", ""},
	{"western_europe", "西欧地区", LineEurope, "os_western_europe", "", ""},
	{"southern_europe", "南欧地区", LineEurope, "os_southern_europe", "", ""},
	{"eastern_europe", "东欧地区", LineEurope, "os_eastern_europe", "", ""},
	{"north_america", LineNorthAmerica, LineOverseas, "os_namerica", "NA", "84613318853272576"},
	{"northern_america", "北美地区", LineNorthAmerica, "os_northern_america", "", ""},
	{"central_america", "中美地区", LineNorthAmerica, "os_sentral_america", "", ""},
	{"caribbean", "加勒比地区", LineNorthAmerica, "os_caribbean", "", ""},
	{"south_america", LineSouthAmerica, LineOverseas, "os_samerica", "LA", "84613318790358016"},
	{"africa", LineAfrica, LineOverseas, "os_africa", "AF", "84613318651945984"},
	{"northern_africa", "北非地区", LineAfrica, "os_northern_africa", "", ""},
	{"western_africa", "西非地区", LineAfrica, "os_western_africa", "", ""},
	{"eastern_africa", "东非地区", LineAfrica, "os_eastern_africa", "", ""},
	{"middle_africa", "中非地区", LineAfrica, "os_middle_africa", "", ""},
	{"southern_africa", "南非地区", LineAfrica, "os_southern_africa", "", ""},
	{"oceania", LineOceania, LineOverseas, "os_oceanica", "OA", "84613318937158656"},
	{"australia_new_zealand", "澳大利亚和新西兰地区", LineOceania, "os_australia_newzaland", "", ""},
	{"melanesia", "美拉尼西亚地区", LineOceania, "os_melanesia", "", ""},
	{"micronesia", "密克罗尼西亚地区", LineOceania, "os_micronesia", "", ""},
	{"polynesia", "波利尼西亚地区", LineOceania, "os_polynesia", "", ""},
}

// areaLines lists the area lines in table order, as SupportedLines appends them.
func areaLines() []string {
	lines := make([]string, 0, len(areaLineTable))
	for _, row := range areaLineTable {
		lines = append(lines, row.line)
	}
	return lines
}

// AreaCodes lists the macro-area codes that have an area line (every geoarea
// code except global), in table order.
func AreaCodes() []string {
	codes := make([]string, 0, len(areaLineTable))
	for _, row := range areaLineTable {
		codes = append(codes, row.area)
	}
	return codes
}

// AreaOwnLine is the unified line of the area itself, before any provider
// fallback; ok is false for global and an unknown code.
func AreaOwnLine(area string) (string, bool) {
	for _, row := range areaLineTable {
		if row.area == area {
			return row.line, true
		}
	}
	return "", false
}

// AreaLine returns the unified line a provider writes for the nodes of a
// macro area (libs/geoarea code): the area's own line when the provider has
// it, else the closest line above it the provider has (the region's
// continent, then 境外), else 默认. Global is always 默认: the default line
// already holds every published node, so a global node needs no line of its
// own. ok is false only for an unknown area code.
func AreaLine(providerType, area string) (string, bool) {
	if area == areaGlobal {
		return LineDefault, true
	}
	line, ok := AreaOwnLine(area)
	if !ok {
		return "", false
	}
	for line != LineDefault && !areaLineSupported(providerType, line) {
		line = areaLineParent(line)
	}
	return line, true
}

func areaLineParent(line string) string {
	for _, row := range areaLineTable {
		if row.line == line {
			return row.parent
		}
	}
	return LineDefault
}

func areaLineSupported(providerType, line string) bool {
	capability, ok := providerCapabilityFor(providerType)
	return ok && capability.Line && writableLine(providerType, line)
}

func init() {
	for _, row := range areaLineTable {
		for provider, code := range map[string]string{providerAliyun: row.aliyun, providerHuawei: row.huawei,
			providerDNSLA: row.dnsLA} {
			if code != "" {
				providerLineCodes[provider][row.line] = code
			}
		}
	}
}
