package dnsproviderremote

import "strings"

// Province+carrier lines for smart scheduling. The unified value of a province line is its
// DNSPod line name (省份短名+运营商, e.g. "广东电信"), like the five basic
// lines in lines.go; DNSPod writes it verbatim, other providers map it in
// providerLineCodes. docs/dns/provider-line-capabilities.md lists the
// sources.
//
// Sources (2026-10-31):
//   - DNSPod 智能解析线路说明 https://docs.dnspod.cn/dns/dns-record-line/
//     「省份运营商」适用于企业版、尊享版; 内蒙古 is written 内蒙电信/内蒙联通/
//     内蒙移动 (the other provinces use their short name).
//   - 阿里云 运营商线路 https://help.aliyun.com/zh/dns/pubz-operator-line
//     (linked from 解析线路枚举 https://help.aliyun.com/zh/dns/pubz-resolve-line-enumeration/):
//     三级线路 中国电信_广东（cn_telecom_guangdong）, likewise cn_unicom_* /
//     cn_mobile_*, 31 provinces each; 陕西 is shaanxi, 山西 shanxi. Written
//     to AddDomainRecord/UpdateDomainRecord "Line".
//   - 华为云 解析线路 https://support.huaweicloud.com/api-dns/zh-cn_topic_0085546214.html
//     (运营商_省, e.g. Dianxin_Shanxi): the page is behind a human check, so
//     the IDs were cross-checked against two independent implementations,
//     GoEdge https://github.com/TeaOSLab/EdgeAPI/blob/master/internal/dnsclients/provider_huawei_dns.go
//     and dnsmgr https://github.com/netcccyun/dnsmgr/blob/main/app/data/huawei_line.json
//     (identical 114 codes). Dianxin_/Liantong_/Yidong_ + the same pinyin
//     as Aliyun, first letter upper (Dianxin_Shaanxi 陕西). Written to the
//     v2.1 record set "line".
//   - DNS.LA GET https://api.dns.la/api/allLineList (no auth): 电信 > 华南电信
//     > 广东电信 (code cngdhnntele) and so on; the ID is written to "lineId".
//   - DNS.COM: the official plans open 大区 lines (企业版) but no province
//     lines (dnscom_lines.go), so none are mapped. Cloudflare, name.com:
//     no line support at all. custom_http / plugin: the protocol defines
//     only the five unified lines.

// Carriers of ProvinceCarrierLine.
const (
	CarrierTelecom = "telecom"
	CarrierUnicom  = "unicom"
	CarrierMobile  = "mobile"
)

var provinceCarriers = [3]struct{ carrier, name, aliyun, huawei string }{
	{CarrierTelecom, "电信", "cn_telecom_", "Dianxin_"},
	{CarrierUnicom, "联通", "cn_unicom_", "Liantong_"},
	{CarrierMobile, "移动", "cn_mobile_", "Yidong_"},
}

// provinceLineTable: the 31 mainland provincial-level divisions. dnsPod is
// the DNSPod line-name prefix, pinyin the Aliyun/Huawei code suffix, dnsLA
// the DNS.LA line IDs in provinceCarriers order (电信, 联通, 移动).
var provinceLineTable = []struct {
	province, dnsPod, pinyin string
	dnsLA                    [3]string
}{
	{"北京", "北京", "beijing", [3]string{"84613320799429632", "84613320736515072", "84613323240514560"}},
	{"天津", "天津", "tianjin", [3]string{"84613321172722688", "84613321097225216", "84613323278263296"}},
	{"河北", "河北", "hebei", [3]string{"84613321709593600", "84613321659261952", "84613323341177856"}},
	{"山西", "山西", "shanxi", [3]string{"84613321889948672", "84613321831228416", "84613323353760768"}},
	{"内蒙古", "内蒙", "neimenggu", [3]string{"84613322045137920", "84613321982223360", "84613323370537984"}},
	{"辽宁", "辽宁", "liaoning", [3]string{"84613321613124608", "84613321562792960", "84613323328594944"}},
	{"吉林", "吉林", "jilin", [3]string{"84613321487295488", "84613321441158144", "84613323316012032"}},
	{"黑龙江", "黑龙江", "heilongjiang", [3]string{"84613321365660672", "84613321315329024", "84613323303429120"}},
	{"上海", "上海", "shanghai", [3]string{"84613320933647360", "84613320866538496", "84613323261486080"}},
	{"江苏", "江苏", "jiangsu", [3]string{"84613322728809472", "84613322712032256", "84613323399898112"}},
	{"浙江", "浙江", "zhejiang", [3]string{"84613322783335424", "84613322766558208", "84613323420869632"}},
	{"安徽", "安徽", "anhui", [3]string{"84613322753975296", "84613322745586688", "84613323408286720"}},
	{"福建", "福建", "fujian", [3]string{"84613322842055680", "84613322829472768", "84613323446035456"}},
	{"江西", "江西", "jiangxi", [3]string{"84613322812695552", "84613322795918336", "84613323433452544"}},
	{"山东", "山东", "shandong", [3]string{"84613322699449344", "84613322112246784", "84613323383120896"}},
	{"河南", "河南", "henan", [3]string{"84613320589714432", "84613320530994176", "84613323248903168"}},
	{"湖北", "湖北", "hubei", [3]string{"84613322863027200", "84613322854638592", "84613323467006976"}},
	{"湖南", "湖南", "hunan", [3]string{"84613322888193024", "84613322879804416", "84613323475395584"}},
	{"广东", "广东", "guangdong", [3]string{"84613322917553152", "84613322904970240", "84613323487978496"}},
	{"广西", "广西", "guangxi", [3]string{"84613322980467712", "84613322967884800", "84613323517338624"}},
	{"海南", "海南", "hainan", [3]string{"84613322951107584", "84613322934330368", "84613323504755712"}},
	{"重庆", "重庆", "chongqing", [3]string{"84613321269191680", "84613321218860032", "84613323290846208"}},
	{"四川", "四川", "sichuan", [3]string{"84613323005633536", "84613322997244928", "84613323529921536"}},
	{"贵州", "贵州", "guizhou", [3]string{"84613323043382272", "84613323026605056", "84613323538310144"}},
	{"云南", "云南", "yunnan", [3]string{"84613323068548096", "84613323055965184", "84613323555087360"}},
	{"西藏", "西藏", "xizang", [3]string{"84613323093713920", "84613323076936704", "84613323567670272"}},
	{"陕西", "陕西", "shaanxi", [3]string{"84613323118879744", "84613323102102528", "84613323580253184"}},
	{"甘肃", "甘肃", "gansu", [3]string{"84613323169211392", "84613323160822784", "84613323605419008"}},
	{"青海", "青海", "qinghai", [3]string{"84613323198571520", "84613323185988608", "84613323622196224"}},
	{"宁夏", "宁夏", "ningxia", [3]string{"84613323144045568", "84613323135656960", "84613323588641792"}},
	{"新疆", "新疆", "xinjiang", [3]string{"84613323227931648", "84613323211154432", "84613323634779136"}},
}

// provinceSuffixes are stripped from full official names (广西壮族自治区,
// 广东省, 北京市) to reach the short name; longest first.
var provinceSuffixes = []string{"维吾尔自治区", "壮族自治区", "回族自治区", "自治区", "省", "市"}

// canonicalProvince returns the short name of a mainland province, accepting
// the full official name and DNSPod's 内蒙.
func canonicalProvince(name string) (int, bool) {
	name = strings.TrimSpace(name)
	if name == "内蒙" {
		name = "内蒙古"
	}
	for _, candidate := range []string{name, trimProvinceSuffix(name)} {
		for index, row := range provinceLineTable {
			if row.province == candidate {
				return index, true
			}
		}
	}
	return 0, false
}

func trimProvinceSuffix(name string) string {
	for _, suffix := range provinceSuffixes {
		if trimmed, ok := strings.CutSuffix(name, suffix); ok && trimmed != "" {
			return trimmed
		}
	}
	return name
}

// ProvinceCarrierLine returns the unified line of a mainland province and
// carrier (telecom/unicom/mobile), e.g. ("广东", "mobile") -> "广东移动".
// Unknown provinces (including 香港/澳门/台湾) and carriers return false.
func ProvinceCarrierLine(province, carrier string) (string, bool) {
	index, ok := canonicalProvince(province)
	if !ok {
		return "", false
	}
	for _, known := range provinceCarriers {
		if known.carrier == carrier {
			return provinceLineTable[index].dnsPod + known.name, true
		}
	}
	return "", false
}

// SupportsProvinceLines reports whether the provider adapter writes the
// province+carrier lines. The provider account's plan may still refuse
// them (DNSPod: 企业版/尊享版 only); that is the API's answer at write time.
func SupportsProvinceLines(providerType string) bool {
	switch providerType {
	case providerDNSPodCN, providerAliyun, providerHuawei, providerDNSLA:
		return true
	}
	return false
}

// provinceLines lists the unified province lines in table order, carriers
// telecom, unicom, mobile.
func provinceLines() []string {
	lines := make([]string, 0, len(provinceLineTable)*len(provinceCarriers))
	for _, row := range provinceLineTable {
		for _, carrier := range provinceCarriers {
			lines = append(lines, row.dnsPod+carrier.name)
		}
	}
	return lines
}

func init() {
	for _, row := range provinceLineTable {
		for index, carrier := range provinceCarriers {
			line := row.dnsPod + carrier.name
			providerLineCodes[providerAliyun][line] = carrier.aliyun + row.pinyin
			providerLineCodes[providerHuawei][line] = carrier.huawei + strings.ToUpper(row.pinyin[:1]) + row.pinyin[1:]
			providerLineCodes[providerDNSLA][line] = row.dnsLA[index]
		}
	}
}
