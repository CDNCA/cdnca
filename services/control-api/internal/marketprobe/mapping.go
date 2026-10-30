package marketprobe

import (
	"regexp"
	"strings"
)

// Line endpoints carry free-text region and carrier ("广东", "中国电信", ...).
// The market wants coarse codes. A value that does not map is not guessed:
// the node is left out of probing and the reason is logged.

const (
	reasonRegion  = "region_unmapped"
	reasonCarrier = "carrier_unmapped"
)

var carrierKeywords = []struct {
	code  string
	words []string
}{
	{"telecom", []string{"电信", "telecom", "chinanet", "ctcc", "ct"}},
	{"unicom", []string{"联通", "unicom", "cucc", "cnc", "cu"}},
	{"mobile", []string{"移动", "mobile", "cmcc", "cmnet", "cm"}},
}

var bgpKeywords = []string{"bgp", "多线", "三线", "双线", "全网"}

var tokenSplit = regexp.MustCompile(`[\s/,;|+\-_()（）、，]+`)

// Carrier maps a free-text carrier to telecom, unicom, mobile or bgp.
func Carrier(raw string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", false
	}
	for _, word := range bgpKeywords {
		if strings.Contains(value, word) {
			return "bgp", true
		}
	}
	tokens := tokenSplit.Split(value, -1)
	found := ""
	for _, carrier := range carrierKeywords {
		if matchesCarrier(value, tokens, carrier.words) {
			if found != "" {
				return "", false // several carriers without a BGP marker is ambiguous
			}
			found = carrier.code
		}
	}
	return found, found != ""
}

func matchesCarrier(value string, tokens []string, words []string) bool {
	for _, word := range words {
		// Chinese names match anywhere; short Latin codes only as whole tokens.
		if word[0] >= 0x80 || len(word) > 4 {
			if strings.Contains(value, word) {
				return true
			}
			continue
		}
		for _, token := range tokens {
			if token == word {
				return true
			}
		}
	}
	return false
}

var regionNames = map[string]string{
	"中国": "cn", "中国大陆": "cn", "大陆": "cn", "内地": "cn", "国内": "cn", "china": "cn", "mainland": "cn",
	"香港": "hk", "中国香港": "hk", "hongkong": "hk", "hong kong": "hk",
	"澳门": "mo", "中国澳门": "mo", "macau": "mo", "macao": "mo",
	"台湾": "tw", "中国台湾": "tw", "taiwan": "tw",
	"日本": "jp", "japan": "jp", "韩国": "kr", "korea": "kr", "south korea": "kr",
	"新加坡": "sg", "singapore": "sg", "美国": "us", "usa": "us", "united states": "us",
	"德国": "de", "germany": "de", "英国": "gb", "uk": "gb", "united kingdom": "gb",
	"法国": "fr", "france": "fr", "荷兰": "nl", "netherlands": "nl", "俄罗斯": "ru", "russia": "ru",
	"印度": "in", "india": "in", "澳大利亚": "au", "australia": "au", "加拿大": "ca", "canada": "ca",
	"越南": "vn", "vietnam": "vn", "泰国": "th", "thailand": "th", "马来西亚": "my", "malaysia": "my",
	"印度尼西亚": "id", "印尼": "id", "indonesia": "id", "菲律宾": "ph", "philippines": "ph",
}

// Mainland provinces and municipalities: a province names a place in "cn".
var mainlandProvinces = []string{
	"北京", "天津", "上海", "重庆", "河北", "山西", "辽宁", "吉林", "黑龙江", "江苏", "浙江", "安徽", "福建",
	"江西", "山东", "河南", "湖北", "湖南", "广东", "海南", "四川", "贵州", "云南", "陕西", "甘肃", "青海",
	"内蒙古", "广西", "西藏", "宁夏", "新疆",
}

var isoAlpha2 = regexp.MustCompile(`^[a-z]{2}$`)

// Region maps a free-text region to a lowercase ISO 3166 alpha-2 code.
func Region(raw string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", false
	}
	if code, ok := regionNames[value]; ok {
		return code, true
	}
	if isoAlpha2.MatchString(value) {
		if value == "uk" {
			return "gb", true
		}
		return value, true
	}
	// Special regions before the mainland, so "中国香港" is hk, not cn.
	for _, name := range []string{"香港", "澳门", "台湾"} {
		if strings.Contains(value, name) {
			return regionNames[name], true
		}
	}
	trimmed := strings.TrimPrefix(value, "中国")
	for _, province := range mainlandProvinces {
		if strings.HasPrefix(trimmed, province) {
			return "cn", true
		}
	}
	return "", false
}
