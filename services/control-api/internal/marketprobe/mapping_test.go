package marketprobe

import "testing"

func TestCarrier(t *testing.T) {
	for raw, want := range map[string]string{
		"电信": "telecom", "中国电信": "telecom", "China Telecom": "telecom", "CTCC": "telecom", "ct": "telecom",
		"联通": "unicom", "中国联通": "unicom", "UNICOM": "unicom", "cucc": "unicom",
		"移动": "mobile", "中国移动": "mobile", "CMCC": "mobile", "China Mobile": "mobile",
		"BGP": "bgp", "多线": "bgp", "三线BGP": "bgp", "电信/联通/移动 多线": "bgp", "双线": "bgp",
	} {
		if got, ok := Carrier(raw); !ok || got != want {
			t.Fatalf("Carrier(%q) = %q %v, want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"", "  ", "Orange S.A.", "Cogent", "电信/联通", "act", "cnn", "comcast"} {
		if got, ok := Carrier(raw); ok {
			t.Fatalf("Carrier(%q) mapped to %q", raw, got)
		}
	}
}

// A market node's region is a country code from its IP location, never a libs/geoarea
// area (market-service region codes have no underscore; buyer filters and DNS lines go by country).
func TestMarketRegion(t *testing.T) {
	for raw, want := range map[string]string{"CN": "cn", "广东": "cn", "香港": "hk", "UK": "gb", "日本": "jp"} {
		if got, ok := MarketRegion(raw); !ok || got != want {
			t.Fatalf("MarketRegion(%q) = %q %v, want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"", "华南", "东南亚", "Europe", "north_america", "全球", "global"} {
		if got, ok := MarketRegion(raw); ok {
			t.Fatalf("MarketRegion(%q) mapped to %q", raw, got)
		}
	}
}

func TestRegion(t *testing.T) {
	for raw, want := range map[string]string{
		"CN": "cn", "hk": "hk", "UK": "gb", "us": "us",
		"中国": "cn", "国内": "cn", "广东": "cn", "广东省": "cn", "中国广东": "cn", "北京市": "cn", "内蒙古自治区": "cn",
		"香港": "hk", "中国香港": "hk", "Hong Kong": "hk", "澳门": "mo", "台湾": "tw",
		"日本": "jp", "新加坡": "sg", "美国": "us", "United States": "us",
		"欧洲": "europe", "东南亚": "southeast_asia", "Southeast Asia": "southeast_asia", "north_america": "north_america",
		"北美洲": "north_america", "北美": "north_america", "北美北部": "northern_america", "全球": "global", "大洋洲": "oceania", "亚洲": "asia",
		"北欧": "northern_europe",
	} {
		if got, ok := Region(raw); !ok || got != want {
			t.Fatalf("Region(%q) = %q %v, want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"", "亚太", "华南", "东京", "南极洲", "asia-east", "usa-west"} {
		if got, ok := Region(raw); ok {
			t.Fatalf("Region(%q) mapped to %q", raw, got)
		}
	}
}
