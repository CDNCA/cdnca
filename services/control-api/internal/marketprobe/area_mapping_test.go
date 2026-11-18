package marketprobe

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/geoarea"
)

// Every libs/geoarea area maps from its code, its Chinese and its English name.
func TestRegionAreas(t *testing.T) {
	for _, area := range geoarea.Areas {
		for _, raw := range []string{area.Code, area.NameZH, area.NameEN, strings.ToUpper(area.NameEN), " " + area.NameZH + " "} {
			if got, ok := Region(raw); !ok || got != area.Code {
				t.Errorf("Region(%q) = %q %v, want %q", raw, got, ok, area.Code)
			}
		}
	}
	for raw, want := range map[string]string{"北美": geoarea.NorthAmerica, "北美洲": geoarea.NorthAmerica,
		"north america": geoarea.NorthAmerica, "北美北部": geoarea.NorthernAmerica, "northern america": geoarea.NorthernAmerica,
		"南美": geoarea.SouthAmerica, "大洋": geoarea.Oceania, "亚洲": geoarea.Asia, "Asia": geoarea.Asia,
		"北欧": geoarea.NorthernEurope, "Eastern Europe": geoarea.EasternEurope, "加勒比": geoarea.Caribbean,
		"中美洲": geoarea.CentralAmerica, "南部非洲": geoarea.SouthernAfrica, "middle-africa": geoarea.MiddleAfrica,
		"Australia and New Zealand": geoarea.AustraliaNewZealand, "密克罗尼西亚": geoarea.Micronesia,
		"south-east asia": geoarea.SoutheastAsia, "southeastasia": geoarea.SoutheastAsia} {
		if got, ok := Region(raw); !ok || got != want {
			t.Errorf("Region(%q) = %q %v, want %q", raw, got, ok, want)
		}
	}
	// Countries keep mapping to their own code, not to an area.
	for raw, want := range map[string]string{"新加坡": "sg", "中国香港": "hk", "广东": "cn", "Japan": "jp"} {
		if got, ok := Region(raw); !ok || got != want {
			t.Errorf("Region(%q) = %q %v, want %q", raw, got, ok, want)
		}
	}
}

func TestOverseas(t *testing.T) {
	for _, item := range []struct {
		code            string
		overseas, known bool
	}{
		{"", false, false}, {"cn", false, true}, {"hk", true, true}, {"us", true, true},
		{"southeast_asia", true, true}, {"europe", true, true}, {"africa", true, true},
		{"global", false, false}, {"east_asia", false, false}, {"asia", false, false},
		{"south_asia", true, true}, {"northern_europe", true, true}, {"oceania", true, true}, {"polynesia", true, true},
		{"north_america", true, true}, {"caribbean", true, true}, {"south_america", true, true}, {"eastern_africa", true, true},
	} {
		if overseas, known := Overseas(item.code); overseas != item.overseas || known != item.known {
			t.Errorf("Overseas(%q) = %v %v, want %v %v", item.code, overseas, known, item.overseas, item.known)
		}
	}
}
