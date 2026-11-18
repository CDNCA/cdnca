// Package geoarea is the single list of geographic areas (大区) a node region,
// a DNS line, a probe target or a node market listing can be scoped to, and the
// ISO 3166-1 alpha-2 countries each area covers. Every service and the web
// console read it from here (the web mirror is generated from Areas and
// checked by a test), so an area means the same countries everywhere.
//
// Two levels under global: continents (asia, europe, ...) and their regions
// (east_asia, northern_europe, ...). Country membership follows the UN M49
// standard country or area codes (https://unstats.un.org/unsd/methodology/m49/overview/,
// read 2026-11-19), grouped the usual Chinese way: 北美洲 is M49 Northern
// America + Central America + Caribbean, 南美洲 is not split, Africa's regions
// are M49 Northern Africa plus the four Sub-Saharan intermediate regions.
// TW (not listed by M49) is in east_asia. Uninhabited territories (Exceptions)
// are in no continent or region; global covers them like every country.
// Two deliberate departures from M49, following Chinese geography textbooks
// (and v1, already live): IR is in west_asia (M49: Southern Asia), and AF stays
// in south_asia as in v1.
package geoarea

import (
	"slices"
	"strings"
)

// Area codes. Stable lower-case ASCII; stored in databases and sent on the wire.
const (
	Global = "global"

	Asia          = "asia"
	EastAsia      = "east_asia"
	SoutheastAsia = "southeast_asia"
	SouthAsia     = "south_asia"
	WestAsia      = "west_asia"
	CentralAsia   = "central_asia"

	Europe         = "europe"
	NorthernEurope = "northern_europe"
	WesternEurope  = "western_europe"
	SouthernEurope = "southern_europe"
	EasternEurope  = "eastern_europe"

	Africa         = "africa"
	NorthernAfrica = "northern_africa"
	WesternAfrica  = "western_africa"
	EasternAfrica  = "eastern_africa"
	MiddleAfrica   = "middle_africa"
	SouthernAfrica = "southern_africa"

	NorthAmerica    = "north_america"
	NorthernAmerica = "northern_america"
	CentralAmerica  = "central_america"
	Caribbean       = "caribbean"

	SouthAmerica = "south_america"

	Oceania             = "oceania"
	AustraliaNewZealand = "australia_new_zealand"
	Melanesia           = "melanesia"
	Micronesia          = "micronesia"
	Polynesia           = "polynesia"
)

// Levels.
const (
	LevelGlobal    = "global"
	LevelContinent = "continent"
	LevelRegion    = "region"
)

// Area is one geographic area. Countries is empty for Global, which covers
// every country; a continent's Countries is the union of its regions' (filled
// in at init), or its own list when it has no regions (south_america).
type Area struct {
	Code      string   `json:"code"`
	NameZH    string   `json:"name_zh"`
	NameEN    string   `json:"name_en"`
	Level     string   `json:"level"`
	Parent    string   `json:"parent"` // the continent of a region; "" otherwise
	Countries []string `json:"countries"`
}

// Exceptions: ISO 3166-1 codes in no continent or region (no permanent
// population): Antarctica, Bouvet Island, Heard and McDonald Islands, French
// Southern Territories, South Georgia and the South Sandwich Islands.
var Exceptions = []string{"AQ", "BV", "GS", "HM", "TF"}

func continent(code, zh, en string) Area {
	return Area{Code: code, NameZH: zh, NameEN: en, Level: LevelContinent}
}

func region(code, zh, en, parent string, countries ...string) Area {
	return Area{Code: code, NameZH: zh, NameEN: en, Level: LevelRegion, Parent: parent, Countries: countries}
}

// Areas in display order: global, then each continent followed by its regions.
var Areas = func() []Area {
	areas := []Area{
		{Code: Global, NameZH: "全球", NameEN: "Global", Level: LevelGlobal},

		continent(Asia, "亚洲", "Asia"),
		region(EastAsia, "东亚", "East Asia", Asia, "CN", "HK", "JP", "KP", "KR", "MN", "MO", "TW"),
		region(SoutheastAsia, "东南亚", "Southeast Asia", Asia, "BN", "ID", "KH", "LA", "MM", "MY", "PH", "SG", "TH", "TL", "VN"),
		region(SouthAsia, "南亚", "South Asia", Asia, "AF", "BD", "BT", "IN", "LK", "MV", "NP", "PK"),
		region(WestAsia, "西亚", "West Asia", Asia, "AE", "AM", "AZ", "BH", "CY", "GE", "IL", "IQ", "IR", "JO", "KW", "LB",
			"OM", "PS", "QA", "SA", "SY", "TR", "YE"), // IR: Chinese convention, not M49
		region(CentralAsia, "中亚", "Central Asia", Asia, "KG", "KZ", "TJ", "TM", "UZ"),

		continent(Europe, "欧洲", "Europe"),
		region(NorthernEurope, "北欧", "Northern Europe", Europe, "AX", "DK", "EE", "FI", "FO", "GB", "GG", "IE", "IM", "IS",
			"JE", "LT", "LV", "NO", "SE", "SJ"),
		region(WesternEurope, "西欧", "Western Europe", Europe, "AT", "BE", "CH", "DE", "FR", "LI", "LU", "MC", "NL"),
		region(SouthernEurope, "南欧", "Southern Europe", Europe, "AD", "AL", "BA", "ES", "GI", "GR", "HR", "IT", "ME", "MK",
			"MT", "PT", "RS", "SI", "SM", "VA"),
		region(EasternEurope, "东欧", "Eastern Europe", Europe, "BG", "BY", "CZ", "HU", "MD", "PL", "RO", "RU", "SK", "UA"),

		continent(Africa, "非洲", "Africa"),
		region(NorthernAfrica, "北非", "Northern Africa", Africa, "DZ", "EG", "EH", "LY", "MA", "SD", "TN"),
		region(WesternAfrica, "西非", "Western Africa", Africa, "BF", "BJ", "CI", "CV", "GH", "GM", "GN", "GW", "LR", "ML",
			"MR", "NE", "NG", "SH", "SL", "SN", "TG"),
		region(EasternAfrica, "东非", "Eastern Africa", Africa, "BI", "DJ", "ER", "ET", "IO", "KE", "KM", "MG", "MU", "MW",
			"MZ", "RE", "RW", "SC", "SO", "SS", "TZ", "UG", "YT", "ZM", "ZW"),
		region(MiddleAfrica, "中非", "Middle Africa", Africa, "AO", "CD", "CF", "CG", "CM", "GA", "GQ", "ST", "TD"),
		region(SouthernAfrica, "南部非洲", "Southern Africa", Africa, "BW", "LS", "NA", "SZ", "ZA"),

		continent(NorthAmerica, "北美洲", "North America"),
		region(NorthernAmerica, "北美北部", "Northern America", NorthAmerica, "BM", "CA", "GL", "PM", "US"),
		region(CentralAmerica, "中美洲", "Central America", NorthAmerica, "BZ", "CR", "GT", "HN", "MX", "NI", "PA", "SV"),
		region(Caribbean, "加勒比", "Caribbean", NorthAmerica, "AG", "AI", "AW", "BB", "BL", "BQ", "BS", "CU", "CW", "DM",
			"DO", "GD", "GP", "HT", "JM", "KN", "KY", "LC", "MF", "MQ", "MS", "PR", "SX", "TC", "TT", "VC", "VG", "VI"),

		{Code: SouthAmerica, NameZH: "南美洲", NameEN: "South America", Level: LevelContinent,
			Countries: []string{"AR", "BO", "BR", "CL", "CO", "EC", "FK", "GF", "GY", "PE", "PY", "SR", "UY", "VE"}},

		continent(Oceania, "大洋洲", "Oceania"),
		region(AustraliaNewZealand, "澳新", "Australia and New Zealand", Oceania, "AU", "CC", "CX", "NF", "NZ"),
		region(Melanesia, "美拉尼西亚", "Melanesia", Oceania, "FJ", "NC", "PG", "SB", "VU"),
		region(Micronesia, "密克罗尼西亚", "Micronesia", Oceania, "FM", "GU", "KI", "MH", "MP", "NR", "PW", "UM"),
		region(Polynesia, "波利尼西亚", "Polynesia", Oceania, "AS", "CK", "NU", "PF", "PN", "TK", "TO", "TV", "WF", "WS"),
	}
	for i := range areas {
		if areas[i].Level != LevelRegion {
			continue
		}
		for j := range areas {
			if areas[j].Code == areas[i].Parent {
				areas[j].Countries = append(areas[j].Countries, areas[i].Countries...)
			}
		}
	}
	return areas
}()

// Lookup returns the area with this code.
func Lookup(code string) (Area, bool) {
	for _, area := range Areas {
		if area.Code == code {
			return area, true
		}
	}
	return Area{}, false
}

// Valid reports whether code is a known area code.
func Valid(code string) bool {
	_, ok := Lookup(code)
	return ok
}

// Contains reports whether the area covers the ISO alpha-2 country (any case).
// Global covers every non-empty country, a continent the union of its
// regions; an unknown area covers none.
func Contains(code, country string) bool {
	country = strings.ToUpper(strings.TrimSpace(country))
	if country == "" {
		return false
	}
	if code == Global {
		return true
	}
	area, ok := Lookup(code)
	return ok && slices.Contains(area.Countries, country)
}

// Includes reports whether every country of area inner is in area outer:
// the same area, global (covers all), or inner a region of continent outer.
func Includes(outer, inner string) bool {
	if !Valid(outer) || !Valid(inner) {
		return false
	}
	if outer == inner || outer == Global {
		return true
	}
	area, _ := Lookup(inner)
	return area.Parent == outer
}

// Of returns the finest area that covers the country: its region, or its
// continent when the continent has no regions (south_america); "" when none
// does (Exceptions, codes that are not ISO 3166-1). Never Global.
func Of(country string) string {
	country = strings.ToUpper(strings.TrimSpace(country))
	found := ""
	for _, area := range Areas {
		if area.Code != Global && slices.Contains(area.Countries, country) {
			found = area.Code // regions follow their continent
		}
	}
	return found
}

// ContinentOf returns the continent that covers the country, "" when none does.
func ContinentOf(country string) string {
	area, ok := Lookup(Of(country))
	switch {
	case !ok:
		return ""
	case area.Level == LevelRegion:
		return area.Parent
	}
	return area.Code
}
