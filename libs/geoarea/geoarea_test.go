package geoarea

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"golang.org/x/text/language"
)

// iso3166 is every ISO 3166-1 alpha-2 code (249): the M49 overview's ISO
// codes (248, read 2026-11-19) plus TW.
var iso3166 = strings.Fields(`
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO
FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE
JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO
MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW
PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM
TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW`)

// leaves are the areas a country is finally placed in: regions, and
// continents without regions.
func leaves() []Area {
	var out []Area
	for _, area := range Areas {
		if area.Level == LevelRegion || (area.Level == LevelContinent && !hasRegions(area.Code)) {
			out = append(out, area)
		}
	}
	return out
}

func hasRegions(continent string) bool {
	return slices.ContainsFunc(Areas, func(a Area) bool { return a.Parent == continent })
}

func TestAreasAreWellFormed(t *testing.T) {
	code := regexp.MustCompile(`^[a-z][a-z_]*[a-z]$`)
	seen := map[string]bool{}
	if Areas[0].Code != Global || Areas[0].Level != LevelGlobal || len(Areas[0].Countries) != 0 {
		t.Fatalf("global must be first, level global, countryless: %+v", Areas[0])
	}
	continent := ""
	for i, area := range Areas {
		if !code.MatchString(area.Code) || seen[area.Code] || area.NameZH == "" || area.NameEN == "" {
			t.Fatalf("bad area %+v", area)
		}
		seen[area.Code] = true
		switch area.Level {
		case LevelGlobal:
			if i != 0 || area.Parent != "" {
				t.Fatalf("bad global %+v", area)
			}
		case LevelContinent:
			if area.Parent != "" || len(area.Countries) == 0 {
				t.Fatalf("continent %s: parent %q, %d countries", area.Code, area.Parent, len(area.Countries))
			}
			continent = area.Code
		case LevelRegion:
			// A region follows its continent (display order) and is not empty.
			if area.Parent != continent || len(area.Countries) == 0 {
				t.Fatalf("region %s: parent %q after continent %q, %d countries", area.Code, area.Parent, continent, len(area.Countries))
			}
		default:
			t.Fatalf("%s: level %q", area.Code, area.Level)
		}
		for _, country := range area.Countries {
			region, err := language.ParseRegion(country)
			if err != nil || region.String() != country {
				t.Fatalf("%s: %q is not an ISO alpha-2 code", area.Code, country)
			}
		}
	}
	// Names are unique too (probemap maps names back to codes).
	names := map[string]string{}
	for _, area := range Areas {
		for _, name := range []string{area.NameZH, strings.ToLower(area.NameEN)} {
			if other, dup := names[name]; dup {
				t.Fatalf("%s and %s share the name %q", other, area.Code, name)
			}
			names[name] = area.Code
		}
	}
}

// TestEveryISOCodeHasOneLeaf: each of the 249 ISO codes is in exactly one
// region (or region-less continent), except the listed uninhabited ones,
// which are in none; no area lists anything else.
func TestEveryISOCodeHasOneLeaf(t *testing.T) {
	if len(iso3166) != 249 {
		t.Fatalf("iso list has %d codes", len(iso3166))
	}
	placed := map[string]string{}
	for _, leaf := range leaves() {
		for _, country := range leaf.Countries {
			if other, dup := placed[country]; dup {
				t.Fatalf("%s is in both %s and %s", country, other, leaf.Code)
			}
			placed[country] = leaf.Code
		}
	}
	for _, country := range iso3166 {
		_, ok := placed[country]
		if ok == slices.Contains(Exceptions, country) {
			t.Errorf("%s: placed in %q, exception %v", country, placed[country], !ok)
		}
	}
	if len(placed)+len(Exceptions) != len(iso3166) {
		t.Fatalf("placed %d + exceptions %d != %d ISO codes", len(placed), len(Exceptions), len(iso3166))
	}
}

// TestContinentsAreTheirRegionsUnion: a continent's countries are exactly its
// regions' (when it has regions), and continents do not overlap.
func TestContinentsAreTheirRegionsUnion(t *testing.T) {
	owner := map[string]string{}
	for _, area := range Areas {
		if area.Level != LevelContinent {
			continue
		}
		if hasRegions(area.Code) {
			var union []string
			for _, r := range Areas {
				if r.Parent == area.Code {
					union = append(union, r.Countries...)
				}
			}
			got, want := slices.Sorted(slices.Values(area.Countries)), slices.Sorted(slices.Values(union))
			if !slices.Equal(got, want) {
				t.Fatalf("%s countries %v are not its regions' union %v", area.Code, got, want)
			}
		}
		for _, country := range area.Countries {
			if other, dup := owner[country]; dup {
				t.Fatalf("%s is in continents %s and %s", country, other, area.Code)
			}
			owner[country] = area.Code
		}
	}
}

func TestContainsOfAndContinentOf(t *testing.T) {
	cases := []struct {
		area, country string
		want          bool
	}{
		{SoutheastAsia, "sg", true}, {SoutheastAsia, "JP", false}, {EastAsia, "HK", true}, {EastAsia, "TW", true},
		{Global, "AU", true}, {Global, "AQ", true}, {Global, "", false}, {Oceania, "AU", true}, {Asia, "CN", true},
		{Asia, "RU", false}, {Europe, "RU", true}, {EasternEurope, "RU", true}, {WestAsia, "TR", true},
		{Africa, "EG", true}, {NorthernAfrica, "EG", true}, {NorthAmerica, "PA", true}, {CentralAmerica, "MX", true},
		{SouthAmerica, "BR", true}, {"antarctica", "AQ", false}, {"nowhere", "US", false},
	}
	for _, c := range cases {
		if got := Contains(c.area, c.country); got != c.want {
			t.Errorf("Contains(%q,%q)=%v want %v", c.area, c.country, got, c.want)
		}
	}
	for country, want := range map[string][2]string{
		"vn": {SoutheastAsia, Asia}, "AU": {AustraliaNewZealand, Oceania}, "IN": {SouthAsia, Asia},
		"KZ": {CentralAsia, Asia}, "GB": {NorthernEurope, Europe}, "BR": {SouthAmerica, SouthAmerica},
		"US": {NorthernAmerica, NorthAmerica}, "JM": {Caribbean, NorthAmerica}, "ZA": {SouthernAfrica, Africa},
		"AQ": {"", ""}, "XX": {"", ""}, "": {"", ""},
	} {
		if got := [2]string{Of(country), ContinentOf(country)}; got != want {
			t.Errorf("Of/ContinentOf(%q) = %v, want %v", country, got, want)
		}
	}
	if !Valid(Global) || !Valid(Oceania) || Valid("antarctica") || Valid("") {
		t.Fatalf("Valid mismatch")
	}
}

func TestIncludes(t *testing.T) {
	for _, c := range []struct {
		outer, inner string
		want         bool
	}{
		{Global, EastAsia, true}, {Global, Global, true}, {Asia, EastAsia, true}, {Asia, Asia, true},
		{EastAsia, Asia, false}, {Europe, EastAsia, false}, {EastAsia, EastAsia, true}, {EastAsia, Global, false},
		{"x", "x", false}, {Asia, "", false},
	} {
		if got := Includes(c.outer, c.inner); got != c.want {
			t.Errorf("Includes(%q,%q)=%v want %v", c.outer, c.inner, got, c.want)
		}
	}
}

// TestV1CodesKeepTheirCountries: the v1 codes still cover every country they
// covered (continents may cover more); IR stays in west_asia and AF in
// south_asia (Chinese convention over M49).
func TestV1CodesKeepTheirCountries(t *testing.T) {
	v1 := map[string]string{
		EastAsia: "CN HK MO TW JP KR KP MN", SoutheastAsia: "SG MY TH VN ID PH MM KH LA BN TL",
		SouthAsia: "IN PK BD LK NP BT MV AF", WestAsia: "AE SA QA KW BH OM YE IQ IR IL PS JO LB SY TR CY GE AM AZ",
		CentralAsia: "KZ UZ TM KG TJ",
		Europe: "GB IE FR DE NL BE LU CH AT IT ES PT PL CZ SK HU RO BG GR SE NO FI DK IS EE LV LT UA BY MD RU RS HR SI BA " +
			"ME MK AL MT MC LI AD SM VA",
		NorthAmerica: "US CA MX GT BZ SV HN NI CR PA CU DO HT JM PR BS TT BB AG DM GD KN LC VC",
		SouthAmerica: "BR AR CL CO PE VE EC BO PY UY GY SR",
		Africa: "DZ AO BJ BW BF BI CV CM CF TD KM CG CD CI DJ EG GQ ER SZ ET GA GM GH GN GW KE LS LR LY MG MW ML MR MU " +
			"MA MZ NA NE NG RW ST SN SC SL SO ZA SS SD TZ TG TN UG ZM ZW",
	}
	for code, countries := range v1 {
		for _, country := range strings.Fields(countries) {
			if !Contains(code, country) {
				t.Errorf("%s no longer covers %s", code, country)
			}
		}
	}
	if Of("IR") != WestAsia || Of("AF") != SouthAsia {
		t.Fatalf("IR must be west_asia and AF south_asia, got %s %s", Of("IR"), Of("AF"))
	}
}
