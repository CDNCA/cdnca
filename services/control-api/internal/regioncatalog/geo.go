package regioncatalog

import (
	"context"
	"regexp"

	"golang.org/x/text/language"
)

// Standard geography of a region (migration 576): what a market leaf maps a
// subscriber's conditional origin node region onto. CountryCode is ISO
// 3166-1 alpha-2; ProvinceCode a GB/T 2260 province-level code, CN only.

var countryCodePattern = regexp.MustCompile(`^[A-Z]{2}$`)

// ProvinceCodes are the GB/T 2260 province-level codes (incl. 台湾、香港、澳门).
var ProvinceCodes = []string{
	"110000", "120000", "130000", "140000", "150000", "210000", "220000", "230000",
	"310000", "320000", "330000", "340000", "350000", "360000", "370000",
	"410000", "420000", "430000", "440000", "450000", "460000",
	"500000", "510000", "520000", "530000", "540000",
	"610000", "620000", "630000", "640000", "650000", "710000", "810000", "820000",
}

// ValidGeo: both empty, a country alone, or CN with one of ProvinceCodes.
func ValidGeo(country, province string) bool {
	if country == "" {
		return province == ""
	}
	if !countryCodePattern.MatchString(country) {
		return false
	}
	if region, err := language.ParseRegion(country); err != nil || !region.IsCountry() {
		return false
	}
	if province == "" {
		return true
	}
	if country != "CN" {
		return false
	}
	for _, code := range ProvinceCodes {
		if code == province {
			return true
		}
	}
	return false
}

// CodeGeo is a region's code (what nodes and node_regions match on) with
// its standard geography.
type CodeGeo struct {
	Code         string
	CountryCode  string
	ProvinceCode string
}

// LoadCodeGeos is every platform region's code and geography, by code (the
// same platform region catalog node regions are resolved against,
// edgepublish loadNodeRegionCodes). System use, no actor.
func LoadCodeGeos(ctx context.Context, database queryer) (map[string]CodeGeo, error) {
	if database == nil {
		return nil, ErrUnavailable
	}
	rows, err := database.Query(ctx, `SELECT catalog.code,catalog.country_code,catalog.province_code
		FROM region_catalog catalog JOIN access_scopes platform ON platform.id=catalog.platform_scope_id AND platform.kind='platform'
		ORDER BY catalog.display_id`)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	out := map[string]CodeGeo{}
	for rows.Next() {
		var item CodeGeo
		if err := rows.Scan(&item.Code, &item.CountryCode, &item.ProvinceCode); err != nil {
			return nil, ErrUnavailable
		}
		if _, seen := out[item.Code]; !seen {
			out[item.Code] = item
		}
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
