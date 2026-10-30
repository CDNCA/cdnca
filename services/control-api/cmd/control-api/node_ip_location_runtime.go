package main

import (
	"context"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// nodeIPLocationInterval: how often nodes are checked for a new address or
// library (fix-nodeipgeo); a check without work reads only the node rows.
const nodeIPLocationInterval = time.Minute

// nodeIPLocationSource answers node addresses from the control plane's IP
// intelligence library (the same one access logs and login regions use).
type nodeIPLocationSource struct {
	lookup *analyticslog.PostgresIPIntelLookup
}

func (source nodeIPLocationSource) Library(ctx context.Context) (node.IPLocationLibrary, bool) {
	revision, version, ok := source.lookup.Library(ctx)
	return node.IPLocationLibrary{Revision: revision, Version: version}, ok
}

func (source nodeIPLocationSource) Locate(ctx context.Context, addresses []string) map[string]*node.NodeIPLocation {
	answers := source.lookup.Lookup(ctx, addresses)
	result := make(map[string]*node.NodeIPLocation, len(answers))
	for address, info := range answers {
		if location := nodeIPLocationFromIntel(info); location != nil {
			result[address] = location
		}
	}
	return result
}

// nodeIPLocationFromIntel: the country by its Chinese name, province and city
// by the library's region names, the ISP by its carrier label (the library
// names only mainland carriers).
func nodeIPLocationFromIntel(info *analyticslog.IPInfo) *node.NodeIPLocation {
	if info == nil || len(info.Country) != 2 {
		return nil
	}
	code := strings.ToUpper(info.Country)
	location := &node.NodeIPLocation{CountryCode: code, Country: code, Province: info.ProvinceName, City: info.CityName}
	if region, err := language.ParseRegion(code); err == nil {
		if name := display.Chinese.Regions().Name(region); name != "" {
			location.Country = name
		}
	}
	for _, definition := range ipintel.TagDefinitions() {
		if definition.Name == info.Carrier {
			location.ISP = definition.Label
		}
	}
	return location
}
