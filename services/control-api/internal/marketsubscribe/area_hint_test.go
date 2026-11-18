package marketsubscribe

import (
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
)

// A seller controller from before area geographies
// refuses an area origin rule with the generic
// "invalid site configuration"; the buyer names the likely cause.
func TestAreaRefusalHint(t *testing.T) {
	area := siteconf.Config{OriginRoutes: &siteconf.OriginRoutes{Routes: []siteconf.Route{
		{ID: "de", NodeGeos: []siteconf.NodeGeo{{Country: "DE"}}},
		{ID: "asia", NodeGeos: []siteconf.NodeGeo{{Area: "asia"}}},
		{ID: "eu", NodeGeos: []siteconf.NodeGeo{{Country: "FR"}, {Area: "northern_europe"}}},
	}}}
	country := siteconf.Config{OriginRoutes: &siteconf.OriginRoutes{Routes: []siteconf.Route{
		{ID: "de", NodeGeos: []siteconf.NodeGeo{{Country: "DE"}}}}}}
	invalid := siteconf.Reply{Error: siteconf.ErrInvalid.Error()}
	got := areaRefusalHint(area, invalid)
	if len(got) != 1 || got[0].Code != BlockerSellerAreaUnsupported || got[0].Detail != "asia,eu" {
		t.Fatalf("hint = %+v", got)
	}
	for name, c := range map[string]struct {
		cfg   siteconf.Config
		reply siteconf.Reply
	}{
		"no area rule":       {country, invalid},
		"no origin routes":   {siteconf.Config{}, invalid},
		"other error":        {area, siteconf.Reply{Error: "site limit"}},
		"seller has reasons": {area, siteconf.Reply{Error: siteconf.ErrInvalid.Error(), Blockers: []siteconf.Blocker{{Code: "x"}}}},
	} {
		if got := areaRefusalHint(c.cfg, c.reply); got != nil {
			t.Errorf("%s: hint %+v", name, got)
		}
	}
}
