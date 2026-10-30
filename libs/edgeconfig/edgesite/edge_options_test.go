package edgesite

import (
	"errors"
	"testing"
)

// site-backend6: the site edit options of the site object.
func TestSiteEdgeOptions(t *testing.T) {
	withEngine := func() Site {
		site := minimalSite()
		pool := site.Origin.Pools[0]
		pool.ID = "search-engine"
		pool.Endpoints = []Endpoint{{ID: "search-engine-0", Scheme: "http", Host: "192.0.2.9", Port: 80, Weight: 1}}
		site.Origin.Pools = append(site.Origin.Pools, pool)
		site.Origin.SearchEngine = &SearchEngineOrigin{PoolID: "search-engine"}
		return site
	}
	valid := map[string]func() Site{
		"search engine pool": withEngine,
		"search engine tokens": func() Site {
			site := withEngine()
			site.Origin.SearchEngine.Tokens = []string{"baiduspider", "googlebot"}
			return site
		},
		"unbuffered both": func() Site {
			site := minimalSite()
			site.Origin.Unbuffered = []string{UnbufferedRequest, UnbufferedResponse}
			return site
		},
		"acme pass-through": func() Site { site := minimalSite(); site.Origin.ACMEPassthrough = true; return site },
		"default site":      func() Site { site := minimalSite(); site.Default = true; return site },
	}
	for name, build := range valid {
		site := build()
		raw, err := Encode(site)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := Decode(raw); err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if !site.UsesEdgeOptions() {
			t.Fatalf("%s: UsesEdgeOptions false", name)
		}
	}
	if minimalSite().UsesEdgeOptions() {
		t.Fatal("a plain site needs no SITE_EDGE_OPTIONS")
	}
	invalid := map[string]func() Site{
		"engine on the default pool": func() Site {
			site := minimalSite()
			site.Origin.SearchEngine = &SearchEngineOrigin{PoolID: "primary"}
			return site
		},
		"engine pool missing": func() Site {
			site := minimalSite()
			site.Origin.SearchEngine = &SearchEngineOrigin{PoolID: "absent"}
			return site
		},
		"upper-case token": func() Site {
			site := withEngine()
			site.Origin.SearchEngine.Tokens = []string{"Googlebot"}
			return site
		},
		"unknown direction": func() Site {
			site := minimalSite()
			site.Origin.Unbuffered = []string{"both"}
			return site
		},
		"unsorted directions": func() Site {
			site := minimalSite()
			site.Origin.Unbuffered = []string{UnbufferedResponse, UnbufferedRequest}
			return site
		},
	}
	for name, build := range invalid {
		if err := Validate(build()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

// The default site answers the empty index name on each of its ports; two
// default sites do not make PortProfiles refuse (they only meet while
// scopes republish one after the other).
func TestDefaultSiteIndexEntries(t *testing.T) {
	site := minimalSite()
	site.Default = true
	site.Listeners = append(site.Listeners, Listener{Port: 443, AddressFamily: FamilyIPv4})
	defaults := 0
	for _, entry := range site.IndexEntries() {
		if entry.Name == DefaultSiteName {
			defaults++
			if entry.Key != IndexKey(entry.Port, "") {
				t.Fatalf("default key of port %d", entry.Port)
			}
		}
	}
	if defaults != 2 {
		t.Fatalf("default entries = %d, want one per port (2)", defaults)
	}
	other := minimalSite()
	other.SiteID = "00000000-0000-4000-8000-0000000000aa"
	other.Hosts.Primary = "other.example.test"
	other.Default = true
	if _, err := PortProfiles([]Site{site, other}); err != nil {
		t.Fatalf("two default sites: %v", err)
	}
}
