package originroute

import (
	"slices"
	"testing"
)

func TestNormalizeRouteHosts(t *testing.T) {
	hosts, err := normalizeRouteHosts([]string{"WWW.example.com", "*.img.example.com"})
	if err != nil || !slices.Equal(hosts, []string{"*.img.example.com", "www.example.com"}) {
		t.Fatalf("%v %v", hosts, err)
	}
	for _, bad := range [][]string{{"bad host"}, {"a.example.com", "A.example.com"}, {"*"}, {"example..com"}} {
		if _, err := normalizeRouteHosts(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	if hosts, err := normalizeRouteHosts(nil); err != nil || hosts != nil {
		t.Fatal("empty hosts")
	}
}

func TestRouteLessPrefersHostConditions(t *testing.T) {
	host := Route{ID: "b", Hosts: []string{"a.example.com"}}
	region := Route{ID: "a", NodeRegions: []string{"cn"}}
	if !routeLess(host, region) || routeLess(region, host) {
		t.Fatal("a host condition is more specific than a node region")
	}
}
