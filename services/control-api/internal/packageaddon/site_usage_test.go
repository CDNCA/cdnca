package packageaddon

import (
	"errors"
	"testing"
)

func TestSiteUsageCanonicalDomainsAndNonstandardPorts(t *testing.T) {
	got, err := countSiteAllocations([]siteAllocation{
		{domains: []string{"a.example.co.uk", "b.example.co.uk", "*.Example.co.uk.", "店铺.公司.cn"}, ports: []int64{80, 443, 8080, 8080}},
		{domains: []string{"A.example.co.uk.", "xn--hxtq42j.xn--55qx5d.cn", "tenant.github.io"}, ports: []int64{443, 8080}},
	})
	if err != nil || got != (SiteUsageCounts{Domains: 5, RootDomains: 3, HTTPPorts: 2}) {
		t.Fatalf("counts=%+v err=%v", got, err)
	}
}

func TestSiteUsageRejectsInvalidPublicSuffixAndPort(t *testing.T) {
	for _, value := range []siteAllocation{
		{domains: []string{"co.uk"}},
		{domains: []string{"valid.example"}, ports: []int64{65536}},
	} {
		if _, err := countSiteAllocations([]siteAllocation{value}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid allocation accepted: %+v %v", value, err)
		}
	}
}
