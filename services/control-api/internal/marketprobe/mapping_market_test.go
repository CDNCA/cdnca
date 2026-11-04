package marketprobe

import "testing"

func TestMarketCarrierOnlyRequiredOnTheMainland(t *testing.T) {
	for _, c := range []struct {
		region, raw, want string
		ok                bool
	}{
		{"cn", "中国电信", "telecom", true},
		{"cn", "", "", false},
		{"cn", "HKBN", "", false},
		{"hk", "", "bgp", true},
		{"hk", "PCCW", "bgp", true},
		{"us", "Cogent", "bgp", true},
		{"tw", "中华电信", "bgp", true},
		{"jp", "BGP", "bgp", true},
	} {
		got, ok := MarketCarrier(c.region, c.raw)
		if got != c.want || ok != c.ok {
			t.Errorf("MarketCarrier(%q, %q) = %q %v, want %q %v", c.region, c.raw, got, ok, c.want, c.ok)
		}
	}
}
