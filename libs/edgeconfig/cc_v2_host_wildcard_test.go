package edgeconfig

import "testing"

// A CC v2 match.host is an exact host or a leading wildcard site domain
// ("*.x.example", a wildcard alias the server serves); anything else is
// refused.
func TestCCV2MatchHostAcceptsWildcardSiteDomain(t *testing.T) {
	for host, valid := range map[string]bool{
		"cc.example.test": true, "*.wild.example.test": true,
		"*.test": false, "a.*.example.test": false, "*wild.example.test": false, "*.Wild.example.test": false,
		"**.example.test": false, "*.": false,
	} {
		policy := testCCV2Policy("11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666")
		policy.Rules[0].Match.Host = host
		if _, err := CanonicalCCV2Policy(policy); (err == nil) != valid {
			t.Errorf("host %q: error = %v, want valid %v", host, err, valid)
		}
	}
}
