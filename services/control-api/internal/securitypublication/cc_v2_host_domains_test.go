package securitypublication

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

// ccV2HostPolicy is ccV2PolicyForTest with its host condition on host.
func ccV2HostPolicy(host string) securitypolicy.Policy {
	return mutateCCV2Policy(ccV2PolicyForTest(), func(value *securitypolicy.Policy) {
		value.Rules[0].Conditions[0].Values = []string{host}
	})
}

func compileCCV2Host(t *testing.T, domains []string, host string) (string, error) {
	t.Helper()
	compiled, err := CompileSiteSecurityBindingsFor(baseSite(), domains, testTenantScopeID, testSiteID, []ActiveBinding{activeBinding(t, ccV2HostPolicy(host))})
	if err != nil {
		return "", err
	}
	return compiled.Site.CCV2.Policy.Rules[0].Match.Host, nil
}

// A CC host condition may name any domain the server serves (the site
// runtime v2 server_name): the primary, an alias, a wildcard alias, or a
// host under a wildcard alias. Any other host is refused.
func TestCompileCCV2HostConditionCoversEverySiteDomain(t *testing.T) {
	domains := []string{"security.example.test", "alias.example.test", "*.wild.example.test"}
	for _, host := range []string{"security.example.test", "alias.example.test", "*.wild.example.test", "a.wild.example.test", "a.b.wild.example.test"} {
		got, err := compileCCV2Host(t, domains, host)
		if err != nil || got != host {
			t.Errorf("host %q: match.host = %q, %v", host, got, err)
		}
	}
	for _, host := range []string{"other.example.test", "wild.example.test", "*.example.test", "*.a.wild.example.test"} {
		if _, err := compileCCV2Host(t, domains, host); !errors.Is(err, ErrUnsupportedRuntime) {
			t.Errorf("host %q: error = %v, want ErrUnsupportedRuntime", host, err)
		}
	}
}

// Without domains (the legacy single-domain server) only the primary is a
// host the server serves.
func TestCompileCCV2HostConditionWithoutDomainsIsThePrimary(t *testing.T) {
	if got, err := compileCCV2Host(t, nil, "security.example.test"); err != nil || got != "security.example.test" {
		t.Fatalf("primary: %q, %v", got, err)
	}
	if _, err := compileCCV2Host(t, nil, "alias.example.test"); !errors.Is(err, ErrUnsupportedRuntime) {
		t.Fatalf("alias without Domains: %v", err)
	}
}
