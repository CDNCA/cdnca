package edgepublish

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fix-https443-scope (73 demo-nodes): HTTPS off with https_ports {443} was a
// bare ErrInvalidInput the automatic worker retried as an unknown outcome; it
// is now a SiteConfigInvalidError naming the site and the rule, still
// validation_error for a manual publication.
func TestSiteRuntimeV2RefusesHTTPSPortsMismatchAsSiteConfigInvalid(t *testing.T) {
	base := siteFact{
		id: uuid.New(), revision: 3, domain: "demo.example.test", domains: []string{"demo.example.test"},
		httpPorts: []string{"80"}, balance: "round_robin", failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}
	for name, test := range map[string]struct {
		mutate func(*siteFact)
		reason string
	}{
		"https off with ports":   {func(f *siteFact) { f.httpsPorts = []string{"443"} }, "https_ports_mismatch"},
		"https on without ports": {func(f *siteFact) { f.httpsEnabled = true }, "https_ports_mismatch"},
		"no ports":               {func(f *siteFact) { f.httpPorts = nil }, "no_listen_ports"},
		"failover tries":         {func(f *siteFact) { f.failoverTries = 0 }, "failover_tries_invalid"},
	} {
		fact := base
		test.mutate(&fact)
		_, _, err := compileSiteRuntimeV2SiteFact(nil, nil, uuid.New(), fact, time.Unix(1, 0).UTC())
		var invalid *SiteConfigInvalidError
		if !errors.As(err, &invalid) || invalid.SiteID != fact.id || invalid.Reason != test.reason ||
			!errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: error = %v, want SiteConfigInvalidError %s", name, err, test.reason)
		}
	}
}
