package edgeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestProjectSiteChallengeBindsOnlyExactSiteFact(t *testing.T) {
	scopeID := uuid.New()
	siteID := uuid.New()
	policyID := uuid.New()
	secretConfigVersionID := uuid.New()
	fact := ChallengeBindingFact{
		TenantScopeID: scopeID, SiteID: siteID, Host: "a.example.test", PolicyID: policyID,
		PolicyRevision: 7, BindingRevision: 3, SecretConfigVersionID: secretConfigVersionID,
	}

	projection, err := ProjectSiteChallenge(scopeID, siteID, "a.example.test", &fact)
	if err != nil {
		t.Fatalf("ProjectSiteChallenge() error = %v", err)
	}
	if projection == nil || projection.PolicyID != policyID.String() || projection.PolicyRevision != 7 ||
		projection.BindingRevision != 3 || projection.SecretConfigVersionID != secretConfigVersionID.String() ||
		projection.Runtime.PolicyID != policyID.String() || projection.Runtime.PolicyVersion != 7 {
		t.Fatalf("projection = %+v", projection)
	}
	first, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("Marshal(first) error = %v", err)
	}
	second, err := json.Marshal(projection)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("canonical projection changed: %s / %s / %v", first, second, err)
	}

	legacy, err := ProjectSiteChallenge(scopeID, siteID, "a.example.test", nil)
	if err != nil || legacy != nil {
		t.Fatalf("legacy projection = (%+v, %v)", legacy, err)
	}
}

// A wildcard site ("*.x.example") binds a policy named for one concrete host
// under it (053's policy rule); the node matches the rule by site identity, so
// it challenges every host the site serves. The bare suffix, a deeper
// wildcard or another domain stay refused.
func TestProjectSiteChallengeBindsWildcardSiteToACoveredHost(t *testing.T) {
	scopeID, siteID := uuid.New(), uuid.New()
	fact := ChallengeBindingFact{
		TenantScopeID: scopeID, SiteID: siteID, Host: "www.x.example", PolicyID: uuid.New(),
		PolicyRevision: 2, BindingRevision: 1, SecretConfigVersionID: uuid.New(),
	}
	if projection, err := ProjectSiteChallenge(scopeID, siteID, "*.x.example", &fact); err != nil || projection == nil {
		t.Fatalf("wildcard site projection = (%+v, %v)", projection, err)
	}
	for _, host := range []string{"x.example", "*.x.example", "www.other.example"} {
		candidate := fact
		candidate.Host = host
		if projection, err := ProjectSiteChallenge(scopeID, siteID, "*.x.example", &candidate); projection != nil ||
			!errors.Is(err, ErrInvalidChallengeBinding) {
			t.Fatalf("%s: projection = (%+v, %v)", host, projection, err)
		}
	}
	for site, host := range map[string]string{"x.example": "www.x.example", "a.example.test": "*.example.test"} {
		candidate := fact
		candidate.Host = host
		if _, err := ProjectSiteChallenge(scopeID, siteID, site, &candidate); !errors.Is(err, ErrInvalidChallengeBinding) {
			t.Fatalf("site %s host %s: %v", site, host, err)
		}
	}
}

func TestProjectSiteChallengeRejectsScopeAndPolicyDrift(t *testing.T) {
	scopeID := uuid.New()
	siteID := uuid.New()
	base := ChallengeBindingFact{
		TenantScopeID: scopeID, SiteID: siteID, Host: "a.example.test", PolicyID: uuid.New(),
		PolicyRevision: 7, BindingRevision: 3, SecretConfigVersionID: uuid.New(),
	}
	tests := []struct {
		name   string
		mutate func(*ChallengeBindingFact)
	}{
		{name: "cross scope", mutate: func(value *ChallengeBindingFact) { value.TenantScopeID = uuid.New() }},
		{name: "cross site", mutate: func(value *ChallengeBindingFact) { value.SiteID = uuid.New() }},
		{name: "cross host", mutate: func(value *ChallengeBindingFact) { value.Host = "b.example.test" }},
		{name: "unknown policy", mutate: func(value *ChallengeBindingFact) { value.PolicyID = uuid.Nil }},
		{name: "missing policy revision", mutate: func(value *ChallengeBindingFact) { value.PolicyRevision = 0 }},
		{name: "unsafe policy revision", mutate: func(value *ChallengeBindingFact) { value.PolicyRevision = 1 << 53 }},
		{name: "missing binding revision", mutate: func(value *ChallengeBindingFact) { value.BindingRevision = 0 }},
		{name: "missing secret config", mutate: func(value *ChallengeBindingFact) { value.SecretConfigVersionID = uuid.Nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			if projection, err := ProjectSiteChallenge(scopeID, siteID, "a.example.test", &candidate); projection != nil || !errors.Is(err, ErrInvalidChallengeBinding) {
				t.Fatalf("ProjectSiteChallenge() = (%+v, %v)", projection, err)
			}
		})
	}
}
