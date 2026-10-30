package edgepublish

import (
	"testing"

	"github.com/google/uuid"
)

func TestCompileSiteFactAppliesOnlyExactDurableChallengeBinding(t *testing.T) {
	scopeID := uuid.New()
	siteID := uuid.New()
	fact := siteFact{id: siteID, revision: 3, domain: "challenge.example.test", balance: "round_robin",
		failoverTries: 1, connectTimeoutMS: 1000, readTimeoutMS: 5000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
	binding := &challengeBindingFact{tenantScopeID: scopeID, siteID: siteID, host: fact.domain,
		policyID: uuid.New(), policyRevision: 7,
		bindingRevision: 2, secretConfigVersionID: uuid.New()}
	fact.challenge = binding
	snapshot, site, err := compileSiteFact(scopeID, fact, 80, nil, nil, nil)
	if err != nil {
		t.Fatalf("compileSiteFact(, nil) error = %v", err)
	}
	if site.Challenge == nil || site.Challenge.PolicyID != binding.policyID.String() ||
		site.Challenge.PolicyVersion != uint64(binding.policyRevision) || snapshot.Challenge == nil {
		t.Fatalf("compiled challenge = (%+v, %+v)", site.Challenge, snapshot.Challenge)
	}

	for name, mutate := range map[string]func(*challengeBindingFact){
		"cross scope":    func(value *challengeBindingFact) { value.tenantScopeID = uuid.New() },
		"cross site":     func(value *challengeBindingFact) { value.siteID = uuid.New() },
		"unknown policy": func(value *challengeBindingFact) { value.policyID = uuid.Nil },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := *binding
			mutate(&wrong)
			fact.challenge = &wrong
			if _, _, err := compileSiteFact(scopeID, fact, 80, nil, nil, nil); err != ErrInvalidInput {
				t.Fatalf("compile error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
	fact.challenge = nil
	withoutSnapshot, withoutSite, err := compileSiteFact(scopeID, fact, 80, nil, nil, nil)
	if err != nil || withoutSite.Challenge != nil || withoutSnapshot.Challenge != nil {
		t.Fatalf("unbound site compile = (%+v, %+v, %v)", withoutSite.Challenge, withoutSnapshot.Challenge, err)
	}
}

func TestCompileSiteFactKeepsChallengePoliciesIsolatedAcrossSites(t *testing.T) {
	scopeID := uuid.New()
	compile := func(host string, revision int64) (snapshotSite, string) {
		siteID := uuid.New()
		policyID := uuid.New()
		fact := siteFact{id: siteID, revision: 1, domain: host, balance: "round_robin",
			failoverTries: 1, connectTimeoutMS: 1000, readTimeoutMS: 5000,
			origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}},
			challenge: &challengeBindingFact{tenantScopeID: scopeID, siteID: siteID, host: host,
				policyID: policyID, policyRevision: revision, bindingRevision: revision,
				secretConfigVersionID: uuid.New()},
		}
		snapshot, site, err := compileSiteFact(scopeID, fact, 80, nil, nil, nil)
		if err != nil || site.Challenge == nil {
			t.Fatalf("compile %s = (%+v, %v)", host, site.Challenge, err)
		}
		return snapshot, site.Challenge.PolicyID
	}

	first, firstPolicyID := compile("a.example.test", 3)
	second, secondPolicyID := compile("b.example.test", 9)
	if firstPolicyID == secondPolicyID || first.Challenge.PolicyID != firstPolicyID ||
		second.Challenge.PolicyID != secondPolicyID || first.Challenge.PolicyRevision != 3 ||
		second.Challenge.PolicyRevision != 9 {
		t.Fatalf("cross-site challenge contamination: first=%+v second=%+v", first.Challenge, second.Challenge)
	}
}
