package securityactivation

import (
	"testing"

	"github.com/google/uuid"
)

// sec-rebind: the live 400 was validStart comparing library B's version to
// library A's active one.
func TestValidStartVersionsAcrossLibraries(t *testing.T) {
	recovery := &CIDRRecoveryIntent{}
	for _, test := range []struct {
		name  string
		input StartInput
		want  bool
	}{
		{"rebind B v1 over A v1", StartInput{PolicyVersion: 1, ExpectedActivePolicyVersion: 1}, true},
		{"rebind B v1 over A v5", StartInput{PolicyVersion: 1, ExpectedActivePolicyVersion: 5}, true},
		{"first bind", StartInput{PolicyVersion: 1}, true},
		{"no version", StartInput{PolicyVersion: 0, ExpectedActivePolicyVersion: 1}, false},
		{"detach active", StartInput{PolicyVersion: 3, ExpectedActivePolicyVersion: 3, Detach: true}, true},
		{"detach other version", StartInput{PolicyVersion: 4, ExpectedActivePolicyVersion: 3, Detach: true}, false},
		{"detach nothing", StartInput{PolicyVersion: 1, Detach: true}, false},
		{"recovery forward", StartInput{PolicyVersion: 3, ExpectedActivePolicyVersion: 2, Recovery: recovery}, true},
		{"recovery not forward", StartInput{PolicyVersion: 2, ExpectedActivePolicyVersion: 2, Recovery: recovery}, false},
		{"recovery detach", StartInput{PolicyVersion: 2, ExpectedActivePolicyVersion: 2, Recovery: recovery, Detach: true}, false},
	} {
		if got := validStartVersions(test.input); got != test.want {
			t.Errorf("%s: validStartVersions = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestStartDigestCoversDetach(t *testing.T) {
	input := StartInput{TenantScopeID: uuid.New(), SiteID: uuid.New(), PolicyID: uuid.New(), PolicyVersion: 1,
		ExpectedActivePolicyVersion: 1}
	publish, err := startDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Detach = true
	detach, err := startDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	if publish == detach {
		t.Fatal("a detach replays as the publish of the same version")
	}
}

func TestRollbackAvailability(t *testing.T) {
	target, previous := uuid.New(), uuid.New()
	for _, test := range []struct {
		name      string
		facts     rollbackFacts
		available bool
		reason    string
	}{
		{"never promoted", rollbackFacts{}, false, RollbackReasonNoCandidate},
		{"in flight", rollbackFacts{promoted: true, inFlight: true, previousVersion: 1, previousPolicy: previous, target: target}, false, RollbackReasonInFlight},
		// The live disabled button: the first binding has nothing before it.
		{"first binding", rollbackFacts{promoted: true}, false, RollbackReasonNoPrevious},
		{"previous library deleted", rollbackFacts{promoted: true, previousVersion: 1, previousPolicy: previous, target: target, targetDeleted: true}, false, RollbackReasonPolicyDeleted},
		{"after rebind or detach", rollbackFacts{promoted: true, previousVersion: 1, previousPolicy: previous, target: target}, true, ""},
	} {
		got := rollbackAvailability(test.facts)
		if got.Available != test.available || got.Reason != test.reason {
			t.Errorf("%s: rollbackAvailability = %+v, want available=%v reason=%q", test.name, got, test.available, test.reason)
		}
		if got.Available && (got.CandidateID == nil || *got.CandidateID != target || got.PolicyID == nil ||
			*got.PolicyID != previous || got.SourcePolicyVersion != 1) {
			t.Errorf("%s: rollback target = %+v", test.name, got)
		}
	}
}
