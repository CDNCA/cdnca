package securitybinding

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

// sec-rebind: the claim state machine over a fake binding (no database).
func TestCheckClaimRebindDetachAndMonotonicVersions(t *testing.T) {
	libraryA, libraryB := uuid.New(), uuid.New()
	activeA := bindingState{policyID: libraryA, kind: "cc", activeVersion: 1, lastClaimedVersion: 1, revision: 2,
		lastPolicyID: libraryA}
	failedRebindToB := bindingState{policyID: libraryA, kind: "cc", activeVersion: 1, lastClaimedVersion: 1, revision: 3,
		lastPolicyID: libraryB}
	detached := bindingState{policyID: libraryA, kind: "cc", lastClaimedVersion: 1, revision: 4,
		lastPolicyID: libraryA, lastDetach: true}
	claim := func(version, revision, active int64, detach bool) PublishRequest {
		return PublishRequest{PolicyVersion: version, ExpectedBindingRevision: revision, ExpectedActiveVersion: active, Detach: detach}
	}
	for _, test := range []struct {
		name    string
		binding bindingState
		policy  uuid.UUID
		kind    string
		request PublishRequest
		want    error
	}{
		// The live 400/409: library B v1 over library A v1.
		{"rebind A v1 to B v1", activeA, libraryB, "cc", claim(1, 2, 1, false), nil},
		{"rebind back to A after B failed", failedRebindToB, libraryA, "cc", claim(2, 3, 1, false), nil},
		{"same library must move forward", activeA, libraryA, "cc", claim(1, 2, 1, false), ErrPolicyVersionConflict},
		{"same library forward", activeA, libraryA, "cc", claim(2, 2, 1, false), nil},
		{"B claim versions do not bind A", failedRebindToB, libraryB, "cc", claim(1, 3, 1, false), nil},
		{"stale binding revision", activeA, libraryB, "cc", claim(1, 1, 1, false), ErrBindingRevision},
		{"stale active version", activeA, libraryB, "cc", claim(1, 2, 0, false), ErrActiveVersionConflict},
		{"other kind", activeA, libraryB, "waf", claim(1, 2, 1, false), ErrBindingConflict},
		{"detach active", activeA, libraryA, "cc", claim(1, 2, 1, true), nil},
		{"detach other library", activeA, libraryB, "cc", claim(1, 2, 1, true), ErrBindingConflict},
		{"detach other version", activeA, libraryA, "cc", claim(2, 2, 1, true), ErrBindingConflict},
		{"detach nothing active", detached, libraryA, "cc", claim(1, 4, 0, true), ErrBindingConflict},
		{"bind the detached library again", detached, libraryA, "cc", claim(1, 4, 0, false), nil},
	} {
		if err := checkClaim(test.binding, test.policy, test.kind, test.request); !errors.Is(err, test.want) {
			t.Errorf("%s: checkClaim = %v, want %v", test.name, err, test.want)
		}
	}
}
