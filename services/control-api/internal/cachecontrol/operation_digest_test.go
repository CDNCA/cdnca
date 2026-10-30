package cachecontrol

import (
	"testing"

	"github.com/google/uuid"
)

// ADD-08: an automatic-node create is identified without the carrying node
// set, so retrying the same intent after the set changes is a replay; an
// explicit node list stays part of the identity.
func TestCreateOperationDigestIgnoresCarryingNodesInAutoMode(t *testing.T) {
	request := CreateOperationRequest{SiteID: uuid.New(), Action: ActionPurge, TargetType: TargetExactURL}
	targets := []Target{{CanonicalURL: "http://example.test/a"}}
	first, second := []uuid.UUID{uuid.New()}, []uuid.UUID{uuid.New(), uuid.New()}

	autoA, err := createOperationDigest(request, targets, first, true)
	if err != nil {
		t.Fatal(err)
	}
	autoB, _ := createOperationDigest(request, targets, second, true)
	autoNone, _ := createOperationDigest(request, targets, nil, true)
	if autoA != autoB || autoA != autoNone {
		t.Fatal("automatic-node digest changed with the carrying node set")
	}
	explicitA, _ := createOperationDigest(request, targets, first, false)
	explicitB, _ := createOperationDigest(request, targets, second, false)
	if explicitA == explicitB {
		t.Fatal("explicit node list must stay in the digest")
	}
	if explicitA == autoA {
		t.Fatal("automatic and explicit requests must differ")
	}
	otherTarget, _ := createOperationDigest(request, []Target{{CanonicalURL: "http://example.test/b"}}, first, true)
	request.Action = ActionPrewarm
	otherAction, _ := createOperationDigest(request, targets, first, true)
	if otherTarget == autoA || otherAction == autoA {
		t.Fatal("target and action must stay in the digest")
	}
}
