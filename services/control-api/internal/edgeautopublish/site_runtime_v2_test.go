package edgeautopublish

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSiteRuntimeV2AutomaticRequestDigestBindsRealEnqueueFacts(t *testing.T) {
	input := EnqueueInput{
		Actor: Actor{
			UserID:    uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7202"),
			ScopeID:   uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7201"),
			ScopeKind: ScopeKindTenant,
		},
		TargetScopeID:    uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101"),
		SourceKind:       SourceSite,
		SourceResourceID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"),
		Operation:        "site.update",
		Reason:           ReasonResourceMutation,
		Permission:       PermissionSitesManage,
		SourceRequestID:  "request-41",
	}
	policy := Policy{
		TargetScopeID: input.TargetScopeID,
		Revision:      9,
		Mode:          ModeAutomatic,
		NodeIDs: []uuid.UUID{
			uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7301"),
			uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7302"),
		},
		TargetSnapshot: &TargetSnapshot{
			ID:       uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7401"),
			Revision: 3,
			SHA256:   sha256.Sum256([]byte("target-snapshot")),
		},
		ActivationTimeout:            30 * time.Second,
		ObservationWindow:            15 * time.Second,
		RequiredConsecutiveSuccesses: 2,
		MaxAttempts:                  3,
		DeadlineWindow:               10 * time.Minute,
	}
	const sourceRevision int64 = 41
	want, err := automaticRequestDigest(input, policy, sourceRevision)
	if err != nil || want == ([sha256.Size]byte{}) {
		t.Fatalf("automaticRequestDigest() = %x, %v", want, err)
	}

	tests := map[string]func(*EnqueueInput, *Policy, *int64){
		"target scope":      func(input *EnqueueInput, _ *Policy, _ *int64) { input.TargetScopeID = uuid.New() },
		"actor scope":       func(input *EnqueueInput, _ *Policy, _ *int64) { input.Actor.ScopeID = uuid.New() },
		"actor user":        func(input *EnqueueInput, _ *Policy, _ *int64) { input.Actor.UserID = uuid.New() },
		"actor kind":        func(input *EnqueueInput, _ *Policy, _ *int64) { input.Actor.ScopeKind = ScopeKindPlatform },
		"resource":          func(input *EnqueueInput, _ *Policy, _ *int64) { input.SourceResourceID = uuid.New() },
		"operation":         func(input *EnqueueInput, _ *Policy, _ *int64) { input.Operation = "site.origin.update" },
		"reason":            func(input *EnqueueInput, _ *Policy, _ *int64) { input.Reason = "changed" },
		"permission":        func(input *EnqueueInput, _ *Policy, _ *int64) { input.Permission = "changed" },
		"request":           func(input *EnqueueInput, _ *Policy, _ *int64) { input.SourceRequestID = "request-42" },
		"source revision":   func(_ *EnqueueInput, _ *Policy, revision *int64) { *revision = 42 },
		"policy revision":   func(_ *EnqueueInput, policy *Policy, _ *int64) { policy.Revision++ },
		"node":              func(_ *EnqueueInput, policy *Policy, _ *int64) { policy.NodeIDs[0] = uuid.New() },
		"snapshot id":       func(_ *EnqueueInput, policy *Policy, _ *int64) { policy.TargetSnapshot.ID = uuid.New() },
		"snapshot revision": func(_ *EnqueueInput, policy *Policy, _ *int64) { policy.TargetSnapshot.Revision++ },
		"snapshot digest": func(_ *EnqueueInput, policy *Policy, _ *int64) {
			policy.TargetSnapshot.SHA256 = sha256.Sum256([]byte("changed"))
		},
		"activation":  func(_ *EnqueueInput, policy *Policy, _ *int64) { policy.ActivationTimeout += time.Millisecond },
		"observation": func(_ *EnqueueInput, policy *Policy, _ *int64) { policy.ObservationWindow += time.Millisecond },
		"successes":   func(_ *EnqueueInput, policy *Policy, _ *int64) { policy.RequiredConsecutiveSuccesses++ },
		"attempts":    func(_ *EnqueueInput, policy *Policy, _ *int64) { policy.MaxAttempts++ },
		"deadline":    func(_ *EnqueueInput, policy *Policy, _ *int64) { policy.DeadlineWindow += time.Second },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changedInput := input
			changedPolicy := cloneSiteRuntimeV2Policy(policy)
			changedRevision := sourceRevision
			mutate(&changedInput, &changedPolicy, &changedRevision)
			got, err := automaticRequestDigest(changedInput, changedPolicy, changedRevision)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatalf("%s was not digest-bound", name)
			}
		})
	}

	reordered := cloneSiteRuntimeV2Policy(policy)
	reordered.NodeIDs[0], reordered.NodeIDs[1] = reordered.NodeIDs[1], reordered.NodeIDs[0]
	got, err := automaticRequestDigest(input, reordered, sourceRevision)
	if err != nil || got != want {
		t.Fatalf("equivalent node set did not converge: %x, %v", got, err)
	}
}

func cloneSiteRuntimeV2Policy(value Policy) Policy {
	result := value
	result.NodeIDs = append([]uuid.UUID(nil), value.NodeIDs...)
	if value.TargetSnapshot != nil {
		copy := *value.TargetSnapshot
		result.TargetSnapshot = &copy
	}
	return result
}
