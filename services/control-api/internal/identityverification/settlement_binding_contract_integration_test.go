//go:build integration

package identityverification

import (
	"context"
	"testing"
)

func TestSettlementWorkerPublishesImmutableReservationBinding(t *testing.T) {
	fixture := newVerificationFixture(t)
	request := validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xb1), "settlement-binding")
	draft, err := fixture.service.CreateDraft(t.Context(), fixture.applicant.Actor, request)
	if err != nil {
		t.Fatal(err)
	}
	committer := &scriptedSettlementCommitter{results: []SettlementCommitResult{{Outcome: SettlementCommitSucceeded}}}
	worker := newTestSettlementWorker(t, fixture, committer, 3)
	if processed, runErr := worker.RunOnce(context.Background()); runErr != nil || !processed {
		t.Fatalf("RunOnce() = %t,%v", processed, runErr)
	}
	digest, err := requestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	committer.mu.Lock()
	defer committer.mu.Unlock()
	if len(committer.calls) != 1 {
		t.Fatalf("commit calls=%d", len(committer.calls))
	}
	published := committer.calls[0]
	if published.TenantScopeID != fixture.applicant.ScopeID ||
		published.ActorUserID != fixture.applicant.UserID || published.CaseID != draft.ID ||
		published.IdempotencyKey != request.IdempotencyKey || published.RequestDigest != digest ||
		published.EvidenceClaimDigest != request.EvidenceClaimDigest ||
		published.ResolverName != request.ResolverName ||
		published.ResolverReference != request.ResolverReference {
		t.Fatalf("published binding=%#v", published)
	}
}
