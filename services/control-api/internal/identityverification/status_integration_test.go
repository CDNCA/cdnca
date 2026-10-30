//go:build integration

package identityverification

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCurrentStatusFollowsOwnLatestCaseAndVerifiedPerson(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx := context.Background()
	applicant := fixture.applicant.Actor
	advance := func() { fixture.clock.set(fixture.clock.now().Add(time.Minute)) }
	expect := func(label string, verified bool, latestStatus string, latestID *Case) SelfStatus {
		t.Helper()
		status, err := fixture.service.CurrentStatus(ctx, applicant)
		if err != nil {
			t.Fatalf("%s CurrentStatus: %v", label, err)
		}
		if status.PersonVerified != verified || (status.VerifiedAt != nil) != verified {
			t.Fatalf("%s verified = %t at %v, want %t", label, status.PersonVerified, status.VerifiedAt, verified)
		}
		if latestStatus == "" {
			if status.LatestCase != nil {
				t.Fatalf("%s latest case = %#v, want none", label, status.LatestCase)
			}
			return status
		}
		if status.LatestCase == nil || status.LatestCase.Status != latestStatus ||
			(latestID != nil && status.LatestCase.ID != latestID.ID) ||
			status.LatestCase.TenantScopeID != applicant.ScopeID || status.LatestCase.ApplicantUserID != applicant.UserID {
			t.Fatalf("%s latest case = %#v, want status %s", label, status.LatestCase, latestStatus)
		}
		return status
	}

	expect("no case", false, "", nil)

	rejectedDraft, err := fixture.service.CreateDraft(ctx, applicant,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0x51), "status-rejected"))
	if err != nil {
		t.Fatal(err)
	}
	expect("draft", false, StatusDraft, &rejectedDraft)
	settleDraft(t, fixture.pool, rejectedDraft.ID, fixture.clock.now())
	submitted, err := fixture.service.Submit(ctx, applicant, mutation(rejectedDraft, "status-rejected-submit"))
	if err != nil {
		t.Fatal(err)
	}
	expect("submitted", false, StatusSubmitted, &submitted)
	reviewing, err := fixture.service.StartReview(ctx, fixture.reviewer.Actor, mutation(submitted, "status-rejected-start"))
	if err != nil {
		t.Fatal(err)
	}
	expect("reviewing", false, StatusReviewing, &reviewing)
	rejected, err := fixture.service.Review(ctx, fixture.reviewer.Actor, ReviewRequest{CaseID: reviewing.ID,
		ExpectedRevision: reviewing.Revision, Decision: DecisionReject, ReasonCode: ReasonEvidenceUnreadable,
		IdempotencyKey: "status-rejected-review", RequestID: "status-rejected-review-request"})
	if err != nil {
		t.Fatal(err)
	}
	status := expect("rejected", false, StatusRejected, &rejected)
	if status.LatestCase.DecisionReasonCode != ReasonEvidenceUnreadable {
		t.Fatalf("rejected reason = %q", status.LatestCase.DecisionReasonCode)
	}

	advance()
	approvedAt := fixture.clock.now()
	approved := approveCase(t, fixture, validPersonalDraft(KindPersonalInitial, bytesOf(32, 0x52), "status-approved"),
		"status-approved")
	status = expect("approved", true, StatusApproved, &approved)
	if !status.VerifiedAt.Equal(approvedAt) {
		t.Fatalf("verified at = %v, want %v", status.VerifiedAt, approvedAt)
	}

	// A newer reverification draft is the latest case, but the person stays verified.
	advance()
	reverify, err := fixture.service.CreateDraft(ctx, applicant,
		validPersonalDraft(KindPersonalReverification, bytesOf(32, 0x52), "status-reverify"))
	if err != nil {
		t.Fatal(err)
	}
	expect("reverification draft", true, StatusDraft, &reverify)

	// Another tenant member never sees the applicant's facts.
	other, err := fixture.service.CurrentStatus(ctx, fixture.unauthorized.Actor)
	if err != nil || other.PersonVerified || other.LatestCase != nil {
		t.Fatalf("other member status = %#v, %v", other, err)
	}
	for label, actor := range map[string]Actor{
		"reviewer without self manage": fixture.reviewer.Actor,
		"other tenant reviewer":        fixture.otherReviewer.Actor,
	} {
		if _, err := fixture.service.CurrentStatus(ctx, actor); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s CurrentStatus error = %v, want permission denied", label, err)
		}
	}
	if _, err := fixture.service.CurrentStatus(ctx, Actor{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CurrentStatus(zero actor) error = %v", err)
	}
}
