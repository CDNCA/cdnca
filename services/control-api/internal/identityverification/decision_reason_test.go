package identityverification

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIAM10DecisionReasonStatusContract(t *testing.T) {
	tests := []struct {
		status string
		reason string
		valid  bool
	}{
		{StatusApproved, ReasonEvidenceVerified, true},
		{StatusRejected, ReasonIdentityMismatch, true},
		{StatusRejected, ReasonEvidenceIncomplete, true},
		{StatusRejected, ReasonEvidenceUnreadable, true},
		{StatusRejected, ReasonOrganizationMismatch, true},
		{StatusRejected, ReasonAuthorizationInvalid, true},
		{StatusRejected, ReasonSuspectedFraud, true},
		{StatusApproved, "", false},
		{StatusApproved, ReasonIdentityMismatch, false},
		{StatusRejected, "", false},
		{StatusRejected, ReasonEvidenceVerified, false},
		{StatusDraft, "", true},
		{StatusSubmitted, "", true},
		{StatusReviewing, "", true},
		{StatusWithdrawn, "", true},
		{StatusExpired, "", true},
		{StatusDraft, ReasonIdentityMismatch, false},
	}
	for _, test := range tests {
		if got := validCaseDecisionReason(test.status, test.reason); got != test.valid {
			t.Errorf("validCaseDecisionReason(%q,%q) = %t, want %t", test.status, test.reason, got, test.valid)
		}
	}

	approved, err := json.Marshal(Case{Status: StatusApproved, DecisionReasonCode: ReasonEvidenceVerified})
	if err != nil || !strings.Contains(string(approved), `"decision_reason_code":"evidence_verified"`) {
		t.Fatalf("approved case JSON = %s, %v", approved, err)
	}
	draft, err := json.Marshal(Case{Status: StatusDraft})
	if err != nil || strings.Contains(string(draft), "decision_reason_code") {
		t.Fatalf("draft case JSON = %s, %v", draft, err)
	}
}

func TestIAM10CaseQueryReadsDecisionReasonOnlyFromReviewFact(t *testing.T) {
	for _, required := range []string{
		"review.reason_code",
		"LEFT JOIN identity_verification_reviews review",
		"review.tenant_scope_id=verification_case.tenant_scope_id",
		"review.case_id=verification_case.id",
		"review.reviewer_user_id=verification_case.reviewer_user_id",
		"review.decision=verification_case.status",
		"review.resulting_revision=verification_case.revision",
	} {
		if !strings.Contains(caseQuery, required) {
			t.Errorf("caseQuery missing review fact binding %q", required)
		}
	}
	for _, forbidden := range []string{"audit_events", "identity_verification_state_events", "reason_code AS decision_reason_code"} {
		if strings.Contains(caseQuery, forbidden) {
			t.Errorf("caseQuery infers decision reason through %q", forbidden)
		}
	}
}
