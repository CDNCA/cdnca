package identityverificationhttp

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
)

func TestIAM10CaseViewRequiresStatusBoundDecisionReason(t *testing.T) {
	actor := testActor()
	valid := []struct {
		status string
		reason string
	}{
		{identityverification.StatusApproved, identityverification.ReasonEvidenceVerified},
		{identityverification.StatusRejected, identityverification.ReasonIdentityMismatch},
		{identityverification.StatusDraft, ""},
	}
	for _, test := range valid {
		item := testCase(actor, identityverification.KindPersonalInitial, test.status, 4)
		item.DecisionReasonCode = test.reason
		view, err := caseView(actor, item, true)
		if err != nil || view.DecisionReasonCode != test.reason {
			t.Errorf("caseView(%q,%q) = (%#v,%v)", test.status, test.reason, view, err)
		}
	}

	invalid := []struct {
		status string
		reason string
	}{
		{identityverification.StatusApproved, ""},
		{identityverification.StatusApproved, identityverification.ReasonIdentityMismatch},
		{identityverification.StatusRejected, ""},
		{identityverification.StatusRejected, identityverification.ReasonEvidenceVerified},
		{identityverification.StatusDraft, identityverification.ReasonIdentityMismatch},
	}
	for _, test := range invalid {
		item := testCase(actor, identityverification.KindPersonalInitial, test.status, 4)
		item.DecisionReasonCode = test.reason
		if _, err := caseView(actor, item, true); err != ErrInvalidStoreResponse {
			t.Errorf("caseView(%q,%q) error = %v, want invalid store response", test.status, test.reason, err)
		}
	}
}
