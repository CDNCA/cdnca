package controlupgrade

import (
	"errors"
	"fmt"
	"testing"
)

// every preparation error maps to one of the
// stable failure codes the 710 CHECK allows; only a transient conflict retries.
func TestCreatePreparationFailureCodes(t *testing.T) {
	for _, test := range []struct {
		err       error
		code      string
		reason    string
		retryable bool
	}{
		{&UpgradeTargetBlockedError{Reason: "schema_downgrade"}, PreparationFailureLicenseRejected, "schema_downgrade", false},
		{fmt.Errorf("issue: %w", &LicenseRefusalError{Status: 403, Code: "installation_banned"}),
			PreparationFailureLicenseRejected, "installation_banned", false},
		{fmt.Errorf("%w: fetch license.example", ErrArtifactUnavailable), PreparationFailureDownloadFailed, "", false},
		{ErrArtifactInvalid, PreparationFailureArtifactInvalid, "", false},
		{ErrGrantInvalid, PreparationFailureGrantInvalid, "", false},
		// A codeless License refusal is still a refusal, named by its HTTP status.
		{fmt.Errorf("issue: %w", licenseIssueError(403, []byte(`{}`))), PreparationFailureLicenseRejected, "http_403", false},
		{licenseIssueError(401, nil), PreparationFailureLicenseRejected, "http_401", false},
		{ErrLicenseUnavailable, PreparationFailureLicenseUnavailable, "", false},
		{ErrLicenseOutcomeUnknown, PreparationFailureLicenseOutcomeUnknown, "", false},
		{ErrNodeNotFound, PreparationFailureCohortIncompatible, "", false},
		{ErrCohortIncompatible, PreparationFailureCohortIncompatible, "", false},
		{ErrPermissionDenied, PreparationFailurePermissionDenied, "", false},
		{fmt.Errorf("%w: finalize: lock", ErrResourceUnavailable), PreparationFailureResourceUnavailable, "", true},
		{errors.New("boom"), PreparationFailureInternal, "", false},
	} {
		code, reason, retryable := createPreparationFailure(test.err)
		if code != test.code || reason != test.reason || retryable != test.retryable {
			t.Errorf("%v = (%q, %q, %v), want (%q, %q, %v)", test.err, code, reason, retryable,
				test.code, test.reason, test.retryable)
		}
	}
}

func TestPrepareRolloutsOnceRequiresRuntimeAndWorkerID(t *testing.T) {
	if _, err := (&Service{store: &Store{}}).PrepareRolloutsOnce(t.Context(), "worker-1"); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("no runtime error = %v", err)
	}
	service := &Service{store: &Store{}, rollout: validTestRolloutRuntime(t)}
	if _, err := service.PrepareRolloutsOnce(t.Context(), "bad worker"); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("invalid worker error = %v", err)
	}
}

// The auto-start after a preparation: an approval-held start and a plan that no
// longer takes it are final; what the console offered "retry the same request"
// for is retried.
func TestCreatePreparationStartFailureCodes(t *testing.T) {
	for _, test := range []struct {
		err       error
		code      string
		reason    string
		retryable bool
	}{
		{errStartApprovalRequired, PreparationStartApprovalRequired, "", false},
		{fmt.Errorf("prepare control upgrade action: %w", ErrStalePlanRevision), PreparationStartRefused, "", false},
		{ErrInvalidPlanTransition, PreparationStartRefused, "", false},
		{ErrPlanBlocked, PreparationStartRefused, "", false},
		{licenseIssueError(422, []byte(`{"code":"Not A Code"}`)), PreparationFailureLicenseRejected, "http_422", false},
		{&LicenseRefusalError{Status: 403, Code: "installation_banned"}, PreparationFailureLicenseRejected, "installation_banned", false},
		{ErrLicenseOutcomeUnknown, PreparationFailureLicenseOutcomeUnknown, "", true},
		{ErrLicenseUnavailable, PreparationFailureLicenseUnavailable, "", true},
		{fmt.Errorf("%w: fetch", ErrArtifactUnavailable), PreparationFailureDownloadFailed, "", true},
		{ErrResourceUnavailable, PreparationFailureResourceUnavailable, "", true},
		{ErrExecutionInvalid, PreparationFailureInternal, "", false},
	} {
		code, reason, retryable := createPreparationStartFailure(test.err)
		if code != test.code || reason != test.reason || retryable != test.retryable {
			t.Errorf("%v = (%q, %q, %v), want (%q, %q, %v)", test.err, code, reason, retryable,
				test.code, test.reason, test.retryable)
		}
	}
}

// LicenseStatusRefusalError only adds the status: every caller of the issue
// calls still sees the mapLicenseStatus sentinel, and the coded refusals and
// 409/5xx answers keep their old errors.
func TestLicenseIssueErrorKeepsSentinels(t *testing.T) {
	for _, status := range []int{400, 401, 403, 422} {
		err := licenseIssueError(status, nil)
		var refusal *LicenseStatusRefusalError
		if !errors.As(err, &refusal) || refusal.Status != status || !errors.Is(err, ErrGrantInvalid) {
			t.Errorf("status %d = %v", status, err)
		}
		var coded *LicenseRefusalError
		if errors.As(err, &coded) {
			t.Errorf("status %d became a coded refusal", status)
		}
	}
	if err := licenseIssueError(503, nil); err != ErrLicenseUnavailable {
		t.Errorf("503 = %v", err)
	}
	if err := licenseIssueError(409, nil); err != ErrResourceUnavailable {
		t.Errorf("409 = %v", err)
	}
	var coded *LicenseRefusalError
	if err := licenseIssueError(403, []byte(`{"code":"installation_banned"}`)); !errors.As(err, &coded) || coded.Code != "installation_banned" {
		t.Errorf("coded 403 = %v", err)
	}
}
