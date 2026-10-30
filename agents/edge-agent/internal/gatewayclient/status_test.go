package gatewayclient

import (
	"testing"

	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
)

func TestExplicitRollbackErrorCodesAreStable(t *testing.T) {
	tests := map[string]commonv1.ErrorCode{
		"ROLLBACK_TARGET_INVALID":     commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH,
		"ROLLBACK_BASELINE_INVALID":   commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH,
		"ROLLBACK_TARGET_UNAVAILABLE": commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
		"ROLLBACK_TARGET_MISMATCH":    commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
		"ROLLBACK_BASELINE_MISMATCH":  commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
		"ROLLBACK_PRECHECK_FAILED":    commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE,
		"ROLLBACK_ACTIVATION_FAILED":  commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE,
		"ROLLBACK_HEALTH_FAILED":      commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE,
		"ROLLBACK_RESTORE_FAILED":     commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE,
		"ROLLBACK_POINTER_FAILED":     commonv1.ErrorCode_ERROR_CODE_INTERNAL,
	}
	for code, want := range tests {
		if got := errorCode(code); got != want {
			t.Errorf("errorCode(%q) = %s, want %s", code, got, want)
		}
	}
}

// fix-cfgflow2 §1: an apply refused before activation because the node
// already runs a newer or the rolled-back release reaches the controller with
// a specific code, not INTERNAL, so it shows as an ignored old release.
func TestRevisionRefusalErrorCodesAreSpecific(t *testing.T) {
	tests := map[string]commonv1.ErrorCode{
		"STALE_CONFIGURATION_REVISION":    commonv1.ErrorCode_ERROR_CODE_STALE_ATTEMPT,
		"CONFIGURATION_ROLLED_BACK":       commonv1.ErrorCode_ERROR_CODE_REVOKED,
		"CONFIGURATION_REVISION_CONFLICT": commonv1.ErrorCode_ERROR_CODE_CONFLICT,
	}
	for code, want := range tests {
		if got := errorCode(code); got != want {
			t.Errorf("errorCode(%q) = %s, want %s", code, got, want)
		}
	}
}
