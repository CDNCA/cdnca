package acmehttp01

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestOverlayStatusLegalityMatrix(t *testing.T) {
	tests := []struct {
		name       string
		state      agentv1.AcmeHTTP01OverlayState
		result     agentv1.AcmeHTTP01OverlayResultCode
		hasError   bool
		wantResult bool
		wantError  bool
	}{
		{name: "delivered", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_DELIVERED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK, wantResult: true, wantError: true},
		{name: "delivered with error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_DELIVERED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK, hasError: true, wantResult: true},
		{name: "healthy", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK, wantResult: true, wantError: true},
		{name: "healthy failure result", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED, wantError: true},
		{name: "failed without error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ACTIVATION_FAILED, wantResult: true},
		{name: "failed with error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ACTIVATION_FAILED, hasError: true, wantResult: true, wantError: true},
		{name: "reverting transition", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTING, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED, wantResult: true, wantError: true},
		{name: "reverting with error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTING, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED, hasError: true, wantResult: true, wantError: true},
		{name: "reverted transition", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK, wantResult: true, wantError: true},
		{name: "reverted terminal error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK, hasError: true, wantResult: true, wantError: true},
		{name: "rollback failed without error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED, wantResult: true},
		{name: "rollback failed with error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED, hasError: true, wantResult: true, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validOverlayStateResult(test.state, test.result); got != test.wantResult {
				t.Fatalf("state/result legality = %v, want %v", got, test.wantResult)
			}
			if got := validOverlayErrorPresence(test.state, test.hasError); got != test.wantError {
				t.Fatalf("error presence legality = %v, want %v", got, test.wantError)
			}
		})
	}
}
