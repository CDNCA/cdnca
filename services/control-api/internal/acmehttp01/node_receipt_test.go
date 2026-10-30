package acmehttp01

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
)

func nodeStatus(generationID uuid.UUID, attempt uint32, state agentv1.AcmeHTTP01OverlayState,
	code agentv1.AcmeHTTP01OverlayResultCode) *agentv1.AcmeHTTP01OverlayStatus {
	causation := nodeCommandEventID(generationID, int(attempt)).String()
	active := generationID.String()
	return &agentv1.AcmeHTTP01OverlayStatus{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: nodeRequestID(generationID).String(),
			CorrelationId: generationID.String(), CausationId: &causation,
		},
		OverlayDeploymentId: generationID.String(), OverlayVersionId: generationID.String(),
		Attempt: attempt, OverlayRevision: 7, State: state, ResultCode: code,
		ActiveOverlayVersionId: &active, ActiveOverlayRevision: 7,
	}
}

func TestNodeReceiptForMapsStatesAndBindsIdentity(t *testing.T) {
	node, generation := uuid.New(), uuid.New()
	ok := agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK
	for state, want := range map[agentv1.AcmeHTTP01OverlayState]string{
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ACTIVATED: "applied",
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY:   "healthy",
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_STAGED:    "",
	} {
		receipt, record, err := nodeReceiptFor(node, nodeStatus(generation, 2, state, ok))
		if err != nil || record != (want != "") || record && (receipt.State != want || receipt.Generation != 7 ||
			receipt.Attempt != 2 || receipt.NodeID != node || receipt.GenerationID != generation) {
			t.Fatalf("%s: %+v record=%v err=%v", state, receipt, record, err)
		}
	}
	failed := nodeStatus(generation, 1, agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED,
		agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_STALE_ATTEMPT)
	failed.ActiveOverlayRevision = 40
	receipt, record, err := nodeReceiptFor(node, failed)
	if err != nil || !record || receipt.State != "failed" || receipt.FailureCode != "stale_attempt" || receipt.ActiveRevision != 40 {
		t.Fatalf("failed: %+v %v %v", receipt, record, err)
	}
	for name, mutate := range map[string]func(*agentv1.AcmeHTTP01OverlayStatus){
		"version differs":    func(s *agentv1.AcmeHTTP01OverlayStatus) { s.OverlayVersionId = uuid.NewString() },
		"foreign request":    func(s *agentv1.AcmeHTTP01OverlayStatus) { s.Event.RequestId = uuid.NewString() },
		"foreign causation":  func(s *agentv1.AcmeHTTP01OverlayStatus) { other := uuid.NewString(); s.Event.CausationId = &other },
		"other attempt":      func(s *agentv1.AcmeHTTP01OverlayStatus) { s.Attempt = 3 },
		"healthy not active": func(s *agentv1.AcmeHTTP01OverlayStatus) { s.ActiveOverlayRevision = 6 },
	} {
		status := nodeStatus(generation, 2, agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY, ok)
		if name == "other attempt" {
			status = nodeStatus(generation, 2, agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY, ok)
		}
		mutate(status)
		if _, _, err := nodeReceiptFor(node, status); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRetryableNodeFailure(t *testing.T) {
	for _, code := range []string{"attempt_timeout", "health_failed", "precheck_failed", "activation_failed"} {
		if !retryableNodeFailure(code) {
			t.Errorf("%s should be retried", code)
		}
	}
	for _, code := range []string{"invalid_artifact", "unsupported", "conflict", "stale_attempt", "expired", "superseded"} {
		if retryableNodeFailure(code) {
			t.Errorf("%s should not be retried", code)
		}
	}
}
