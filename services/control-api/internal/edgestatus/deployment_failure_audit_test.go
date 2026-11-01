package edgestatus

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func failedEnvelope(t *testing.T, code commonv1.ErrorCode, message string, unchanged bool) Envelope {
	t.Helper()
	status := &agentv1.DeploymentStatus{State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, Attempt: 1,
		TransitionSequence: 3, RunningConfigUnchanged: unchanged,
		Error: &commonv1.ProtocolError{Code: code, Message: message}}
	payload, err := proto.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	return Envelope{NodeID: uuid.New(), DeploymentID: uuid.New(), ConfigID: uuid.New(), EventID: uuid.New(),
		RequestID: uuid.New(), Status: status, Payload: payload}
}

// a node's failed deployment is audited as node.deployment.failed
// with the node, its error code and its own failure text.
func TestDeploymentFailureAuditCarriesTheNodeCause(t *testing.T) {
	deployment := lockedDeployment{scopeID: uuid.New(), action: "apply"}
	now := time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
	cause := "L4 configuration precheck failed: OpenResty command failed: nginx: [emerg] bind() failed\n" + strings.Repeat("x", 600)
	envelope := failedEnvelope(t, commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, cause, true)
	event, ok := deploymentFailureAudit(deployment, envelope, "failed", artifactDomainConfiguration, now)
	if !ok {
		t.Fatal("failed status not audited")
	}
	message, _ := event.Payload["error_message"].(string)
	if event.Action != DeploymentFailedAuditAction || event.Result != "failure" ||
		event.ReasonCode != "ERROR_CODE_FAILED_PRECONDITION" || event.ScopeID != deployment.scopeID ||
		event.ResourceID != envelope.DeploymentID.String() || event.ActorKind != audit.ActorNode ||
		event.Payload["node_id"] != envelope.NodeID.String() || event.Payload["error_code"] != "ERROR_CODE_FAILED_PRECONDITION" ||
		len(message) != edgedeployment.MaxDeploymentErrorMessageBytes || strings.Contains(message, "\n") ||
		!strings.HasPrefix(message, "L4 configuration precheck failed: OpenResty command failed: nginx: [emerg] bind() failed x") {
		t.Fatalf("event %+v", event)
	}
	entry, ok := audit.Lookup(DeploymentFailedAuditAction)
	if !ok || entry.Category != audit.CategoryNode {
		t.Fatalf("catalog entry %+v %v", entry, ok)
	}
	for _, field := range []string{"node_id", "error_code", "error_message"} {
		if !strings.Contains(entry.TemplateZH, "{"+field+"}") {
			t.Fatalf("template lacks %s: %s", field, entry.TemplateZH)
		}
	}
	if _, ok := deploymentFailureAudit(deployment, envelope, "rollback_failed", artifactDomainConfiguration, now); !ok {
		t.Fatal("rollback_failed not audited")
	}
}

func TestDeploymentFailureAuditSkipsNonFailures(t *testing.T) {
	deployment := lockedDeployment{scopeID: uuid.New(), action: "apply"}
	now := time.Now()
	failed := failedEnvelope(t, commonv1.ErrorCode_ERROR_CODE_INTERNAL, "boom", true)
	stale := failedEnvelope(t, commonv1.ErrorCode_ERROR_CODE_STALE_ATTEMPT, "newer running", true)
	frozen := failedEnvelope(t, commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, edgedeployment.InstallationFrozenReason+": ticket expired", true)
	for name, check := range map[string]struct {
		envelope Envelope
		state    string
		domain   artifactDomain
	}{
		"healthy":         {failed, "healthy", artifactDomainConfiguration},
		"superseded":      {stale, "failed", artifactDomainConfiguration},
		"frozen":          {frozen, "failed", artifactDomainConfiguration},
		"artifact domain": {failed, "failed", artifactDomainNodeArtifact},
	} {
		if event, ok := deploymentFailureAudit(deployment, check.envelope, check.state, check.domain, now); ok {
			t.Fatalf("%s audited: %+v", name, event)
		}
	}
}
