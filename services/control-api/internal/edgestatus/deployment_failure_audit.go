package edgestatus

import (
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
)

// DeploymentFailedAuditAction is written when a node reports a deployment
// failed: the node, its
// error code and its own failure text (at most 512 bytes).
const DeploymentFailedAuditAction = "node.deployment.failed"

// deploymentFailureAudit is the audit event of a node's failed status, false
// for a status that is no failure: not failed, the node ignored an old
// release (superseded) or refused it while frozen (redelivered later). A
// node artifact delivery has its own receipt audit.
func deploymentFailureAudit(deployment lockedDeployment, envelope Envelope, state string, domain artifactDomain,
	now time.Time,
) (audit.Event, bool) {
	if state != "failed" && state != "rollback_failed" || domain == artifactDomainNodeArtifact {
		return audit.Event{}, false
	}
	code := ""
	if envelope.Status.GetError() != nil {
		code = envelope.Status.GetError().GetCode().String()
	}
	if edgedeployment.DeploymentSuperseded(state, code, envelope.Status.GetRunningConfigUnchanged()) ||
		edgedeployment.FrozenRefusal(deployment.action, envelope.Status) {
		return audit.Event{}, false
	}
	message := edgedeployment.DeploymentErrorMessage(envelope.Payload)
	nodeID := envelope.NodeID.String()
	return audit.Event{ScopeID: deployment.scopeID, Action: DeploymentFailedAuditAction,
		ResourceType: "node_deployment", ResourceID: envelope.DeploymentID.String(),
		RequestID: envelope.RequestID.String(), Result: "failure", ReasonCode: code,
		ActorKind: audit.ActorNode, ActorRef: "node:" + nodeID,
		Payload: map[string]any{"node_id": nodeID, "attempt": envelope.Status.Attempt, "action": deployment.action,
			"state": state, "error_code": code, "error_message": message,
			"transition_sequence": envelope.Status.TransitionSequence, "event_id": envelope.EventID.String()},
		OccurredAt: now}, true
}
