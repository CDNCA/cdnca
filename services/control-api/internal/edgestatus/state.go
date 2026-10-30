package edgestatus

import agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"

func stateStorageValue(state agentv1.NodeDeploymentState) (string, bool) {
	switch state {
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_QUEUED:
		return "queued", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED:
		return "delivered", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED:
		return "agent_queued", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED:
		return "started", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED:
		return "staged", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED:
		return "prechecked", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED:
		return "activated", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY:
		return "healthy", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED:
		return "failed", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING:
		return "reverting", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED:
		return "reverted", true
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED:
		return "rollback_failed", true
	default:
		// SUPERSEDED is unreachable: the control plane keeps one in-flight
		// deployment per (node, scope), so nothing can replace a queued one.
		return "", false
	}
}

func validAdvance(action, from, to string) bool {
	if from == "queued" {
		return to == "delivered"
	}
	// A MULTI_TENANT_RUNTIME agent queues a delivered deployment until the
	// node applies it; started is where the legacy delivered path resumes.
	switch from {
	case "agent_queued":
		return to == "started" || to == "failed"
	case "started":
		return to == "staged" || to == "failed"
	case "delivered":
		if to == "agent_queued" {
			return true
		}
	}
	if action == "rollback" {
		switch from {
		case "delivered":
			return to == "staged" || to == "failed"
		case "staged":
			return to == "prechecked" || to == "failed"
		case "prechecked":
			return to == "reverting" || to == "failed"
		case "reverting":
			return to == "reverted" || to == "failed" || to == "rollback_failed"
		default:
			return false
		}
	}
	switch from {
	case "delivered":
		return to == "staged" || to == "failed"
	case "staged":
		return to == "prechecked" || to == "failed"
	case "prechecked":
		return to == "activated" || to == "failed"
	case "activated":
		return to == "healthy" || to == "reverting"
	case "reverting":
		return to == "reverted" || to == "rollback_failed"
	default:
		return false
	}
}
