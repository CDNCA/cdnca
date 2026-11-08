package challengepublication

import (
	"errors"
	"slices"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// ChallengePoWAPIVersion is CAPABILITY_NAME_CHALLENGE_POW v1
//: the node's engine accepts rule field pow_difficulty.
// A policy without it is byte for byte what older agents accept, so only a
// policy with an explicit difficulty requires the capability.
const ChallengePoWAPIVersion uint32 = 1

// RequiredCapabilities are the capabilities a challenge secret rollout of
// one policy requires (publication and redelivery alike).
func RequiredCapabilities(explicitPoW bool) []*agentv1.Capability {
	result := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
	}
	if explicitPoW {
		result = append(result, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_CHALLENGE_POW, ApiVersion: ChallengePoWAPIVersion,
		})
	}
	return result
}

// SplitCapabilityRefusal splits nodeIDs by the result of
// edgepublish.ValidateFeatureCapabilityTargets: the nodes its
// TargetCapabilityError names lack the capability; the others take the
// rollout (a node without a readable session is left to the command's
// required_capabilities, which the agent checks itself). Any other error is
// returned as is.
func SplitCapabilityRefusal(nodeIDs []uuid.UUID, refusal error) (capable, unsupported []uuid.UUID, err error) {
	if refusal == nil {
		return slices.Clone(nodeIDs), nil, nil
	}
	var target *edgepublish.TargetCapabilityError
	if !errors.As(refusal, &target) {
		return nil, nil, refusal
	}
	refused := append([]uuid.UUID{target.NodeID}, target.OtherNodeIDs...)
	for _, nodeID := range nodeIDs {
		if slices.Contains(refused, nodeID) {
			unsupported = append(unsupported, nodeID)
		} else {
			capable = append(capable, nodeID)
		}
	}
	return capable, unsupported, nil
}
