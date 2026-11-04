package gatewayclient

import (
	"context"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// marketRoleAPIVersion: MARKET_ROLE v1, role assignments
// carried by MarketProbeCommand.assigned_role.
const marketRoleAPIVersion = 1

// MarketRoleAssigner applies the node-market role the controller assigns
// (JOIN_MARKET or PROBE_ONLY) and returns the role in effect afterwards and
// why ("assigned", "local_join" or "local_leave"). It may reload the node.
type MarketRoleAssigner interface {
	AssignMarketRole(ctx context.Context, role agentv1.MarketProbeRole) (agentv1.MarketProbeRole, string)
}

// WithMarketRoleAssigner declares MARKET_ROLE v1 (with a market probe
// executor only) and applies the role assignments the gateway relays.
func WithMarketRoleAssigner(assigner MarketRoleAssigner) ClientOption {
	return func(client *Client) error {
		if assigner == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.marketRole = assigner
		return nil
	}
}

// marketRoleAssignment reports whether command is a role assignment this
// client handles: an assignable role, no targets and no benchmark.
func (client *Client) marketRoleAssignment(command *agentv1.MarketProbeCommand) bool {
	role := command.GetAssignedRole()
	return client.marketRole != nil && len(command.GetTargets()) == 0 && command.GetBenchmark() == nil &&
		(role == agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET || role == agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY)
}

// startMarketRole applies an assignment in the background (it may reload
// the node) and delivers the answer on done (buffered, capacity 1). One runs
// at a time; one arriving meanwhile is dropped (the controller asks again).
func (client *Client) startMarketRole(ctx context.Context, command *agentv1.MarketProbeCommand, busy bool,
	done chan<- *agentv1.MarketProbeResult,
) bool {
	if busy || command.GetNodeId() != client.config.NodeID || command.GetEvent().GetEventId() == "" {
		return false
	}
	go func() {
		role, source := client.marketRole.AssignMarketRole(ctx, command.AssignedRole)
		result := client.marketProbeResult(command, nil, client.now())
		result.EffectiveRole, result.RoleSource = role, source
		select {
		case done <- result:
		case <-ctx.Done():
		}
	}()
	return true
}
