package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	// MARKET_PROBE 2: host targets (third-party CDN access names, ADR 0008
	// §6.2); 3: origin targets (origin failover). The gateway relays targets
	// unchanged and enables the version the Agent advertised.
	minMarketProbeAPIVersion = 2
	maxMarketProbeAPIVersion = 3
	// maxPendingMarketProbes bounds commands awaiting the Agent's result per
	// session; control-api sends at most one per node per round.
	maxPendingMarketProbes = 2
)

// Market probe commands are ephemeral request/reply exchanges (see
// libs/edgeconfig/marketprobe): the gateway relays a command to the node's
// live, authenticated session and answers the request with the Agent's result.
// A command the gateway refuses is answered with an empty reply; one still
// pending when the session ends is simply never answered.

type MarketProbeRequest interface {
	Command() *agentv1.MarketProbeCommand
	// Reply answers the request; nil means refused or not executed.
	Reply(*agentv1.MarketProbeResult) error
}

type MarketProbeSubscription interface {
	Requests() <-chan MarketProbeRequest
	Close() error
}

type MarketProbeBus interface {
	SubscribeMarketProbes(ctx context.Context, nodeID string) (MarketProbeSubscription, error)
}

func (g *Gateway) ConfigureMarketProbes(bus MarketProbeBus) error {
	if g == nil || bus == nil || g.marketProbes != nil {
		return fmt.Errorf("market probe bus is invalid or already configured")
	}
	g.marketProbes = bus
	return nil
}

// marketProbeCapabilityFromFeatures returns the advertised MARKET_PROBE
// version (0: not advertised).
func marketProbeCapabilityFromFeatures(features []*agentv1.Capability) (uint32, error) {
	version := uint32(0)
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE {
			continue
		}
		if version != 0 || capability.ApiVersion < minMarketProbeAPIVersion || capability.ApiVersion > maxMarketProbeAPIVersion {
			return 0, fmt.Errorf("market probe capability is duplicated or unsupported")
		}
		version = capability.ApiVersion
	}
	return version, nil
}

// sessionMarketProbes is the market probe state of one Connect session.
type sessionMarketProbes struct {
	subscription MarketProbeSubscription
	pending      map[string]pendingMarketProbe
}

type pendingMarketProbe struct {
	request MarketProbeRequest
	command *agentv1.MarketProbeCommand
}

func (g *Gateway) startSessionMarketProbes(ctx context.Context, nodeID string) (*sessionMarketProbes, error) {
	subscription, err := g.marketProbes.SubscribeMarketProbes(ctx, nodeID)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "could not subscribe to market probe commands")
	}
	return &sessionMarketProbes{subscription: subscription, pending: map[string]pendingMarketProbe{}}, nil
}

func (session *sessionMarketProbes) requests() <-chan MarketProbeRequest {
	if session == nil {
		return nil
	}
	return session.subscription.Requests()
}

// stop closes the subscription; pending requests time out at the sender.
func (session *sessionMarketProbes) stop() {
	if session != nil {
		_ = session.subscription.Close()
	}
}

// applyMarketProbeAuthorization follows a session authorization refresh like L4 live connections do.
func (g *Gateway) applyMarketProbeAuthorization(ctx context.Context, nodeID string, session *sessionMarketProbes,
	isAllowed bool,
) (*sessionMarketProbes, error) {
	if g.marketProbes == nil || (session != nil) == isAllowed {
		return session, nil
	}
	if !isAllowed {
		session.stop()
		return nil, nil
	}
	return g.startSessionMarketProbes(ctx, nodeID)
}

func validateMarketProbeCommand(command *agentv1.MarketProbeCommand, nodeID string, now time.Time) error {
	if command == nil || proto.Size(command) > marketprobe.MaxCarrierBytes || cacheControlMessageHasUnknown(command.ProtoReflect()) ||
		command.NodeId != nodeID || command.Event == nil || !canonicalUUID(command.Event.EventId) ||
		len(command.Targets) == 0 || len(command.Targets) > marketprobe.MaxTargets ||
		command.TimeoutMillis < marketprobe.MinTimeoutMillis || command.TimeoutMillis > marketprobe.MaxTimeoutMillis ||
		command.ExpireTime == nil || command.ExpireTime.CheckValid() != nil || !now.Before(command.ExpireTime.AsTime()) {
		return fmt.Errorf("market probe command is invalid")
	}
	return nil
}

func validateMarketProbeResult(result *agentv1.MarketProbeResult, command *agentv1.MarketProbeCommand, nodeID string) error {
	if result == nil || command == nil || proto.Size(result) > marketprobe.MaxCarrierBytes ||
		cacheControlMessageHasUnknown(result.ProtoReflect()) || result.NodeId != nodeID ||
		result.CommandEventId != command.Event.GetEventId() || result.Event == nil || !canonicalUUID(result.Event.EventId) ||
		len(result.Results) != len(command.Targets) {
		return fmt.Errorf("market probe result is invalid")
	}
	for i, item := range result.Results {
		if item == nil || item.TaskId != command.Targets[i].GetTaskId() ||
			item.Outcome == agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_UNSPECIFIED ||
			item.LatencyMillis > marketprobe.MaxTimeoutMillis || len(item.ErrorCode) > 64 {
			return fmt.Errorf("market probe result is invalid")
		}
	}
	return nil
}

// admit validates a relayed command and records it pending, or refuses it.
func (session *sessionMarketProbes) admit(request MarketProbeRequest, nodeID string, now time.Time) (*agentv1.MarketProbeCommand, bool) {
	command := request.Command()
	if validateMarketProbeCommand(command, nodeID, now) != nil || len(session.pending) >= maxPendingMarketProbes {
		_ = request.Reply(nil)
		return nil, false
	}
	if _, exists := session.pending[command.Event.EventId]; exists {
		_ = request.Reply(nil)
		return nil, false
	}
	command = proto.Clone(command).(*agentv1.MarketProbeCommand)
	session.pending[command.Event.EventId] = pendingMarketProbe{request: request, command: command}
	return command, true
}

// settle answers the pending request a result belongs to. Results for
// commands no longer pending (timed out, session restarted) are ignored.
func (session *sessionMarketProbes) settle(result *agentv1.MarketProbeResult, nodeID string) error {
	pending, exists := session.pending[result.GetCommandEventId()]
	if !exists {
		return nil
	}
	if err := validateMarketProbeResult(result, pending.command, nodeID); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	delete(session.pending, result.CommandEventId)
	_ = pending.request.Reply(proto.Clone(result).(*agentv1.MarketProbeResult))
	return nil
}

// expire drops pending commands past their deadline so a lost result cannot
// hold the per-session budget.
func (session *sessionMarketProbes) expire(now time.Time) {
	if session == nil {
		return
	}
	for id, pending := range session.pending {
		if !now.Before(pending.command.ExpireTime.AsTime()) {
			delete(session.pending, id)
		}
	}
}
