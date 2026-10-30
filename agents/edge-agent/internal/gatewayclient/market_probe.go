package gatewayclient

import (
	"context"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// marketProbeAPIVersion 3: origin targets (scheme, any port, IP or name,
	// separate Host/SNI, custom CA) on top of v2 host targets.
	marketProbeAPIVersion = 3
	// marketBenchmarkAPIVersion: MarketProbeCommand.benchmark downloads.
	marketBenchmarkAPIVersion = 1
	// aggregatedEdgeProbeAPIVersion: GET/HEAD and extra headers on host
	// targets (internal/marketprobe.APIVersion).
	aggregatedEdgeProbeAPIVersion = 1
)

// MarketProbeExecutor runs node-market probes (internal/marketprobe.Executor).
type MarketProbeExecutor interface {
	Validate(*agentv1.MarketProbeCommand) error
	Execute(context.Context, *agentv1.MarketProbeCommand) ([]*agentv1.MarketProbeTargetResult, error)
}

// WithMarketProbeExecutor advertises CAPABILITY_NAME_MARKET_PROBE v3 and runs
// the probe commands the gateway delivers on the authenticated stream.
func WithMarketProbeExecutor(executor MarketProbeExecutor) ClientOption {
	return func(client *Client) error {
		if executor == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.marketProbe = executor
		return nil
	}
}

// negotiateMarketProbe (v3 only): an older gateway may not enable
// it, but enabling it for an Agent that did not advertise it is an error.
func negotiateMarketProbe(gatewayHello *agentv1.GatewayHello, executor MarketProbeExecutor) (bool, error) {
	enabled := false
	for _, capability := range gatewayHello.GetEnabledCapabilities() {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE {
			continue
		}
		if enabled || capability.ApiVersion != marketProbeAPIVersion {
			return false, fmt.Errorf("%w: market probe capability is duplicated or unsupported", ErrInvalidMessage)
		}
		enabled = true
	}
	if enabled && executor == nil {
		return false, fmt.Errorf("%w: gateway enabled market probes that were not advertised", ErrInvalidMessage)
	}
	return enabled, nil
}

// startMarketProbe runs command in the background and delivers its result on
// done (buffered, capacity 1), so heartbeats keep flowing while probes are in
// flight. Only one command runs at a time: a command arriving meanwhile gets an
// immediate SKIPPED/busy result for the caller to send. An invalid command is
// dropped; the controller times it out.
func (client *Client) startMarketProbe(ctx context.Context, command *agentv1.MarketProbeCommand, busy bool,
	done chan<- *agentv1.MarketProbeResult,
) (started bool, immediate *agentv1.MarketProbeResult) {
	if client.marketProbe.Validate(command) != nil {
		return false, nil
	}
	if busy {
		results := make([]*agentv1.MarketProbeTargetResult, len(command.Targets))
		for i, target := range command.Targets {
			results[i] = &agentv1.MarketProbeTargetResult{TaskId: target.GetTaskId(),
				Outcome: agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, ErrorCode: "busy"}
		}
		return false, client.marketProbeResult(command, results, client.now())
	}
	go func() {
		results, err := client.marketProbe.Execute(ctx, command)
		if err != nil {
			results = nil
		}
		select {
		case done <- client.marketProbeResult(command, results, client.now()):
		case <-ctx.Done():
		}
	}()
	return true, nil
}

func (client *Client) marketProbeResult(command *agentv1.MarketProbeCommand, results []*agentv1.MarketProbeTargetResult,
	now time.Time,
) *agentv1.MarketProbeResult {
	namespace := uuid.MustParse(client.config.NodeID)
	return &agentv1.MarketProbeResult{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte("market-probe-result/"+command.Event.EventId)).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("market-probe-result-request/"+command.Event.EventId)).String(),
			OccurredTime: timestamppb.New(now.UTC()),
		},
		NodeId: client.config.NodeID, CommandEventId: command.Event.EventId, Results: results,
	}
}

func sendMarketProbeResult(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, result *agentv1.MarketProbeResult, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_MarketProbeResult{MarketProbeResult: result}})
}
