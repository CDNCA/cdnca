package gatewayclient

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func WithNodeInventoryDiscovery(discover func(context.Context) *agentv1.ReportNodeNetworkInventoryV1Request) ClientOption {
	return func(client *Client) error {
		if discover == nil {
			return fmt.Errorf("%w: inventory discovery required", ErrInvalidConfiguration)
		}
		client.nodeInventory = discover
		return nil
	}
}

// A short, independent RPC cannot hold the Connect send/receive loop. Exact
// retries keep one body and request ID. A later session starts a fresh report.
func (c *Client) runNodeInventory(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, observedPeer string) {
	request := c.nodeInventory(ctx)
	if request == nil {
		return
	}
	useObservedPeer(request, observedPeer)
	request.Request = &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.New(c.now().UTC())}
	for attempt := 0; attempt < 3; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		result, err := gateway.ReportNodeNetworkInventoryV1(callCtx, request, grpc.WaitForReady(false))
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			if result == nil || cacheControlMessageHasUnknown(result.ProtoReflect()) || result.SchemaVersion != 1 || result.NodeId != c.config.NodeID || result.ReceivedTime == nil || result.ReceivedTime.CheckValid() != nil || !inventoryReceiptState(result.Ipv4State) || !inventoryReceiptState(result.Ipv6State) {
				slog.Warn("node network inventory report", "state", "invalid_receipt")
				return
			}
			slog.Info("node network inventory report", "ipv4_state", result.Ipv4State, "ipv6_state", result.Ipv6State)
			return
		}
		code := status.Code(err)
		if code == codes.Unimplemented {
			slog.Warn("node network inventory report", "state", "unsupported")
			return
		}
		if code != codes.Unavailable && code != codes.DeadlineExceeded {
			slog.Warn("node network inventory report", "state", "rejected", "code", code.String())
			return
		}
		if attempt == 2 {
			slog.Warn("node network inventory report", "state", "unavailable")
			return
		}
		timer := time.NewTimer(time.Duration(attempt+1) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// useObservedPeer fills a family the host has no public address for (cloud
// NAT) with the address the Gateway saw (GatewayHello.observed_peer_ip, ADR
// 0013 §4.4). The control plane still requires candidate == peer, so this
// only helps when the session really comes from that address.
func useObservedPeer(request *agentv1.ReportNodeNetworkInventoryV1Request, observed string) {
	address, err := netip.ParseAddr(observed)
	if err != nil || address.Zone() != "" || !address.IsGlobalUnicast() || address.IsPrivate() {
		return
	}
	address = address.Unmap()
	candidate := &agentv1.NodeNetworkCandidateV1{Address: address.String(), InterfaceName: "gateway-observed"}
	if address.Is4() && request.Ipv4 == nil && request.Ipv4Reason == "no_global_address" {
		request.Ipv4, request.Ipv4Reason = candidate, ""
	}
	if address.Is6() && request.Ipv6 == nil && request.Ipv6Reason == "no_global_address" {
		request.Ipv6, request.Ipv6Reason = candidate, ""
	}
}

func inventoryReceiptState(value string) bool {
	switch value {
	case "verified", "address_conflict", "peer_mismatch", "no_default_route", "no_global_address", "ambiguous_route", "unavailable":
		return true
	default:
		return false
	}
}
