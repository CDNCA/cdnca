package gatewayclient

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sitedrop"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const siteDropAPIVersion = 1

// SiteDropRejection is one listed site (or port) the node did not drop.
type SiteDropRejection struct {
	SiteID string
	Port   uint16
	Reason string // sitedrop.Reject*
}

// SiteDropResult is what one site drop list did on the node.
type SiteDropResult struct {
	Applied     bool
	Mode        string // xdp | nftables
	Sites       uint32
	Ports       uint32
	ServerNames uint32
	Rejected    []SiteDropRejection
	ErrorCode   string // sitedrop.Error*; "" when applied
}

// SiteDropApplier verifies and enforces one signed site drop list
// (esc-node; cmd/edge-agent siteDropRuntime).
type SiteDropApplier interface {
	ApplySiteDrop(encoded []byte) SiteDropResult
}

// WithSiteDrop advertises CAPABILITY_NAME_SITE_DROP v1.
func WithSiteDrop(applier SiteDropApplier) ClientOption {
	return func(client *Client) error {
		if applier == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.siteDrop = applier
		return nil
	}
}

func negotiateSiteDropV1(gatewayHello *agentv1.GatewayHello, applier SiteDropApplier) (bool, error) {
	enabled := false
	for _, capability := range gatewayHello.GetEnabledCapabilities() {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP {
			continue
		}
		if enabled || capability.ApiVersion != siteDropAPIVersion {
			return false, fmt.Errorf("%w: site drop capability is duplicated or unsupported", ErrInvalidMessage)
		}
		enabled = true
	}
	if enabled && applier == nil {
		return false, fmt.Errorf("%w: gateway enabled site drop that was not advertised", ErrInvalidMessage)
	}
	return enabled, nil
}

// siteDropReceipt checks the carrier (node, revision, digest), applies the
// list and returns the receipt; signature and revision order are the
// runtime's.
func (client *Client) siteDropReceipt(command *agentv1.SiteDropCommand, now time.Time) (*agentv1.SiteDropReceipt, error) {
	if command == nil || command.NodeId != client.config.NodeID || command.Revision == 0 || command.Event == nil ||
		!canonicalUUID(command.Event.EventId) || len(command.ListJson) == 0 {
		return nil, fmt.Errorf("%w: site drop command carrier is invalid", ErrInvalidMessage)
	}
	digest := sha256.Sum256(command.ListJson)
	if !bytes.Equal(digest[:], command.ListSha256) {
		return nil, fmt.Errorf("%w: site drop command digest mismatch", ErrInvalidMessage)
	}
	var result SiteDropResult
	if node, revision, err := sitedrop.Route(command.ListJson); err != nil || node != command.NodeId || revision != command.Revision {
		result = SiteDropResult{ErrorCode: sitedrop.ErrorInvalid}
	} else {
		result = client.siteDrop.ApplySiteDrop(append([]byte(nil), command.ListJson...))
	}
	if result.Applied {
		result.ErrorCode = ""
	} else if result.ErrorCode == "" {
		result.ErrorCode = sitedrop.ErrorRuntime
	}
	receipt := &agentv1.SiteDropReceipt{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewSHA1(uuid.MustParse(client.config.NodeID),
				[]byte(fmt.Sprintf("site-drop-receipt/%s/%t/%s", command.Event.EventId, result.Applied, result.ErrorCode))).String(),
			RequestId:    uuid.NewSHA1(uuid.MustParse(client.config.NodeID), []byte("site-drop-receipt-request/"+command.Event.EventId)).String(),
			OccurredTime: timestamppb.New(now.UTC()),
		},
		NodeId: client.config.NodeID, CommandEventId: command.Event.EventId, Revision: command.Revision,
		ListSha256: digest[:], Applied: result.Applied, Mode: result.Mode, Sites: result.Sites, Ports: result.Ports,
		ServerNames: result.ServerNames, ErrorCode: result.ErrorCode,
	}
	for _, rejected := range result.Rejected {
		receipt.Rejected = append(receipt.Rejected, &agentv1.SiteDropRejection{SiteId: rejected.SiteID,
			Port: uint32(rejected.Port), Reason: rejected.Reason})
	}
	return receipt, nil
}

func sendSiteDropReceipt(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, receipt *agentv1.SiteDropReceipt, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_SiteDropReceipt{SiteDropReceipt: receipt}})
}
