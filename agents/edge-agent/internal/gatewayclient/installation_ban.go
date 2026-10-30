package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const installationBanAPIVersion = 1

// InstallationBanResult is what the node enforces after one command, and the
// ServiceTicket it holds (zero times before its first ticket).
type InstallationBanResult struct {
	Applied        bool
	Status         string
	Reason         string
	TicketIssuedAt time.Time
	TicketNotAfter time.Time
}

// InstallationBanApplier verifies, keeps and enforces the delivered documents
// (installationban.Runtime through the daemon).
type InstallationBanApplier interface {
	ApplyInstallationBan(ctx context.Context, notice, ticket []byte) InstallationBanResult
}

// InstallationFrozenReason is in the summary of a deployment or the log of an
// upgrade the node refused while frozen (an expired ticket
// keeps existing sites serving but takes no new sites, scaling or upgrades).
const InstallationFrozenReason = "installation_frozen"

// installationFrozen reports whether the applier says the node is frozen; an
// applier without Frozen never freezes.
func (client *Client) installationFrozen() bool {
	frozen, ok := client.installationBan.(interface{ Frozen() bool })
	return ok && frozen.Frozen()
}

// WithInstallationBan advertises CAPABILITY_NAME_INSTALLATION_BAN_TICKET v1.
func WithInstallationBan(applier InstallationBanApplier) ClientOption {
	return func(client *Client) error {
		if applier == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.installationBan = applier
		return nil
	}
}

func negotiateInstallationBanV1(gatewayHello *agentv1.GatewayHello, applier InstallationBanApplier) (bool, error) {
	enabled := false
	for _, capability := range gatewayHello.GetEnabledCapabilities() {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_INSTALLATION_BAN_TICKET {
			continue
		}
		if enabled || capability.ApiVersion != installationBanAPIVersion {
			return false, fmt.Errorf("%w: installation ban capability is duplicated or unsupported", ErrInvalidMessage)
		}
		enabled = true
	}
	if enabled && applier == nil {
		return false, fmt.Errorf("%w: gateway enabled installation ban that was not advertised", ErrInvalidMessage)
	}
	return enabled, nil
}

// installationBanReceipt checks the carrier (node, digests), applies the
// documents and returns the receipt; signatures and revisions are the runtime's.
func (client *Client) installationBanReceipt(ctx context.Context, command *agentv1.InstallationBanCommand,
	now time.Time,
) (*agentv1.InstallationBanReceipt, error) {
	if command == nil || command.NodeId != client.config.NodeID || command.Revision == 0 || command.Event == nil ||
		!canonicalUUID(command.Event.EventId) || !boundInstallationBanDocument(command.NoticeJson, command.NoticeSha256) ||
		!boundInstallationBanDocument(command.TicketJson, command.TicketSha256) {
		return nil, fmt.Errorf("%w: installation ban command carrier is invalid", ErrInvalidMessage)
	}
	var notice, ticket []byte
	if len(command.NoticeJson) > 0 {
		notice = append([]byte(nil), command.NoticeJson...)
	}
	if len(command.TicketJson) > 0 {
		ticket = append([]byte(nil), command.TicketJson...)
	}
	result := client.installationBan.ApplyInstallationBan(ctx, notice, ticket)
	namespace := uuid.MustParse(client.config.NodeID)
	receipt := &agentv1.InstallationBanReceipt{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte("installation-ban-receipt/"+command.Event.EventId+"/"+result.Status+"/"+result.Reason)).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("installation-ban-receipt-request/"+command.Event.EventId)).String(),
			OccurredTime: timestamppb.New(now.UTC()),
		},
		NodeId: client.config.NodeID, CommandEventId: command.Event.EventId, Revision: command.Revision,
		Applied: result.Applied, Status: result.Status, Reason: result.Reason,
	}
	if !result.TicketIssuedAt.IsZero() && result.TicketNotAfter.After(result.TicketIssuedAt) {
		receipt.TicketIssuedTime = timestamppb.New(result.TicketIssuedAt.UTC())
		receipt.TicketNotAfterTime = timestamppb.New(result.TicketNotAfter.UTC())
	}
	return receipt, nil
}

func boundInstallationBanDocument(document, digest []byte) bool {
	if len(document) == 0 {
		return len(digest) == 0
	}
	sum := sha256.Sum256(document)
	return bytes.Equal(sum[:], digest)
}

func sendInstallationBanReceipt(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, receipt *agentv1.InstallationBanReceipt, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_InstallationBanReceipt{InstallationBanReceipt: receipt}})
}
