package gatewayclient

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SecurityBanResult is what a ban list snapshot did on the node.
type SecurityBanResult struct {
	Applied   bool
	Bans      uint32
	Releases  uint32
	ErrorCode string // securityban.Error*; "" when applied
}

// SecurityBanApplier verifies and applies one signed ban list snapshot
// (cmd/edge-agent securityBanRuntime).
type SecurityBanApplier interface {
	ApplySecurityBans(encoded []byte) SecurityBanResult
}

// WithSecurityBans applies the ban lists the gateway delivers (no capability
// of its own: the gateway sends them to a WAF v2 Agent).
func WithSecurityBans(applier SecurityBanApplier) ClientOption {
	return func(client *Client) error {
		if applier == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.securityBans = applier
		return nil
	}
}

// securityBanStatus applies a delivered snapshot and returns its status.
func (client *Client) securityBanStatus(command *agentv1.SecurityBanCommand, now time.Time) (*agentv1.SecurityBanStatus, error) {
	if command == nil || command.NodeId != client.config.NodeID || command.Revision == 0 || command.Event == nil ||
		!canonicalUUID(command.Event.EventId) {
		return nil, fmt.Errorf("%w: security ban command carrier is invalid", ErrInvalidMessage)
	}
	digest := sha256.Sum256(command.ListJson)
	if !bytes.Equal(digest[:], command.ListSha256) {
		return nil, fmt.Errorf("%w: security ban command digest mismatch", ErrInvalidMessage)
	}
	result := SecurityBanResult{ErrorCode: securityban.ErrorNotSupported}
	if client.securityBans != nil {
		result = client.securityBans.ApplySecurityBans(append([]byte(nil), command.ListJson...))
	}
	if result.Applied {
		result.ErrorCode = ""
	} else if result.ErrorCode == "" {
		result.ErrorCode = securityban.ErrorRuntime
	}
	namespace := uuid.MustParse(client.config.NodeID)
	return &agentv1.SecurityBanStatus{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte(fmt.Sprintf("security-ban-status/%s/%t/%s", command.Event.EventId, result.Applied, result.ErrorCode))).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("security-ban-status-request/"+command.Event.EventId)).String(),
			OccurredTime: timestamppb.New(now.UTC()),
		},
		NodeId: client.config.NodeID, CommandEventId: command.Event.EventId, Revision: command.Revision,
		ListSha256: digest[:], Applied: result.Applied, Bans: result.Bans, Releases: result.Releases, ErrorCode: result.ErrorCode,
	}, nil
}

func sendSecurityBanStatus(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, report *agentv1.SecurityBanStatus, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_SecurityBanStatus{SecurityBanStatus: report}})
}
