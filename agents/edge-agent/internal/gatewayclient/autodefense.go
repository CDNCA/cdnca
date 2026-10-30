package gatewayclient

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AutoDefenseResult is what one snapshot part did on the node.
type AutoDefenseResult struct {
	Applied                        bool
	Sites, Signatures, Mitigations uint32
	ErrorCode                      string // autodefense.Error*; "" when applied
}

// AutoDefenseRuntime verifies and applies the automatic defense snapshot parts the gateway delivers
// (CAPABILITY_NAME_AUTO_DEFENSE v1, AD-07; cmd/edge-agent autoDefenseReceiver) and produces the optional
// upstream summaries. Reports may return nil; the channel must be buffered and fed without blocking (a report
// that finds no session is dropped: summaries are display only).
type AutoDefenseRuntime interface {
	ApplyAutoDefense(encoded []byte) AutoDefenseResult
	Reports() <-chan []byte
}

// WithAutoDefense advertises CAPABILITY_NAME_AUTO_DEFENSE v1 and hands the delivered parts to runtime.
func WithAutoDefense(runtime AutoDefenseRuntime) ClientOption {
	return func(client *Client) error {
		if runtime == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.autoDefense = runtime
		return nil
	}
}

func negotiateAutoDefenseV1(gatewayHello *agentv1.GatewayHello, runtime AutoDefenseRuntime) (bool, error) {
	enabled := false
	for _, capability := range gatewayHello.GetEnabledCapabilities() {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE {
			continue
		}
		if enabled || capability.ApiVersion != autodefense.APIVersion {
			return false, fmt.Errorf("%w: auto defense capability is duplicated or unsupported", ErrInvalidMessage)
		}
		enabled = true
	}
	if enabled && runtime == nil {
		return false, fmt.Errorf("%w: gateway enabled auto defense that was not advertised", ErrInvalidMessage)
	}
	return enabled, nil
}

// autoDefenseReceipt applies a delivered part and returns its receipt. The carrier is checked against this
// node and its own digest; signature, revision order and assembly are the runtime's.
func (client *Client) autoDefenseReceipt(command *agentv1.AutoDefenseCommand, now time.Time) (*agentv1.AutoDefenseReceipt, error) {
	if command == nil || command.NodeId != client.config.NodeID || command.Revision == 0 || command.Event == nil ||
		!canonicalUUID(command.Event.EventId) || len(command.SnapshotJson) > autodefense.MaxPartBytes {
		return nil, fmt.Errorf("%w: auto defense command carrier is invalid", ErrInvalidMessage)
	}
	digest := sha256.Sum256(command.SnapshotJson)
	if !bytes.Equal(digest[:], command.SnapshotSha256) {
		return nil, fmt.Errorf("%w: auto defense command digest mismatch", ErrInvalidMessage)
	}
	result := AutoDefenseResult{ErrorCode: autodefense.ErrorNotSupported}
	if client.autoDefense != nil {
		result = client.autoDefense.ApplyAutoDefense(append([]byte(nil), command.SnapshotJson...))
	}
	if result.Applied {
		result.ErrorCode = ""
	} else {
		if result.ErrorCode == "" {
			result.ErrorCode = autodefense.ErrorRuntime
		}
		result.Sites, result.Signatures, result.Mitigations = 0, 0, 0
	}
	namespace := uuid.MustParse(client.config.NodeID)
	return &agentv1.AutoDefenseReceipt{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewSHA1(namespace, []byte(fmt.Sprintf("auto-defense-receipt/%s/%t/%s",
				command.Event.EventId, result.Applied, result.ErrorCode))).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("auto-defense-receipt-request/"+command.Event.EventId)).String(),
			OccurredTime: timestamppb.New(now.UTC()),
		},
		NodeId: client.config.NodeID, CommandEventId: command.Event.EventId, Revision: command.Revision,
		SnapshotSha256: digest[:], Applied: result.Applied, Sites: result.Sites, Signatures: result.Signatures,
		Mitigations: result.Mitigations, ErrorCode: result.ErrorCode,
	}, nil
}

// autoDefenseReports is the runtime's report channel while the session negotiated AUTO_DEFENSE, else nil.
func (client *Client) autoDefenseReports(enabled bool) <-chan []byte {
	if !enabled || client.autoDefense == nil {
		return nil
	}
	return client.autoDefense.Reports()
}

func sendAutoDefenseReceipt(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, receipt *agentv1.AutoDefenseReceipt, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_AutoDefenseReceipt{AutoDefenseReceipt: receipt}})
}

func sendAutoDefenseReport(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, report []byte, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_AutoDefenseReport{AutoDefenseReport: &agentv1.AutoDefenseReport{ReportJson: report}}})
}
