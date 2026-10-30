package gatewayclient

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const signerTrustAPIVersion = 1

// SignerTrustApplier verifies, persists and applies one node signer trust
// bundle and returns the receipt (SignerTrustRuntime).
type SignerTrustApplier interface {
	Apply(encoded []byte) edgesignertrust.Receipt
}

// WithSignerTrustRuntime advertises CAPABILITY_NAME_EDGE_SIGNER_TRUST v1 and
// applies the bundles the gateway delivers.
func WithSignerTrustRuntime(runtime SignerTrustApplier) ClientOption {
	return func(client *Client) error {
		if runtime == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.signerTrust = runtime
		return nil
	}
}

// negotiateSignerTrustV1 enables signer trust when both sides advertise v1.
// A gateway without the bus simply does not enable it; enabling it for an
// Agent that did not ask is a protocol error.
func negotiateSignerTrustV1(gatewayHello *agentv1.GatewayHello, runtime SignerTrustApplier) (bool, error) {
	enabled := false
	for _, capability := range gatewayHello.GetEnabledCapabilities() {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST {
			continue
		}
		if enabled || capability.ApiVersion != signerTrustAPIVersion {
			return false, fmt.Errorf("%w: edge signer trust capability is duplicated or unsupported", ErrInvalidMessage)
		}
		enabled = true
	}
	if enabled && runtime == nil {
		return false, fmt.Errorf("%w: gateway enabled edge signer trust that was not advertised", ErrInvalidMessage)
	}
	return enabled, nil
}

// signerTrustReceipt applies a delivered bundle and returns the receipt to
// send. The carrier is checked against this node and its own digest; the
// signature, revision order and document are the runtime's.
func (client *Client) signerTrustReceipt(bundle *agentv1.EdgeSignerTrustBundle, now time.Time) (*agentv1.EdgeSignerTrustReceipt, error) {
	if bundle == nil || bundle.Schema != agentv1.EdgeSignerTrustSchema_EDGE_SIGNER_TRUST_SCHEMA_V1 ||
		bundle.NodeId != client.config.NodeID || bundle.Revision == 0 || bundle.Event == nil || !canonicalUUID(bundle.Event.EventId) {
		return nil, fmt.Errorf("%w: edge signer trust bundle carrier is invalid", ErrInvalidMessage)
	}
	digest := sha256.Sum256(bundle.BundleJson)
	if !bytes.Equal(digest[:], bundle.BundleSha256) {
		return nil, fmt.Errorf("%w: edge signer trust bundle digest mismatch", ErrInvalidMessage)
	}
	result := client.signerTrust.Apply(append([]byte(nil), bundle.BundleJson...))
	body, err := edgesignertrust.EncodeReceipt(result)
	if err != nil {
		return nil, err
	}
	namespace := uuid.MustParse(client.config.NodeID)
	bodyDigest := sha256.Sum256(body)
	return &agentv1.EdgeSignerTrustReceipt{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, append([]byte("edge-signer-trust-receipt/"+bundle.Event.EventId+"/"), bodyDigest[:]...)).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("edge-signer-trust-receipt-request/"+bundle.Event.EventId)).String(),
			OccurredTime: timestamppb.New(now.UTC()),
		},
		Schema: agentv1.EdgeSignerTrustSchema_EDGE_SIGNER_TRUST_SCHEMA_V1, NodeId: client.config.NodeID,
		BundleEventId: bundle.Event.EventId, Revision: bundle.Revision, BundleSha256: digest[:], ReceiptJson: body,
	}, nil
}

func sendSignerTrustReceipt(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, receipt *agentv1.EdgeSignerTrustReceipt, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_EdgeSignerTrustReceipt{EdgeSignerTrustReceipt: receipt}})
}
