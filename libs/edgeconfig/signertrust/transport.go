// Package signertrust is the transport contract of node signer trust bundles
// (CAPABILITY_NAME_EDGE_SIGNER_TRUST v1) shared by control-api, agent-gateway
// and edge-agent. The bundle and receipt bodies belong to
// libs/entitlement/edgesignertrust; the gateway only binds the carrier to
// them (Route) and never verifies signatures.
package signertrust

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// JetStream names: agent-gateway owns the streams, control-api publishes
// bundles and consumes receipts. Subjects end with the node ID. Commands keep
// only the newest bundle per node: a bundle carries the whole document, so an
// undelivered older one carries nothing a newer one does not.
const (
	CommandStream        = "EDGE_SIGNER_TRUST_COMMANDS"
	StatusStream         = "EDGE_SIGNER_TRUST_STATUS"
	CommandSubjectPrefix = "cdnca.agent.signer-trust.commands"
	StatusSubjectPrefix  = "cdnca.agent.signer-trust.status"
	// GatewayConsumerPrefix names the gateway's durable per-node bundle
	// consumer; ReceiptConsumer is control-api's.
	GatewayConsumerPrefix = "signer_trust"
	ReceiptConsumer       = "control_api_signer_trust_receipts"
	// APIVersion is the CAPABILITY_NAME_EDGE_SIGNER_TRUST version.
	APIVersion = 1
	// MaxBundleBytes and MaxReceiptBytes equal edgesignertrust.MaxBundleBytes
	// and its receipt limit (checked by the edge-agent tests).
	MaxBundleBytes  = 256<<10 + 16<<10
	MaxReceiptBytes = 4096
	// MaxCarrierBytes bounds one EdgeSignerTrustBundle or
	// EdgeSignerTrustReceipt protobuf message.
	MaxCarrierBytes = MaxBundleBytes + 4<<10
)

var ErrInvalid = errors.New("edge signer trust carrier binding is invalid")

// Binding is what the carrier repeats from a bundle or receipt body.
type Binding struct {
	NodeID       string
	Revision     uint64
	BundleSHA256 string
}

// RouteBundle reads node_id and revision from bundle wire bytes.
func RouteBundle(encoded []byte) (Binding, error) {
	var body struct {
		Schema   string `json:"schema"`
		NodeID   string `json:"node_id"`
		Revision uint64 `json:"revision"`
	}
	if len(encoded) == 0 || len(encoded) > MaxBundleBytes || decodeOne(encoded, &body) != nil ||
		body.Schema != "cdnca.edge-signer-trust-bundle/v1" || body.NodeID == "" || body.Revision == 0 {
		return Binding{}, ErrInvalid
	}
	return Binding{NodeID: body.NodeID, Revision: body.Revision}, nil
}

// RouteReceipt reads node_id, the enforced revision and bundle_sha256 from
// receipt wire bytes.
func RouteReceipt(encoded []byte) (Binding, error) {
	var body struct {
		Schema       string `json:"schema"`
		NodeID       string `json:"node_id"`
		BundleSHA256 string `json:"bundle_sha256"`
		Revision     uint64 `json:"revision"`
	}
	if len(encoded) == 0 || len(encoded) > MaxReceiptBytes || decodeOne(encoded, &body) != nil ||
		body.Schema != "cdnca.edge-signer-trust-receipt/v1" || body.NodeID == "" || len(body.BundleSHA256) != 64 {
		return Binding{}, ErrInvalid
	}
	return Binding{NodeID: body.NodeID, Revision: body.Revision, BundleSHA256: body.BundleSHA256}, nil
}

func decodeOne(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
