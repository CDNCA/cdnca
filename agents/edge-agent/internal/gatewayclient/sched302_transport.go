package gatewayclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// Sched302Applier installs a verified HTTP 302 scheduling table
// (sched302.Table) where the node's OpenResty reads it. Apply must ignore a
// revision not newer than the installed one.
type Sched302Applier interface {
	Apply(table sched302.Table, encoded []byte) error
}

// WithSched302Runtime advertises CAPABILITY_NAME_SCHED302 v1 and installs
// the tables the gateway delivers.
func WithSched302Runtime(runtime Sched302Applier) ClientOption {
	return func(client *Client) error {
		if runtime == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.sched302 = runtime
		return nil
	}
}

func negotiateSched302V1(gatewayHello *agentv1.GatewayHello, runtime Sched302Applier) (bool, error) {
	enabled := false
	for _, capability := range gatewayHello.GetEnabledCapabilities() {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_SCHED302 {
			continue
		}
		if enabled || capability.ApiVersion != sched302.APIVersion {
			return false, fmt.Errorf("%w: schedule302 capability is duplicated or unsupported", ErrInvalidMessage)
		}
		enabled = true
	}
	if enabled && runtime == nil {
		return false, fmt.Errorf("%w: gateway enabled schedule302 that was not advertised", ErrInvalidMessage)
	}
	return enabled, nil
}

// applySched302Table verifies a delivered table (this node, its digest, the
// control plane's signature with the artifact trust) and installs it.
func applySched302Table(table *agentv1.Sched302Table, nodeID string, trust *TrustStore, runtime Sched302Applier) error {
	if table == nil || table.Schema != agentv1.Sched302Schema_SCHED302_SCHEMA_V1 || table.NodeId != nodeID ||
		table.Revision == 0 || len(table.TableJson) > sched302.MaxTableBytes {
		return fmt.Errorf("%w: schedule302 table carrier is invalid", ErrInvalidMessage)
	}
	digest := sha256.Sum256(table.TableJson)
	if !bytes.Equal(digest[:], table.TableSha256) {
		return fmt.Errorf("%w: schedule302 table digest is invalid", ErrInvalidMessage)
	}
	key, ok := trust.key(table.SigningKeyId)
	ed25519Key, typed := key.(ed25519.PublicKey)
	if !ok || !typed || len(ed25519Key) != ed25519.PublicKeySize ||
		table.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
		len(table.Signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519Key, table.TableJson, table.Signature) {
		return fmt.Errorf("%w: schedule302 table signature is invalid", ErrInvalidMessage)
	}
	decoded, err := sched302.Decode(table.TableJson)
	if err != nil || decoded.NodeID != nodeID || decoded.Revision != table.Revision {
		return fmt.Errorf("%w: schedule302 table body does not match its carrier", ErrInvalidMessage)
	}
	return runtime.Apply(decoded, table.TableJson)
}
