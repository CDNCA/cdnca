package edgeautopublish

import (
	"fmt"

	"github.com/google/uuid"
)

// Certificate target rejection codes. Each is stored as the
// certificate publication intent's failure_code, suffixed with ".<node id>"
// when one node is at fault, so the intent state and its audit show why a
// certificate never reached the nodes (node-e2e D1: every rejection used to
// be the anonymous, endlessly retried publication_unavailable).
const (
	CertificateTargetPolicyNotAutomatic   = "target_policy_not_automatic"
	CertificateTargetPolicyInvalid        = "target_policy_invalid"
	CertificateTargetSnapshotUnresolved   = "target_snapshot_unresolved"
	CertificateTargetNoNodes              = "target_no_nodes"
	CertificateTargetNodeMissing          = "target_node_missing"
	CertificateTargetNodeInactive         = "target_node_inactive"
	CertificateTargetNodeNotCarried       = "target_node_not_carried"
	CertificateTargetNodeOffline          = "target_node_offline"
	CertificateTargetNodeIdentity         = "target_node_identity_ineligible"
	CertificateTargetNodeCapabilityAbsent = "target_node_capability_missing"
)

// CertificateTargetRejection is why ResolveCertificateTarget refused the
// publication target. It wraps ErrInvalidInput.
type CertificateTargetRejection struct {
	Code   string
	NodeID uuid.UUID
	// Transient rejections (node offline, node identity or target snapshot
	// unreadable right now) can clear by themselves and keep the intent's
	// bounded backoff (MaxAttempts). The others are validation failures a
	// retry cannot fix (policy, carriage, node state, agent capabilities):
	// the intent fails at once with the reason; a later binding change or
	// republish creates a new intent.
	Transient bool
}

func (rejection *CertificateTargetRejection) Error() string {
	if rejection.NodeID == uuid.Nil {
		return fmt.Sprintf("certificate publication target rejected: %s", rejection.Code)
	}
	return fmt.Sprintf("certificate publication target rejected: %s (node %s)", rejection.Code, rejection.NodeID)
}

func (*CertificateTargetRejection) Unwrap() error { return ErrInvalidInput }

// FailureCode is the intent failure_code: the code, plus ".<node id>" when a
// single node is at fault (at most 67 characters, within ^[a-z][a-z0-9._-]{0,127}$).
func (rejection *CertificateTargetRejection) FailureCode() string {
	if rejection.NodeID == uuid.Nil {
		return rejection.Code
	}
	return rejection.Code + "." + rejection.NodeID.String()
}

func rejectCertificateTarget(code string, nodeID uuid.UUID, transient bool) error {
	return &CertificateTargetRejection{Code: code, NodeID: nodeID, Transient: transient}
}
