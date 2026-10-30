package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// LoadNodePublicationCapabilities reads the capabilities of the enrollment that
// owns the active artifact key, not the latest short-lived enrollment attempt.
// Callers must still authorize the publication scope and target selection.
func LoadNodePublicationCapabilities(
	ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID, now time.Time,
) (map[uuid.UUID]*agentv1.AgentCapabilities, error) {
	if ctx == nil || tx == nil || now.IsZero() || len(nodeIDs) == 0 || len(nodeIDs) > 10000 {
		return nil, ErrInvalidInput
	}
	ordered := slices.Clone(nodeIDs)
	slices.SortFunc(ordered, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
	for index, nodeID := range ordered {
		if nodeID == uuid.Nil || (index > 0 && nodeID == ordered[index-1]) {
			return nil, ErrInvalidInput
		}
	}
	// Certificate/CA revocation locks the certificate/epoch before identity
	// state. Keep that order, and hold these facts until publication commits.
	// Renewal may already hold a certificate while waiting for a node locked by
	// the publisher. NOWAIT fails this attempt closed instead of forming a cycle.
	rows, err := tx.Query(ctx, `SELECT node.id,certificate.leaf_certificate_pem,certificate.leaf_der_sha256,
		epoch.ca_certificate_pem,epoch.ca_certificate_sha256
		FROM unnest($1::uuid[]) AS target(node_id)
		JOIN nodes node ON node.id=target.node_id AND node.admin_state='active'
		JOIN node_certificates certificate ON certificate.node_id=node.id AND certificate.owner_scope_id=node.scope_id
		  AND certificate.status='active' AND certificate.rotation_status='current'
		  AND certificate.not_before<=$2 AND certificate.not_after>$2
		JOIN control_installation_entitlement installation
		  ON installation.singleton AND installation.installation_id=certificate.installation_id
		JOIN node_ca_key_epochs epoch ON epoch.id=certificate.ca_epoch_id
		  AND epoch.installation_id=installation.installation_id AND epoch.status IN ('active','retired')
		  AND epoch.not_before<=$2 AND epoch.not_after>$2
		ORDER BY node.id FOR SHARE OF node,certificate,epoch NOWAIT`, ordered, now)
	if err != nil {
		return nil, fmt.Errorf("%w: read publication identity", ErrPersistence)
	}
	seen := 0
	for rows.Next() {
		var nodeID uuid.UUID
		var leafPEM, leafHash, caPEM, caHash []byte
		if err := rows.Scan(&nodeID, &leafPEM, &leafHash, &caPEM, &caHash); err != nil {
			rows.Close()
			return nil, ErrPersistence
		}
		leafBlock, leafRest := pem.Decode(leafPEM)
		caBlock, caRest := pem.Decode(caPEM)
		if seen >= len(ordered) || nodeID != ordered[seen] || leafBlock == nil || caBlock == nil ||
			leafBlock.Type != "CERTIFICATE" || caBlock.Type != "CERTIFICATE" ||
			len(bytes.TrimSpace(leafRest)) != 0 || len(bytes.TrimSpace(caRest)) != 0 {
			rows.Close()
			return nil, ErrTargetIneligible
		}
		actualLeafHash, actualCAHash := sha256.Sum256(leafBlock.Bytes), sha256.Sum256(caBlock.Bytes)
		leaf, leafErr := x509.ParseCertificate(leafBlock.Bytes)
		ca, caErr := x509.ParseCertificate(caBlock.Bytes)
		if leafErr != nil || caErr != nil || !bytes.Equal(actualLeafHash[:], leafHash) ||
			!bytes.Equal(actualCAHash[:], caHash) || leaf.CheckSignatureFrom(ca) != nil ||
			now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
			now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) ||
			len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://cdn-platform/node/"+nodeID.String() {
			rows.Close()
			return nil, ErrTargetIneligible
		}
		seen++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, ErrPersistence
	}
	if seen != len(ordered) {
		return nil, ErrTargetIneligible
	}
	// Read scheduled revocations after locking certificates: a revoker that
	// finished during the first query must not be missed under READ COMMITTED.
	rows, err = tx.Query(ctx, `SELECT state.node_id,auth.capabilities_snapshot,auth.capabilities_sha256,
		artifact.id,artifact.public_key,artifact.public_key_sha256
		FROM unnest($1::uuid[]) AS target(node_id)
		JOIN node_identity_state state ON state.node_id=target.node_id
		JOIN node_artifact_encryption_keys artifact ON artifact.id=state.active_artifact_key_id
		  AND artifact.node_id=state.node_id AND artifact.status='active'
		  AND artifact.activated_at<=$2 AND artifact.deactivated_at IS NULL
		JOIN node_identity_authorizations auth ON auth.id=artifact.authorization_id
		  AND auth.node_id=state.node_id AND auth.status='issued'
		  AND auth.artifact_key_id=artifact.id AND auth.artifact_public_key=artifact.public_key
		  AND auth.completed_at IS NOT NULL AND auth.completed_at<=$2
		  AND auth.authorized_at<=auth.completed_at AND auth.completed_at<auth.expires_at
		JOIN node_certificates initial ON initial.id=auth.issued_certificate_id
		  AND initial.node_id=state.node_id AND initial.enrollment_authorization_id=auth.id
		JOIN nodes node ON node.id=state.node_id AND node.scope_id=initial.owner_scope_id
		JOIN control_installation_entitlement installation
		  ON installation.singleton AND installation.installation_id=initial.installation_id
		JOIN node_certificates current ON current.node_id=state.node_id
		  AND current.installation_id=installation.installation_id AND current.status='active'
		  AND current.rotation_status='current' AND current.issued_at>=initial.issued_at
		  AND (current.enrollment_authorization_id=auth.id OR current.issuance_kind='renewal')
		WHERE NOT EXISTS(SELECT 1 FROM node_certificate_revocations revocation
		  WHERE revocation.certificate_id=current.id AND revocation.node_id=state.node_id
		    AND revocation.binding_status='bound' AND revocation.effective_at<=$2)
		  AND NOT EXISTS(SELECT 1 FROM node_identity_authorizations newer
		    WHERE newer.node_id=state.node_id AND newer.status='issued' AND newer.completed_at>auth.completed_at)
		ORDER BY state.node_id FOR SHARE OF artifact,state`, ordered, now)
	if err != nil {
		return nil, fmt.Errorf("%w: read issued capability binding", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]*agentv1.AgentCapabilities, len(ordered))
	for rows.Next() {
		var nodeID uuid.UUID
		var keyID string
		var snapshot, digest, publicKey, publicHash []byte
		if err := rows.Scan(&nodeID, &snapshot, &digest, &keyID, &publicKey, &publicHash); err != nil {
			return nil, ErrPersistence
		}
		actualPublicHash := sha256.Sum256(publicKey)
		if len(result) >= len(ordered) || nodeID != ordered[len(result)] || len(publicKey) != 32 ||
			!bytes.Equal(actualPublicHash[:], publicHash) || keyID != "x25519:"+hex.EncodeToString(actualPublicHash[:]) {
			return nil, ErrTargetIneligible
		}
		capabilities, err := decodeNodePublicationCapabilities(snapshot, digest)
		if err != nil {
			return nil, err
		}
		result[nodeID] = capabilities
	}
	if err := rows.Err(); err != nil {
		return nil, ErrPersistence
	}
	if len(result) != len(ordered) {
		return nil, ErrTargetIneligible
	}
	return result, nil
}

func decodeNodePublicationCapabilities(snapshot, digest []byte) (*agentv1.AgentCapabilities, error) {
	actualDigest := sha256.Sum256(snapshot)
	if len(snapshot) == 0 || len(snapshot) > 64<<10 || !bytes.Equal(actualDigest[:], digest) {
		return nil, ErrTargetIneligible
	}
	capabilities := new(agentv1.AgentCapabilities)
	if err := proto.Unmarshal(snapshot, capabilities); err != nil ||
		len(capabilities.ProtoReflect().GetUnknown()) != 0 || len(capabilities.Features) == 0 || len(capabilities.Features) > 64 {
		return nil, ErrTargetIneligible
	}
	for _, text := range []struct {
		value    string
		limit    int
		optional bool
	}{
		{capabilities.AgentVersion, 128, false}, {capabilities.BuildId, 128, false},
		{capabilities.OperatingSystem, 64, false}, {capabilities.Architecture, 64, false},
		{capabilities.OpenrestyVersion, 128, true},
	} {
		if (!text.optional && text.value == "") || len(text.value) > text.limit ||
			strings.TrimSpace(text.value) != text.value || !utf8.ValidString(text.value) {
			return nil, ErrTargetIneligible
		}
	}
	for index, feature := range capabilities.Features {
		if feature == nil || feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED ||
			feature.ApiVersion == 0 || len(feature.ProtoReflect().GetUnknown()) != 0 ||
			(index > 0 && feature.Name <= capabilities.Features[index-1].Name) {
			return nil, ErrTargetIneligible
		}
		if _, known := agentv1.CapabilityName_name[int32(feature.Name)]; !known {
			return nil, ErrTargetIneligible
		}
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(capabilities)
	if err != nil || !bytes.Equal(canonical, snapshot) {
		return nil, ErrTargetIneligible
	}
	return capabilities, nil
}
