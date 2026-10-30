package nodeidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

func normalizeSessionFacts(request GetAuthorizationRequest) (*controlv1.GatewaySessionFactsV1, []byte, []byte, error) {
	facts := request.SessionFacts
	if facts == nil || facts.SchemaVersion != 1 || facts.NodeId != request.NodeID.String() || facts.SessionEpoch == 0 || facts.SessionEpoch > math.MaxInt64 ||
		len(facts.ProtoReflect().GetUnknown()) != 0 || !bytes.Equal(facts.CertificateSha256, request.CertificateSHA256[:]) ||
		!validIdentity(facts.ArtifactEncryptionKeyId, 128) || facts.SelectedProtocolVersion == nil || facts.SelectedProtocolVersion.Major == 0 ||
		facts.SelectedProtocolVersion.Major > 65535 || facts.SelectedProtocolVersion.Minor > 65535 || len(facts.SelectedProtocolVersion.ProtoReflect().GetUnknown()) != 0 ||
		facts.Capabilities == nil || len(facts.Capabilities.ProtoReflect().GetUnknown()) != 0 || len(facts.Capabilities.Features) == 0 {
		return nil, nil, nil, ErrInvalidInput
	}
	for _, feature := range facts.Capabilities.Features {
		if feature == nil || len(feature.ProtoReflect().GetUnknown()) != 0 {
			return nil, nil, nil, ErrInvalidInput
		}
	}
	caps, _, err := canonicalCapabilities(facts.Capabilities)
	original, marshalErr := (proto.MarshalOptions{Deterministic: true}).Marshal(facts.Capabilities)
	if err != nil || marshalErr != nil || !bytes.Equal(caps, original) {
		return nil, nil, nil, ErrInvalidInput
	}
	cloned := proto.Clone(facts).(*controlv1.GatewaySessionFactsV1)
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cloned)
	if err != nil {
		return nil, nil, nil, ErrInvalidInput
	}
	return cloned, caps, encoded, nil
}

// Revocation locks certificate/CA before identity state. NOWAIT prevents a
// renewal already holding a certificate from deadlocking with a node writer.
func lockSessionAuthority(ctx context.Context, tx pgx.Tx, request GetAuthorizationRequest) error {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT cert.id FROM node_certificates cert
  JOIN node_ca_key_epochs epoch ON epoch.id=cert.ca_epoch_id
  WHERE cert.node_id=$1 AND cert.serial_number=$2 AND cert.leaf_der_sha256=$3
  FOR SHARE OF cert,epoch NOWAIT`, request.NodeID, request.CertificateSerialNumber, request.CertificateSHA256[:]).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCertificateNotFound
	}
	if err != nil {
		return fmt.Errorf("%w: lock node certificate: %v", ErrPersistence, err)
	}
	err = tx.QueryRow(ctx, `SELECT id FROM nodes WHERE id=$1 FOR UPDATE NOWAIT`, request.NodeID).Scan(&id)
	if err != nil {
		return fmt.Errorf("%w: lock node: %v", ErrPersistence, err)
	}
	var epoch int64
	err = tx.QueryRow(ctx, `SELECT session_epoch FROM node_presence WHERE node_id=$1 FOR SHARE NOWAIT`, request.NodeID).Scan(&epoch)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: lock node presence: %v", ErrPersistence, err)
	}
	return nil
}

func persistSessionCapabilities(ctx context.Context, tx pgx.Tx, request GetAuthorizationRequest, snapshot AuthorizationSnapshot, now time.Time) ([]byte, error) {
	facts, caps, encoded, err := normalizeSessionFacts(request)
	if err != nil {
		return nil, err
	}
	// Deployments may be paused (draining, pending, certificate overlap) for a
	// long time: the capability facts are still recorded so capability-gated
	// pushes (EDGE_SIGNER_TRUST) see the Agent the node actually runs. Only
	// facts of a current certificate are recorded; anything else is not an
	// error while deployments are paused, just no receipt (no upgrade authority).
	paused := !snapshot.DeploymentsAllowed
	if !snapshot.ConnectionAllowed || facts.ArtifactEncryptionKeyId != snapshot.ArtifactEncryptionKeyID ||
		compareProtocol(facts.SelectedProtocolVersion, snapshot.AcceptedProtocolVersions.Minimum) < 0 ||
		compareProtocol(facts.SelectedProtocolVersion, snapshot.AcceptedProtocolVersions.Maximum) > 0 {
		return nil, ErrNodeStateDenied
	}
	var certificateID uuid.UUID
	var publicKey, publicHash, leafPEM, caPEM, caHash []byte
	err = tx.QueryRow(ctx, `SELECT cert.id,key.public_key,key.public_key_sha256,cert.leaf_certificate_pem,epoch.ca_certificate_pem,epoch.ca_certificate_sha256
  FROM nodes node
  JOIN node_identity_state state ON state.node_id=node.id
  JOIN node_artifact_encryption_keys key ON key.id=state.active_artifact_key_id AND key.node_id=node.id
   AND key.status='active' AND key.activated_at<=$5 AND key.deactivated_at IS NULL
  JOIN node_identity_authorizations auth ON auth.id=key.authorization_id AND auth.node_id=node.id
   AND auth.status='issued' AND auth.artifact_key_id=key.id AND auth.artifact_public_key=key.public_key
   AND auth.gateway_workload_identity=$4 AND auth.completed_at<=$5
   AND auth.authorized_at<=auth.completed_at AND auth.completed_at<auth.expires_at
  JOIN node_certificates initial ON initial.id=auth.issued_certificate_id AND initial.node_id=node.id
   AND initial.enrollment_authorization_id=auth.id AND initial.owner_scope_id=node.scope_id
  JOIN control_installation_entitlement installation ON installation.singleton AND installation.installation_id=initial.installation_id
  JOIN node_certificates cert ON cert.node_id=node.id AND cert.serial_number=$2 AND cert.leaf_der_sha256=$3
   AND cert.owner_scope_id=node.scope_id AND cert.installation_id=installation.installation_id
   AND cert.status='active' AND cert.rotation_status='current' AND cert.issued_at>=initial.issued_at
   AND (cert.enrollment_authorization_id=auth.id OR cert.issuance_kind='renewal')
   AND cert.not_before<=$5 AND cert.not_after>$5
  JOIN node_ca_key_epochs epoch ON epoch.id=cert.ca_epoch_id AND epoch.installation_id=cert.installation_id
   AND epoch.status IN ('active','retired') AND epoch.not_before<=$5 AND epoch.not_after>$5
  WHERE node.id=$1 AND node.admin_state IN ('active','draining','pending') AND key.id=$6
   AND NOT EXISTS(SELECT 1 FROM node_certificate_revocations revoked WHERE revoked.certificate_id=cert.id
    AND revoked.node_id=node.id AND revoked.binding_status='bound' AND revoked.effective_at<=$5)
   AND NOT EXISTS(SELECT 1 FROM node_identity_authorizations newer WHERE newer.node_id=node.id AND newer.status='issued' AND newer.completed_at>auth.completed_at)
  FOR SHARE OF state,key,auth,initial,installation NOWAIT`, request.NodeID, request.CertificateSerialNumber, request.CertificateSHA256[:], request.GatewayWorkloadIdentity, now, facts.ArtifactEncryptionKeyId).Scan(&certificateID, &publicKey, &publicHash, &leafPEM, &caPEM, &caHash)
	if errors.Is(err, pgx.ErrNoRows) {
		if paused {
			return nil, nil
		}
		return nil, ErrNodeStateDenied
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read session authority: %v", ErrPersistence, err)
	}
	keyHash := sha256.Sum256(publicKey)
	leaf, leafErr := parseSinglePEMCertificate(leafPEM)
	ca, caErr := parseSinglePEMCertificate(caPEM)
	if leafErr != nil || caErr != nil || len(publicKey) != 32 || !bytes.Equal(keyHash[:], publicHash) || facts.ArtifactEncryptionKeyId != "x25519:"+hex.EncodeToString(keyHash[:]) {
		return nil, ErrCertificateInvalid
	}
	actualCAHash := sha256.Sum256(ca.Raw)
	actualLeafHash := sha256.Sum256(leaf.Raw)
	if !bytes.Equal(actualCAHash[:], caHash) || !bytes.Equal(actualLeafHash[:], facts.CertificateSha256) || leaf.CheckSignatureFrom(ca) != nil ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != NodeSPIFFEPrefix+request.NodeID.String() {
		return nil, ErrCertificateInvalid
	}
	var maximum int64
	if err := tx.QueryRow(ctx, `SELECT GREATEST(COALESCE((SELECT max(session_epoch) FROM node_session_capabilities WHERE node_id=$1),0),
  COALESCE((SELECT session_epoch FROM node_presence WHERE node_id=$1),0))`, request.NodeID).Scan(&maximum); err != nil {
		return nil, fmt.Errorf("%w: read session epoch: %v", ErrPersistence, err)
	}
	if int64(facts.SessionEpoch) < maximum {
		return nil, ErrIdempotencyConflict
	}
	digest := sha256.Sum256(encoded)
	capDigest := sha256.Sum256(caps)
	var stored []byte
	var workload, instance string
	err = tx.QueryRow(ctx, `SELECT facts_sha256,gateway_workload_identity,gateway_instance_id FROM node_session_capabilities WHERE node_id=$1 AND session_epoch=$2`, request.NodeID, int64(facts.SessionEpoch)).Scan(&stored, &workload, &instance)
	if err == nil {
		if !bytes.Equal(stored, digest[:]) || workload != request.GatewayWorkloadIdentity || instance != request.GatewayInstanceID {
			return nil, ErrIdempotencyConflict
		}
		return bytes.Clone(stored), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: read session capabilities: %v", ErrPersistence, err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,artifact_key_id,
  selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,facts_snapshot,facts_sha256,
  gateway_workload_identity,gateway_instance_id,registered_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		request.NodeID, int64(facts.SessionEpoch), certificateID, facts.CertificateSha256, facts.ArtifactEncryptionKeyId,
		facts.SelectedProtocolVersion.Major, facts.SelectedProtocolVersion.Minor, caps, capDigest[:], encoded, digest[:], request.GatewayWorkloadIdentity, request.GatewayInstanceID, now)
	if err != nil {
		return nil, fmt.Errorf("%w: record session capabilities: %v", ErrPersistence, err)
	}
	return digest[:], nil
}
