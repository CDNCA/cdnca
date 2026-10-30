package controlupgrade

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Shared by status, preflight and finalization. A newer registration fences old
// facts even before its first heartbeat; a newer heartbeat cannot reuse them.
// $3 is the current authority time, not the one-time enrollment expiry.
const upgradeSessionAuthoritySQL = `SELECT facts.selected_protocol_major,facts.capabilities_snapshot,facts.capabilities_sha256
 FROM node_session_capabilities facts
 JOIN node_identity_state state ON state.node_id=facts.node_id AND state.active_artifact_key_id=facts.artifact_key_id
 JOIN node_artifact_encryption_keys artifact ON artifact.id=state.active_artifact_key_id AND artifact.node_id=state.node_id
  AND artifact.status='active' AND artifact.deactivated_at IS NULL AND artifact.activated_at<=$3
 JOIN node_identity_authorizations auth ON auth.id=artifact.authorization_id AND auth.node_id=state.node_id
  AND auth.status='issued' AND auth.artifact_key_id=artifact.id AND auth.artifact_public_key=artifact.public_key
  AND auth.gateway_workload_identity=facts.gateway_workload_identity
  AND auth.completed_at<=$3 AND auth.authorized_at<=auth.completed_at AND auth.completed_at<auth.expires_at
 JOIN node_certificates initial ON initial.id=auth.issued_certificate_id AND initial.node_id=node.id
  AND initial.enrollment_authorization_id=auth.id AND initial.owner_scope_id=node.scope_id
 JOIN control_installation_entitlement installation ON installation.singleton AND installation.installation_id=initial.installation_id
 JOIN node_certificates certificate ON certificate.id=facts.certificate_id AND certificate.node_id=node.id
  AND certificate.leaf_der_sha256=facts.certificate_sha256 AND certificate.owner_scope_id=node.scope_id
  AND certificate.installation_id=installation.installation_id AND certificate.status='active'
  AND certificate.rotation_status='current' AND certificate.not_before<=$3 AND certificate.not_after>$3
  AND certificate.issued_at>=initial.issued_at AND (certificate.enrollment_authorization_id=auth.id OR certificate.issuance_kind='renewal')
 JOIN node_ca_key_epochs epoch ON epoch.id=certificate.ca_epoch_id AND epoch.installation_id=installation.installation_id
  AND epoch.status IN ('active','retired') AND epoch.not_before<=$3 AND epoch.not_after>$3
 WHERE facts.node_id=node.id AND facts.registered_at<=$3
  AND facts.session_epoch=presence.confirmed_session_epoch AND facts.session_epoch=presence.session_epoch
  AND facts.session_epoch=(SELECT max(latest.session_epoch) FROM node_session_capabilities latest WHERE latest.node_id=node.id)
  AND NOT EXISTS(SELECT 1 FROM node_certificate_revocations revoked WHERE revoked.certificate_id=certificate.id
   AND revoked.node_id=node.id AND revoked.binding_status='bound' AND revoked.effective_at<=$3)
  AND NOT EXISTS(SELECT 1 FROM node_identity_authorizations newer WHERE newer.node_id=node.id AND newer.status='issued' AND newer.completed_at>auth.completed_at)`

func lockUpgradeSessionAuthority(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) error {
	// The caller holds nodes FOR SHARE, blocking a new registration. Lock current
	// certificates/CA before reading scheduled revocations in a fresh statement.
	// NOWAIT avoids the reverse lock order of certificate renewal/revocation.
	rows, err := tx.Query(ctx, `SELECT certificate.id FROM node_certificates certificate
  JOIN node_ca_key_epochs epoch ON epoch.id=certificate.ca_epoch_id
  WHERE certificate.node_id=ANY($1::uuid[]) AND certificate.rotation_status='current'
  ORDER BY certificate.node_id FOR SHARE OF certificate,epoch NOWAIT`, nodeIDs)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
	}
	return rows.Err()
}
