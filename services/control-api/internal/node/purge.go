package node

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// purgeRevocationReason is recorded on every certificate revoked because an
// administrator deleted its node.
const purgeRevocationReason = "node deleted by administrator"

// auditActionNodeDelete is the audit record of a physical node deletion. It
// outlives the node: audit_events does not reference nodes.
const auditActionNodeDelete = "node.delete"

// ensureNodeUnreferenced blocks deletion while the node is still in use:
// listed by the current revision of a live line group or by a live L2
// configuration (removing it silently would change customer resolution), or
// taking part in multi-node work that is not finished yet (a queued/running
// cache operation, an active cross-node CC coordination). The administrator
// detaches it, or waits for the work to finish, and deletes again.
func ensureNodeUnreferenced(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, now time.Time) error {
	var referenced bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM node_line_endpoints endpoint
			JOIN node_line_groups line_group ON line_group.tenant_scope_id = endpoint.tenant_scope_id
			 AND line_group.id = endpoint.line_group_id AND line_group.current_revision = endpoint.config_revision
			WHERE endpoint.node_id = $1 AND line_group.deleted_at IS NULL
		) OR EXISTS (
			SELECT 1 FROM l2_topology_nodes membership
			JOIN l2_topology_configs config ON config.tenant_scope_id = membership.tenant_scope_id
			 AND config.id = membership.config_id
			WHERE membership.node_id = $1 AND membership.deleted_at IS NULL AND config.deleted_at IS NULL
		) OR EXISTS (
			SELECT 1 FROM cache_operation_nodes WHERE node_id = $1 AND state IN ('queued', 'running')
		) OR EXISTS (
			SELECT 1 FROM cc_coordination_states state
			JOIN cc_coordination_facts fact ON fact.tenant_scope_id = state.tenant_scope_id AND fact.id = state.last_fact_id
			WHERE fact.node_id = $1 AND state.state NOT IN ('released', 'failed') AND state.expires_at > $2
		)`, nodeID, now).Scan(&referenced); err != nil {
		return fmt.Errorf("check node references: %w", err)
	}
	if referenced {
		return ErrInUse
	}
	return nil
}

// lockHTTP01Overlay takes the lock every ACME HTTP-01 overlay writer takes
// first (internal/acmehttp01 lockOverlay, migration 342). A deletion takes it
// before locking the node row: a writer holding it may be waiting for a key
// share lock on the node row (foreign keys), so the reverse order deadlocks.
func lockHTTP01Overlay(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('acme-http01-overlay', 0))`); err != nil {
		return fmt.Errorf("lock HTTP-01 overlay: %w", err)
	}
	return nil
}

// revokedCertificate identifies a certificate revoked by a node deletion in
// the audit record.
type revokedCertificate struct {
	ID           string `json:"id"`
	SerialNumber string `json:"serial_number"`
}

// revokeNodeCertificates revokes every still-active certificate of a node
// being deleted, in the deletion transaction, and returns them for the audit
// record. The revocation facts are removed again by the purge cascade; what
// remains is the audit event.
func revokeNodeCertificates(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, now time.Time) ([]revokedCertificate, error) {
	type activeCertificate struct {
		id             uuid.UUID
		serialNumber   string
		rotationStatus string
		ownerScopeID   *uuid.UUID
		installationID *string
		caEpochID      *uuid.UUID
		leafDERSHA256  []byte
	}
	rows, err := tx.Query(ctx, `
		SELECT id, serial_number, rotation_status, owner_scope_id, installation_id, ca_epoch_id, leaf_der_sha256
		FROM node_certificates WHERE node_id = $1 AND status = 'active'
		ORDER BY id FOR UPDATE`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("load node certificates: %w", err)
	}
	certificates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (activeCertificate, error) {
		var item activeCertificate
		err := row.Scan(&item.id, &item.serialNumber, &item.rotationStatus, &item.ownerScopeID, &item.installationID,
			&item.caEpochID, &item.leafDERSHA256)
		return item, err
	})
	if err != nil {
		return nil, fmt.Errorf("load node certificates: %w", err)
	}
	revoked := make([]revokedCertificate, 0, len(certificates))
	for _, certificate := range certificates {
		var revision int64
		if err := tx.QueryRow(ctx, `
			UPDATE node_identity_state SET authorization_revision = authorization_revision + 1,
			       updated_at = GREATEST(updated_at, $2)
			WHERE node_id = $1 RETURNING authorization_revision`, nodeID, now).Scan(&revision); err != nil {
			return nil, fmt.Errorf("advance node authorization revision: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE node_certificates SET status = 'revoked', revoked_at = $2, revocation_reason = $3
			WHERE id = $1 AND status = 'active'`, certificate.id, now, purgeRevocationReason); err != nil {
			return nil, fmt.Errorf("revoke node certificate: %w", err)
		}
		requestID := uuid.NewSHA1(certificate.id, []byte("node-retire-certificate-revocation"))
		digest := sha256.Sum256([]byte("node-retire:" + nodeID.String() + ":" + certificate.id.String()))
		bound := certificate.rotationStatus != "legacy_unbound" && certificate.ownerScopeID != nil &&
			certificate.installationID != nil && certificate.caEpochID != nil && len(certificate.leafDERSHA256) == sha256.Size
		if bound {
			_, err = tx.Exec(ctx, `
				INSERT INTO node_certificate_revocations
					(request_id, request_digest, certificate_id, node_id, reason, revoked_at, authorization_revision,
					 owner_scope_id, installation_id, ca_epoch_id, leaf_der_sha256, effective_at, binding_status)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$6,'bound')`,
				requestID, digest[:], certificate.id, nodeID, purgeRevocationReason, now, revision,
				*certificate.ownerScopeID, *certificate.installationID, *certificate.caEpochID, certificate.leafDERSHA256)
		} else {
			_, err = tx.Exec(ctx, `
				INSERT INTO node_certificate_revocations
					(request_id, request_digest, certificate_id, node_id, reason, revoked_at, authorization_revision)
				VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				requestID, digest[:], certificate.id, nodeID, purgeRevocationReason, now, revision)
		}
		if err != nil {
			return nil, fmt.Errorf("record node certificate revocation: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO node_certificate_events
				(id, node_id, certificate_id, event_type, reason, authorization_revision, occurred_at)
			VALUES ($1,$2,$3,'revoked',$4,$5,$6)`,
			uuid.NewSHA1(requestID, []byte("node-certificate-revocation-event")), nodeID, certificate.id,
			purgeRevocationReason, revision, now); err != nil {
			return nil, fmt.Errorf("record node certificate revocation event: %w", err)
		}
		revoked = append(revoked, revokedCertificate{ID: certificate.id.String(), SerialNumber: certificate.serialNumber})
	}
	return revoked, nil
}

// purgeNode physically deletes a locked node inside the caller's transaction
// (which took lockHTTP01Overlay before locking the node):
// it checks references, revokes the certificates, writes the node.delete audit
// event, and deletes the node row. Migration 284 cascades the delete to every
// row that only describes this node; the protection triggers on those rows
// let the cascade through only for the node named in cdnca.node_purge. The
// node name is free again once the transaction commits, and the node ID is
// recorded in node_purged_ids so registration never hands it out again.
//
// It returns the deleted node as last seen, with admin_state "retired" and the
// revision advanced, which is what the write response reports.
func (s *Store) purgeNode(ctx context.Context, tx pgx.Tx, actor Actor, item Node, requestID string) (Node, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	if err := ensureNodeUnreferenced(ctx, tx, item.ID, now); err != nil {
		return Node{}, err
	}
	revoked, err := revokeNodeCertificates(ctx, tx, item.ID, now)
	if err != nil {
		return Node{}, err
	}
	// Soft-deleted L2 memberships are history of a configuration that no
	// longer uses the node; the live ones were refused above. The L2
	// membership foreign key stays RESTRICT, so they are removed explicitly.
	if _, err := tx.Exec(ctx, `
		DELETE FROM l2_topology_nodes membership
		WHERE membership.node_id = $1 AND (membership.deleted_at IS NOT NULL OR EXISTS (
			SELECT 1 FROM l2_topology_configs config WHERE config.tenant_scope_id = membership.tenant_scope_id
			  AND config.id = membership.config_id AND config.deleted_at IS NOT NULL))`, item.ID); err != nil {
		return Node{}, fmt.Errorf("remove deleted L2 memberships: %w", err)
	}
	payload := map[string]any{
		"node_id":              item.ID.String(),
		"display_id":           item.DisplayID,
		"name":                 item.Name,
		"ipv4":                 item.IPv4,
		"ipv6":                 item.IPv6,
		"region":               item.Region,
		"from_state":           item.AdminState,
		"revision":             item.Revision,
		"node_created_at":      item.CreatedAt.UTC().Format(time.RFC3339Nano),
		"revoked_certificates": revoked,
		"deleted_by_user_id":   actor.UserID.String(),
		"deleted_at":           now.Format(time.RFC3339Nano),
		"purged":               true,
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID:      actor.ScopeID,
		ActorUserID:  &actor.UserID,
		Action:       auditActionNodeDelete,
		ResourceType: "node",
		ResourceID:   item.ID.String(),
		RequestID:    requestID,
		Result:       "success",
		Payload:      payload,
	}); err != nil {
		return Node{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('cdnca.node_purge', $1, true)`, item.ID.String()); err != nil {
		return Node{}, fmt.Errorf("mark node purge: %w", err)
	}
	// ACME HTTP-01 facts (337/342) keep RESTRICT foreign keys and append-only
	// guards; migration 346 deletes them for the marked node, keeping a
	// tombstone in each site epoch it was frozen into.
	if _, err := tx.Exec(ctx, `SELECT acme_http01_purge_node_346($1)`, item.ID); err != nil {
		return Node{}, fmt.Errorf("purge node HTTP-01 facts: %w", err)
	}
	command, err := tx.Exec(ctx, `DELETE FROM nodes WHERE id = $1 AND scope_id = $2`, item.ID, actor.ScopeID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "23001" || pgErr.Code == "23503") {
			return Node{}, ErrInUse
		}
		return Node{}, fmt.Errorf("delete node: %w", err)
	}
	if command.RowsAffected() != 1 {
		return Node{}, ErrNotFound
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('cdnca.node_purge', '', true)`); err != nil {
		return Node{}, fmt.Errorf("clear node purge mark: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_purged_ids (node_id, scope_id, purged_at) VALUES ($1, $2, $3)
		ON CONFLICT (node_id) DO NOTHING`, item.ID, actor.ScopeID, now); err != nil {
		return Node{}, fmt.Errorf("record purged node id: %w", err)
	}
	deleted := item
	deleted.AdminState = StateRetired
	deleted.Revision++
	deleted.UpdatedAt = now
	return deleted, nil
}
