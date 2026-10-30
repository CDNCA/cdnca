package nodecertlifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool                   *pgxpool.Pool
	auditor                *audit.Log
	clock                  Clock
	overlap                time.Duration
	snapshotTTL            time.Duration
	maxScheduledRevocation time.Duration
}

type certificateFact struct {
	CertificateState
	leafPEM                []byte
	leafStoredHash         [32]byte
	csrHash                [32]byte
	issuanceKind           string
	replacesID             *uuid.UUID
	renewalRequestID       *uuid.UUID
	lifecycleRequestID     *uuid.UUID
	lifecycleRequestDigest [32]byte
	caPEM                  []byte
	caStatus               string
	caEpoch                int64
}

func NewStore(pool *pgxpool.Pool, config Config) (*Store, error) {
	if pool == nil || config.Clock == nil || config.OverlapWindow < 10*time.Second ||
		config.OverlapWindow > time.Hour || config.AuthorizationSnapshotTTL < time.Second ||
		config.AuthorizationSnapshotTTL > 5*time.Minute || config.MaxScheduledRevocation < 0 ||
		config.MaxScheduledRevocation > 7*24*time.Hour {
		return nil, ErrInvalidInput
	}
	return &Store{
		pool: pool, auditor: audit.New(pool), clock: config.Clock, overlap: config.OverlapWindow,
		snapshotTTL:            config.AuthorizationSnapshotTTL,
		maxScheduledRevocation: config.MaxScheduledRevocation,
	}, nil
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		(actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func validTraceID(value string) bool {
	return value == strings.TrimSpace(value) && len(value) >= 1 && len(value) <= 128
}

func authorizeActor(ctx context.Context, tx pgx.Tx, actor Actor, ownerScopeID uuid.UUID, platformOnly bool) error {
	if !validActor(actor) {
		return ErrPermissionDenied
	}
	var kind string
	var member, permitted bool
	permission := "nodes.manage"
	if platformOnly {
		permission = "node_ca.manage"
	}
	err := tx.QueryRow(ctx, `SELECT scope.kind,
		EXISTS(SELECT 1 FROM memberships membership
		       WHERE membership.scope_id=scope.id AND membership.user_id=$2 AND membership.status='active'),
		EXISTS(SELECT 1 FROM role_assignments assignment
		       JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id
		       WHERE assignment.scope_id=scope.id AND assignment.user_id=$2
		       AND grant_row.permission_name=$3)
		FROM access_scopes scope WHERE scope.id=$1`, actor.ScopeID, actor.UserID, permission).Scan(&kind, &member, &permitted)
	if errors.Is(err, pgx.ErrNoRows) || kind != actor.ScopeKind || !member || !permitted ||
		(platformOnly && kind != "platform") || (!platformOnly && actor.ScopeID != ownerScopeID) {
		return ErrPermissionDenied
	}
	if err != nil {
		return ErrPersistence
	}
	return nil
}

func installationID(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (string, error) {
	var installation string
	err := query.QueryRow(ctx, `SELECT installation_id FROM control_installation_entitlement WHERE singleton`).Scan(&installation)
	if errors.Is(err, pgx.ErrNoRows) || installation == "" {
		return "", ErrInstallationMissing
	}
	if err != nil {
		return "", ErrPersistence
	}
	return installation, nil
}

func loadCertificateFact(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, nodeID uuid.UUID, serial string) (certificateFact, error) {
	var fact certificateFact
	var storedLeafHash, csrHash, leafDERHash, lifecycleRequestDigest []byte
	err := query.QueryRow(ctx, `SELECT certificate.id,certificate.node_id,node.scope_id,
		COALESCE(certificate.installation_id,''),certificate.serial_number,certificate.leaf_certificate_pem,
		certificate.leaf_certificate_sha256,certificate.leaf_der_sha256,certificate.csr_sha256,
		certificate.status,certificate.rotation_status,certificate.lifecycle_revision,
		COALESCE(certificate.ca_epoch_id,'00000000-0000-0000-0000-000000000000'::uuid),
		certificate.not_before,certificate.not_after,certificate.renewal_at,
		certificate.overlap_until,certificate.issuance_kind,certificate.replaces_certificate_id,
		certificate.renewal_request_id,certificate.lifecycle_request_id,certificate.lifecycle_request_digest,
		COALESCE(epoch.ca_certificate_pem,'\x'::bytea),
		COALESCE(epoch.status,''),COALESCE(epoch.epoch,0)
		FROM node_certificates certificate
		JOIN nodes node ON node.id=certificate.node_id
		LEFT JOIN node_ca_key_epochs epoch ON epoch.id=certificate.ca_epoch_id
		WHERE certificate.node_id=$1 AND certificate.serial_number=$2`, nodeID, serial).Scan(
		&fact.CertificateID, &fact.NodeID, &fact.OwnerScopeID, &fact.InstallationID,
		&fact.SerialNumber, &fact.leafPEM, &storedLeafHash, &leafDERHash, &csrHash,
		&fact.Status, &fact.RotationStatus, &fact.Revision, &fact.CAEpochID,
		&fact.NotBefore, &fact.NotAfter, &fact.RenewalAt, &fact.OverlapUntil,
		&fact.issuanceKind, &fact.replacesID, &fact.renewalRequestID,
		&fact.lifecycleRequestID, &lifecycleRequestDigest,
		&fact.caPEM, &fact.caStatus, &fact.caEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return certificateFact{}, ErrNotFound
	}
	if err != nil || len(storedLeafHash) != 32 || len(csrHash) != 32 ||
		(len(leafDERHash) != 0 && len(leafDERHash) != 32) {
		return certificateFact{}, ErrPersistence
	}
	copy(fact.leafStoredHash[:], storedLeafHash)
	copy(fact.csrHash[:], csrHash)
	copy(fact.LeafDERSHA256[:], leafDERHash)
	if len(lifecycleRequestDigest) != 0 {
		if len(lifecycleRequestDigest) != 32 {
			return certificateFact{}, ErrPersistence
		}
		copy(fact.lifecycleRequestDigest[:], lifecycleRequestDigest)
	}
	return fact, nil
}

func incrementAuthorizationRevision(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, now time.Time) (uint64, error) {
	var revision int64
	err := tx.QueryRow(ctx, `UPDATE node_identity_state SET
		authorization_revision=authorization_revision+1,updated_at=GREATEST(updated_at,$2)
		WHERE node_id=$1 RETURNING authorization_revision`, nodeID, now).Scan(&revision)
	if err != nil || revision < 1 {
		return 0, ErrPersistence
	}
	return uint64(revision), nil
}

func appendAudit(ctx context.Context, logger *audit.Log, tx pgx.Tx, scopeID uuid.UUID, actorUserID *uuid.UUID,
	action, resourceID, requestID string, payload map[string]any,
) error {
	if err := logger.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: actorUserID, Action: action,
		ResourceType: "node_certificate", ResourceID: resourceID,
		RequestID: requestID, Result: "success", Payload: payload,
	}); err != nil {
		return ErrPersistence
	}
	return nil
}

func mapDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		return err
	}
	if databaseError.Code == "23505" {
		switch databaseError.ConstraintName {
		case "node_ca_key_epochs_one_active_idx", "node_ca_key_epochs_installation_id_epoch_key":
			return ErrCAEpochConflict
		case "node_certificates_one_lifecycle_overlap_idx":
			return ErrOverlapActive
		default:
			return ErrIdempotencyConflict
		}
	}
	return ErrPersistence
}

func wrap(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, mapDatabaseError(err))
}
