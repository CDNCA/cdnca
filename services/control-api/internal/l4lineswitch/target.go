package l4lineswitch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresTargetCoordinator struct {
	pool    *pgxpool.Pool
	iam     *iamlock.Authorizer
	auditor auditAppender
}

type targetHead struct {
	reference    SnapshotReference
	source       int64
	revision     int64
	lastSwitchID uuid.UUID
}

func NewPostgresTargetCoordinator(
	pool *pgxpool.Pool,
	iam *iamlock.Authorizer,
	auditor auditAppender,
) (*PostgresTargetCoordinator, error) {
	if pool == nil || iam == nil || !iam.Configured() {
		return nil, ErrInvalidInput
	}
	if auditor == nil {
		auditor = audit.New(pool)
	}
	return &PostgresTargetCoordinator{pool: pool, iam: iam, auditor: auditor}, nil
}

func (coordinator *PostgresTargetCoordinator) Activate(ctx context.Context, actor Actor, value Switch) error {
	return coordinator.move(ctx, actor, value, "activate", value.From.Reference, value.To.Reference)
}

func (coordinator *PostgresTargetCoordinator) Restore(ctx context.Context, actor Actor, value Switch) error {
	return coordinator.move(ctx, actor, value, "restore", value.To.Reference, value.From.Reference)
}

func (coordinator *PostgresTargetCoordinator) move(
	ctx context.Context,
	actor Actor,
	value Switch,
	operation string,
	before, after SnapshotReference,
) error {
	if ctx == nil || coordinator == nil || !validAuthority(actor) || value.ID == uuid.Nil ||
		value.ConfigurationScopeID == uuid.Nil || value.ExpectedSourceRevision < 1 ||
		!validSnapshotReference(before) || !validSnapshotReference(after) || before == after ||
		(operation != "activate" && operation != "restore") {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, coordinator.pool, func(tx pgx.Tx) error {
		if err := authorizeTx(ctx, tx, coordinator.iam, actor, value.ConfigurationScopeID, value.ID, PermissionManage); err != nil {
			return err
		}
		var databaseNow time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
			return fmt.Errorf("%w: read database clock", ErrPersistence)
		}
		head, found, err := loadTargetHead(ctx, tx, value.ConfigurationScopeID)
		if err != nil {
			return err
		}
		if !found {
			if operation != "activate" {
				return ErrConflict
			}
			head, err = loadPublicationTarget(ctx, tx, value.ConfigurationScopeID, value.ExpectedSourceRevision)
			if err != nil {
				return err
			}
		} else if operation == "activate" && head.source != value.ExpectedSourceRevision {
			published, err := loadPublicationTarget(ctx, tx, value.ConfigurationScopeID, value.ExpectedSourceRevision)
			if err != nil {
				return err
			}
			if !sameSnapshotReference(published.reference, before) {
				return ErrConflict
			}
		}
		if sameSnapshotReference(head.reference, after) && head.source == value.ExpectedSourceRevision &&
			head.lastSwitchID == value.ID {
			return nil
		}
		if !sameSnapshotReference(head.reference, before) || operation == "restore" && head.source != value.ExpectedSourceRevision {
			return ErrConflict
		}
		nextRevision := head.revision + 1
		if head.revision == 0 {
			nextRevision = 1
			if _, err := tx.Exec(ctx, `INSERT INTO l4_line_target_heads(
				configuration_scope_id,snapshot_id,snapshot_revision,snapshot_sha256,source_revision,
				revision,last_switch_id,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
				value.ConfigurationScopeID, after.ID, after.Revision, after.SHA256[:], value.ExpectedSourceRevision,
				nextRevision, value.ID, databaseNow); err != nil {
				return fmt.Errorf("%w: initialize line target", ErrPersistence)
			}
		} else {
			command, err := tx.Exec(ctx, `UPDATE l4_line_target_heads SET
				snapshot_id=$1,snapshot_revision=$2,snapshot_sha256=$3,source_revision=$4,
				revision=$5,last_switch_id=$6,updated_at=$7
				WHERE configuration_scope_id=$8 AND revision=$9 AND snapshot_id=$10 AND snapshot_revision=$11 AND snapshot_sha256=$12`,
				after.ID, after.Revision, after.SHA256[:], value.ExpectedSourceRevision, nextRevision, value.ID, databaseNow,
				value.ConfigurationScopeID, head.revision, before.ID, before.Revision, before.SHA256[:])
			if err != nil {
				return fmt.Errorf("%w: move line target", ErrPersistence)
			}
			if command.RowsAffected() != 1 {
				return ErrConflict
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO l4_line_target_events(
			configuration_scope_id,revision,switch_id,operation,source_revision,before_snapshot_id,before_snapshot_revision,
			before_snapshot_sha256,after_snapshot_id,after_snapshot_revision,after_snapshot_sha256,occurred_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			value.ConfigurationScopeID, nextRevision, value.ID, operation, value.ExpectedSourceRevision,
			before.ID, before.Revision, before.SHA256[:], after.ID, after.Revision, after.SHA256[:], databaseNow); err != nil {
			return fmt.Errorf("%w: append line target event", ErrPersistence)
		}
		if err := coordinator.auditor.Append(ctx, tx, audit.Event{
			ScopeID: value.ConfigurationScopeID, ActorUserID: auditActorUserID(actor),
			Action: "l4_line_switch.target." + operation, ResourceType: "l4_line_switch",
			ResourceID: value.ID.String(), RequestID: value.RequestID.String(), Result: "success",
			Payload: map[string]any{
				"head_revision": nextRevision, "before_snapshot_id": before.ID.String(),
				"after_snapshot_id": after.ID.String(), "source_revision": value.ExpectedSourceRevision,
			},
		}); err != nil {
			return fmt.Errorf("%w: append line target audit", ErrPersistence)
		}
		return nil
	})
}

func loadTargetHead(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (targetHead, bool, error) {
	var result targetHead
	var digest []byte
	err := tx.QueryRow(ctx, `SELECT snapshot_id,snapshot_revision,snapshot_sha256,source_revision,revision,last_switch_id
		FROM l4_line_target_heads WHERE configuration_scope_id=$1 FOR UPDATE`, scopeID).Scan(
		&result.reference.ID, &result.reference.Revision, &digest, &result.source, &result.revision, &result.lastSwitchID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return targetHead{}, false, nil
	}
	if err != nil {
		return targetHead{}, false, fmt.Errorf("%w: load line target", ErrPersistence)
	}
	if len(digest) != len(result.reference.SHA256) || result.lastSwitchID == uuid.Nil {
		return targetHead{}, false, ErrConflict
	}
	copy(result.reference.SHA256[:], digest)
	if !validSnapshotReference(result.reference) || result.source < 1 || result.revision < 1 {
		return targetHead{}, false, ErrConflict
	}
	return result, true, nil
}

func loadPublicationTarget(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, sourceRevision int64) (targetHead, error) {
	var result targetHead
	var digest []byte
	err := tx.QueryRow(ctx, `SELECT target_snapshot_id,target_snapshot_revision,target_resolver_sha256
		FROM edge_config_publications
		WHERE configuration_scope_id=$1 AND source_revision=$2 AND contract_version=1 AND target_kind='resolver'
		FOR SHARE`, scopeID, sourceRevision).Scan(&result.reference.ID, &result.reference.Revision, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return targetHead{}, ErrNotFound
	}
	if err != nil {
		return targetHead{}, fmt.Errorf("%w: load published line target", ErrPersistence)
	}
	if len(digest) != len(result.reference.SHA256) {
		return targetHead{}, ErrConflict
	}
	copy(result.reference.SHA256[:], digest)
	if !validSnapshotReference(result.reference) {
		return targetHead{}, ErrConflict
	}
	result.source = sourceRevision
	return result, nil
}

func sameSnapshotReference(left, right SnapshotReference) bool {
	return left.ID == right.ID && left.Revision == right.Revision && bytes.Equal(left.SHA256[:], right.SHA256[:])
}
