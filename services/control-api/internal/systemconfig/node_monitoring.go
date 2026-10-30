package systemconfig

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LoadActiveNodeMonitoring reads an already authorized activation for command
// reconciliation. It never promotes bootstrap defaults or an unactivated head.
// The caller must retain the transaction through outbox insertion: these locks
// keep activation serialized in platform -> stream -> node order.
func LoadActiveNodeMonitoring(ctx context.Context, tx pgx.Tx) (CategoryDocument, time.Time, error) {
	if ctx == nil || tx == nil {
		return CategoryDocument{}, time.Time{}, ErrInvalidStore
	}
	var platformScopeID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM access_scopes
		WHERE kind='platform' AND tenant_id IS NULL FOR SHARE`).Scan(&platformScopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return CategoryDocument{}, time.Time{}, nil
	}
	if err != nil {
		return CategoryDocument{}, time.Time{}, fmt.Errorf("read node monitoring platform: %w", err)
	}
	var activeRevision *int64
	err = tx.QueryRow(ctx, `SELECT active_revision FROM system_configuration_streams
		WHERE platform_scope_id=$1 FOR SHARE`, platformScopeID).Scan(&activeRevision)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && activeRevision == nil {
		return CategoryDocument{}, time.Time{}, nil
	}
	if err != nil {
		return CategoryDocument{}, time.Time{}, fmt.Errorf("read active node monitoring stream: %w", err)
	}
	if *activeRevision < 1 {
		return CategoryDocument{}, time.Time{}, ErrInvalidInput
	}
	active, err := loadRevision(ctx, tx, platformScopeID, *activeRevision)
	if err != nil {
		return CategoryDocument{}, time.Time{}, fmt.Errorf("read active node monitoring revision: %w", err)
	}
	if active.Status != StatusActive || active.StateChangedAt.IsZero() {
		return CategoryDocument{}, time.Time{}, ErrInvalidInput
	}
	return CategoryDocument{
		Schema: canonicalSchema, Category: CategoryNodeMonitoring,
		HeadRevision: active.Revision, ActiveRevision: active.Revision, Revision: active.Revision,
		Status: StatusActive, SnapshotSHA256: active.SnapshotSHA256,
		Value: EffectiveNodeMonitoring(active.Configuration.NodeMonitoring),
	}, active.StateChangedAt, nil
}
