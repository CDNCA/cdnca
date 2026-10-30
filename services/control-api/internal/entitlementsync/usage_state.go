package entitlementsync

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UsageReportState keeps, per installation, the highest sequence ever
// allocated and the one report the license service has not confirmed yet
// (migration 554, L08). A sequence is never reused across restarts or clock
// steps, and an unconfirmed report is resent byte for byte under its own
// Idempotency-Key before any newer round is built.
type UsageReportState interface {
	// Pending returns the unconfirmed report, if any.
	Pending(ctx context.Context, installationID uuid.UUID) (usageReport, bool, error)
	// Reserve stores the report build returns as the new pending one; build
	// gets the last allocated sequence. If another process stored a pending
	// report first, that one is returned instead (build is not used).
	Reserve(ctx context.Context, installationID uuid.UUID, build func(previous uint64) (usageReport, error), now time.Time) (usageReport, error)
	// Settle clears the pending report only if it is still this one, so a
	// late answer for an older round never clears a newer pending report.
	Settle(ctx context.Context, installationID uuid.UUID, report usageReport) error
}

// PostgresUsageState is the production UsageReportState (control_usage_report_state).
type PostgresUsageState struct{ pool *pgxpool.Pool }

func NewPostgresUsageState(pool *pgxpool.Pool) *PostgresUsageState {
	return &PostgresUsageState{pool: pool}
}

func (state *PostgresUsageState) Pending(ctx context.Context, installationID uuid.UUID) (usageReport, bool, error) {
	if state == nil || state.pool == nil {
		return usageReport{}, false, ErrInvalidConfiguration
	}
	return pendingUsageReport(ctx, state.pool, installationID, false)
}

type usageQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func pendingUsageReport(ctx context.Context, querier usageQuerier, installationID uuid.UUID, lock bool,
) (usageReport, bool, error) {
	query := `SELECT pending_sequence, pending_request_id, pending_lease_serial, pending_body
		FROM control_usage_report_state WHERE installation_id=$1 AND pending_sequence IS NOT NULL`
	if lock {
		query += ` FOR UPDATE`
	}
	var sequence, serial int64
	var report usageReport
	err := querier.QueryRow(ctx, query, installationID).Scan(&sequence, &report.requestID, &serial, &report.body)
	if errors.Is(err, pgx.ErrNoRows) {
		return usageReport{}, false, nil
	}
	if err != nil {
		return usageReport{}, false, fmt.Errorf("read pending usage report: %w", err)
	}
	report.sequence, report.leaseSerial, report.path = uint64(sequence), uint64(serial), usageReportPath(installationID)
	return report, true, nil
}

func (state *PostgresUsageState) Reserve(ctx context.Context, installationID uuid.UUID,
	build func(previous uint64) (usageReport, error), now time.Time,
) (usageReport, error) {
	if state == nil || state.pool == nil {
		return usageReport{}, ErrInvalidConfiguration
	}
	var reserved usageReport
	err := pgx.BeginFunc(ctx, state.pool, func(tx pgx.Tx) error {
		// The row lock serialises reporters of the same installation.
		if _, err := tx.Exec(ctx, `INSERT INTO control_usage_report_state(installation_id, last_sequence, updated_at)
			VALUES ($1, 0, $2) ON CONFLICT (installation_id) DO NOTHING`, installationID, now.UTC()); err != nil {
			return fmt.Errorf("create usage report state: %w", err)
		}
		if pending, found, err := pendingUsageReport(ctx, tx, installationID, true); err != nil || found {
			reserved = pending
			return err
		}
		var last int64
		if err := tx.QueryRow(ctx, `SELECT last_sequence FROM control_usage_report_state WHERE installation_id=$1`,
			installationID).Scan(&last); err != nil {
			return fmt.Errorf("read usage report sequence: %w", err)
		}
		report, err := build(uint64(last))
		if err != nil {
			return err
		}
		if report.sequence <= uint64(last) || report.sequence > math.MaxInt64 || report.leaseSerial > math.MaxInt64 {
			return fmt.Errorf("%w: usage report sequence %d after %d", ErrInvalidConfiguration, report.sequence, last)
		}
		if _, err := tx.Exec(ctx, `UPDATE control_usage_report_state SET last_sequence=$2, pending_sequence=$2,
			pending_request_id=$3, pending_lease_serial=$4, pending_body=$5, pending_created_at=$6, updated_at=$6
			WHERE installation_id=$1`, installationID, int64(report.sequence), report.requestID, int64(report.leaseSerial),
			report.body, now.UTC()); err != nil {
			return fmt.Errorf("store pending usage report: %w", err)
		}
		reserved = report
		return nil
	})
	return reserved, err
}

func (state *PostgresUsageState) Settle(ctx context.Context, installationID uuid.UUID, report usageReport) error {
	if state == nil || state.pool == nil {
		return ErrInvalidConfiguration
	}
	_, err := state.pool.Exec(ctx, `UPDATE control_usage_report_state SET pending_sequence=NULL, pending_request_id=NULL,
		pending_lease_serial=NULL, pending_body=NULL, pending_created_at=NULL, updated_at=now()
		WHERE installation_id=$1 AND pending_sequence=$2 AND pending_request_id=$3`,
		installationID, int64(report.sequence), report.requestID)
	if err != nil {
		return fmt.Errorf("settle usage report: %w", err)
	}
	return nil
}

// memoryUsageState is the in-process UsageReportState for tests; one value
// shared by several reporters behaves like one database across restarts.
type memoryUsageState struct {
	mu      sync.Mutex
	last    uint64
	pending *usageReport
	err     error
}

func (state *memoryUsageState) Pending(context.Context, uuid.UUID) (usageReport, bool, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.err != nil {
		return usageReport{}, false, state.err
	}
	if state.pending == nil {
		return usageReport{}, false, nil
	}
	return *state.pending, true, nil
}

func (state *memoryUsageState) Reserve(_ context.Context, _ uuid.UUID, build func(uint64) (usageReport, error), _ time.Time,
) (usageReport, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.err != nil {
		return usageReport{}, state.err
	}
	if state.pending != nil {
		return *state.pending, nil
	}
	report, err := build(state.last)
	if err != nil {
		return usageReport{}, err
	}
	if report.sequence <= state.last {
		return usageReport{}, ErrInvalidConfiguration
	}
	state.last, state.pending = report.sequence, &report
	return report, nil
}

func (state *memoryUsageState) Settle(_ context.Context, _ uuid.UUID, report usageReport) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.err != nil {
		return state.err
	}
	if state.pending != nil && state.pending.sequence == report.sequence && state.pending.requestID == report.requestID {
		state.pending = nil
	}
	return nil
}
