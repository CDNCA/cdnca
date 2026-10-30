package dnsreconcile

import (
	"context"
	"github.com/cdnca/cdnca/services/control-api/internal/installationlock"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TenantSource interface {
	PendingTenants(context.Context, int) ([]uuid.UUID, error)
}

type TenantRunner interface {
	RunOnce(context.Context, uuid.UUID, string, int) ([]Task, error)
}

type WorkerConfig struct {
	WorkerID     string
	TenantLimit  int
	ClaimLimit   int
	PollInterval time.Duration
}

type WorkerDependencies struct {
	Tenants TenantSource
	Runner  TenantRunner
}

type Worker struct {
	config  WorkerConfig
	tenants TenantSource
	runner  TenantRunner
}

func NewWorker(config WorkerConfig, dependencies WorkerDependencies) (*Worker, error) {
	if config.WorkerID == "" || config.TenantLimit < 1 || config.TenantLimit > 1000 ||
		config.ClaimLimit < 1 || config.ClaimLimit > 100 || config.PollInterval < 10*time.Millisecond ||
		config.PollInterval > time.Minute || dependencies.Tenants == nil || dependencies.Runner == nil {
		return nil, ErrInvalidInput
	}
	return &Worker{config: config, tenants: dependencies.Tenants, runner: dependencies.Runner}, nil
}

func (worker *Worker) RunOnce(ctx context.Context) error {
	if worker == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalidInput
	}
	tenants, err := worker.tenants.PendingTenants(ctx, worker.config.TenantLimit)
	if err != nil {
		return err
	}
	seen := make(map[uuid.UUID]struct{}, len(tenants))
	var firstErr error
	for _, tenantID := range tenants {
		if tenantID == uuid.Nil {
			return ErrUnavailable
		}
		if _, duplicate := seen[tenantID]; duplicate {
			return ErrUnavailable
		}
		seen[tenantID] = struct{}{}
		if err := ctx.Err(); err != nil {
			return err
		}
		_, tenantErr := worker.runner.RunOnce(ctx, tenantID, worker.config.WorkerID, worker.config.ClaimLimit)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if tenantErr != nil {
			if firstErr == nil {
				firstErr = tenantErr
			}
		}
	}
	return firstErr
}

func (worker *Worker) Run(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrInvalidInput
	}
	ticker := time.NewTicker(worker.config.PollInterval)
	defer ticker.Stop()
	for {
		if !installationlock.Skip("dns_reconcile") {
			// N20: a failed round was dropped without a log line.
			if err := worker.RunOnce(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("DNS reconcile round failed", "worker_id", worker.config.WorkerID, "error", err)
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type PostgresTenantSource struct{ pool *pgxpool.Pool }

func NewPostgresTenantSource(pool *pgxpool.Pool) (*PostgresTenantSource, error) {
	if pool == nil {
		return nil, ErrUnavailable
	}
	return &PostgresTenantSource{pool: pool}, nil
}

func (source *PostgresTenantSource) PendingTenants(ctx context.Context, limit int) ([]uuid.UUID, error) {
	if source == nil || source.pool == nil || ctx == nil || limit < 1 || limit > 1000 {
		return nil, ErrInvalidInput
	}
	rows, err := source.pool.Query(ctx, `
		SELECT DISTINCT tenant_id
		FROM background_jobs
		WHERE kind=$1 AND state IN ('queued','running') AND claimable_at <= clock_timestamp()
		ORDER BY tenant_id LIMIT $2`, JobKind, limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	result := make([]uuid.UUID, 0)
	for rows.Next() {
		var tenantID uuid.UUID
		if err := rows.Scan(&tenantID); err != nil || tenantID == uuid.Nil {
			return nil, ErrUnavailable
		}
		result = append(result, tenantID)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}
