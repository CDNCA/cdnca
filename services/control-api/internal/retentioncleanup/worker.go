// Package retentioncleanup deletes history older than the platform retention
// settings (FX01). Deletes run as the dedicated NOLOGIN role
// cdnca_retention_cleanup, which the database only lets remove expired rows
// (migrations 320/331); every batch is recorded in the audit log. Audit
// history itself is archived with a chain checkpoint, never just deleted.
// ClickHouse access/blacklist/bandwidth history follows the settings through
// table TTLs (SyncClickHouseTTL).
package retentioncleanup

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// Role is the only database role allowed to delete expired history.
	Role = "cdnca_retention_cleanup"
	// AuditAction marks each committed cleanup batch.
	AuditAction = "system_cleanup.retention.delete"

	defaultBatchSize   = 1000
	defaultMaxBatches  = 100
	defaultBatchPause  = 200 * time.Millisecond
	advisoryLockKey    = 1_306_000_001
	nodeMetricsSetting = "node_metrics_days"
)

// ErrRoleUnavailable reports that the cleanup role is missing or not granted
// to the application login; nothing is deleted.
var ErrRoleUnavailable = errors.New("retention cleanup role is unavailable")

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

// target is one table pruned by a retention setting.
type target struct {
	table   string
	setting string
	// cutoffSQL returns the cutoff for setting $1 (NULL: keep forever).
	cutoffSQL string
	// deleteSQL removes at most $1 expired rows and returns the count; the
	// table's retention trigger (migrations 320/332) re-checks every row.
	// With selectSQL set, $1 is instead the selected ID array.
	deleteSQL string
	// selectSQL, when set, picks at most $1 expired IDs (uuid[]); childSQL
	// then deletes their child rows in order (children before the tables they
	// reference), deleteSQL and finalSQL the rows themselves (both counted).
	selectSQL string
	childSQL  []string
	finalSQL  string
}

const cleanupCacheSetting = "cleanup_cache_days"

// cacheOperationChildren deletes the rows of the selected cache operations
// child-first (migration 566 lets only the cleanup role do it, and only for
// operations that ended before the cutoff).
var cacheOperationChildren = []string{
	`DELETE FROM cache_operation_target_results WHERE operation_id = ANY($1)`,
	`DELETE FROM cache_operation_cancel_deliveries WHERE operation_id = ANY($1)`,
	`DELETE FROM cache_operation_node_attempts WHERE operation_id = ANY($1)`,
	`DELETE FROM cache_operation_node_targets WHERE operation_id = ANY($1)`,
	`DELETE FROM cache_operation_nodes WHERE operation_id = ANY($1)`,
	`DELETE FROM cache_operation_targets WHERE operation_id = ANY($1)`,
	`DELETE FROM cache_operation_commands WHERE operation_id = ANY($1)`,
}

var targets = []target{{
	table: "node_metric_samples", setting: nodeMetricsSetting,
	cutoffSQL: `SELECT retention_cleanup_cutoff_320($1)`,
	deleteSQL: `WITH expired AS (
		SELECT sample.event_id FROM node_metric_samples sample
		WHERE sample.observed_at < retention_cleanup_cutoff_320('node_metrics_days')
		  AND EXISTS (SELECT 1 FROM node_metric_samples newer
		      WHERE newer.node_id = sample.node_id AND newer.publication_sequence > sample.publication_sequence)
		ORDER BY sample.observed_at
		LIMIT $1)
	DELETE FROM node_metric_samples WHERE event_id IN (SELECT event_id FROM expired)`,
}, {
	// Node traffic history: keep each node's newest evaluation and every
	// evaluation a sync task still references.
	table: "node_traffic_policy_evaluations", setting: "node_traffic_history_days",
	cutoffSQL: `SELECT retention_cleanup_cutoff_331($1)`,
	deleteSQL: `WITH expired AS (
		SELECT evaluation.id FROM node_traffic_policy_evaluations evaluation
		WHERE evaluation.evaluated_at < retention_cleanup_cutoff_331('node_traffic_history_days')
		  AND EXISTS (SELECT 1 FROM node_traffic_policy_evaluations newer
		      WHERE newer.scope_id = evaluation.scope_id AND newer.node_id = evaluation.node_id
		        AND (newer.evaluated_at, newer.id) > (evaluation.evaluated_at, evaluation.id))
		  AND NOT EXISTS (SELECT 1 FROM node_traffic_sync_tasks task WHERE task.evaluation_id = evaluation.id)
		ORDER BY evaluation.evaluated_at
		LIMIT $1)
	DELETE FROM node_traffic_policy_evaluations WHERE id IN (SELECT id FROM expired)`,
}, {
	// 清缓存历史（cleanup_cache_days）：已结束且早于期限、没有未完成命令的
	// 缓存操作。自动节点的后续操作以 RESTRICT 外键指向父操作，所以父操作
	// 只在其后续操作也都过期时入选，并与它们同批删除。
	table: "cache_operations", setting: cleanupCacheSetting,
	cutoffSQL: `SELECT retention_cleanup_cutoff_566($1)`,
	selectSQL: `WITH picked AS (
		SELECT operation.id FROM cache_operations operation
		WHERE operation.state IN ('succeeded', 'partial_failed', 'failed', 'cancelled')
		  AND operation.completed_at < retention_cleanup_cutoff_566('cleanup_cache_days')
		  AND NOT EXISTS (SELECT 1 FROM cache_operation_commands command
		      WHERE command.operation_id = operation.id AND command.completed_at IS NULL)
		  AND NOT EXISTS (SELECT 1 FROM cache_operations child
		      WHERE child.parent_operation_id = operation.id AND NOT cache_operation_retention_expired_566(child.id))
		ORDER BY operation.completed_at, operation.id
		LIMIT $1)
	SELECT COALESCE(array_agg(id), '{}') FROM (
		SELECT id FROM picked
		UNION SELECT child.id FROM cache_operations child JOIN picked ON child.parent_operation_id = picked.id) selected`,
	childSQL: cacheOperationChildren,
	// 后续操作先删，父操作随后（RESTRICT 外键不等到语句结束）。
	deleteSQL: `DELETE FROM cache_operations WHERE id = ANY($1) AND parent_operation_id IS NOT NULL`,
	finalSQL:  `DELETE FROM cache_operations WHERE id = ANY($1)`,
}, {
	// 解锁 IP 历史（cleanup_cache_days）：已解除且出了 7 天释放下发窗口、
	// 或未解除但封禁已在期限前到期的记录。
	table: "security_ban_entries", setting: cleanupCacheSetting,
	cutoffSQL: `SELECT retention_cleanup_cutoff_566($1)`,
	deleteSQL: `WITH expired AS (
		SELECT entry.id FROM security_ban_entries entry
		WHERE (entry.released_at IS NOT NULL AND entry.released_at < least(
		          retention_cleanup_cutoff_566('cleanup_cache_days'), transaction_timestamp() - interval '7 days'))
		   OR (entry.released_at IS NULL AND entry.banned_until < retention_cleanup_cutoff_566('cleanup_cache_days'))
		ORDER BY COALESCE(entry.released_at, entry.banned_until), entry.id
		LIMIT $1)
	DELETE FROM security_ban_entries WHERE id IN (SELECT id FROM expired)`,
}}

type Config struct {
	BatchSize  int
	MaxBatches int
	BatchPause time.Duration
	Logger     *slog.Logger
	// ClickHouse, when set, makes the analytics history TTLs follow the
	// cleanup settings (see SyncClickHouseTTL).
	ClickHouse ClickHouse
}

type Worker struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	config  Config
}

func NewWorker(pool *pgxpool.Pool, auditor AuditAppender, config Config) (*Worker, error) {
	if pool == nil || auditor == nil {
		return nil, errors.New("retention cleanup worker requires a pool and an auditor")
	}
	if config.BatchSize <= 0 {
		config.BatchSize = defaultBatchSize
	}
	if config.MaxBatches <= 0 {
		config.MaxBatches = defaultMaxBatches
	}
	if config.BatchPause < 0 {
		config.BatchPause = 0
	} else if config.BatchPause == 0 {
		config.BatchPause = defaultBatchPause
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Worker{pool: pool, auditor: auditor, config: config}, nil
}

// Result is the per-table outcome of one run.
type Result struct {
	Table    string
	Deleted  int64
	Archived int64 // audit_events rows copied to audit_event_archive
	Err      error
}

// RunOnce prunes every target, then archives expired audit history; a failing
// table is logged and the next one still runs.
func (worker *Worker) RunOnce(ctx context.Context) []Result {
	results := make([]Result, 0, len(targets))
	for _, item := range targets {
		deleted, err := worker.prune(ctx, item)
		if err != nil && ctx.Err() == nil {
			worker.config.Logger.Warn("retention cleanup failed", "table", item.table, "deleted", deleted, "error", err)
		}
		results = append(results, Result{Table: item.table, Deleted: deleted, Err: err})
	}
	archive := worker.archiveAudit(ctx)
	if archive.Err != nil && ctx.Err() == nil {
		worker.config.Logger.Warn("retention cleanup failed", "table", archive.Table, "archived", archive.Archived,
			"deleted", archive.Deleted, "error", archive.Err)
	}
	results = append(results, archive)
	if worker.config.ClickHouse != nil {
		_, err := worker.SyncClickHouseTTL(ctx)
		if err != nil && ctx.Err() == nil {
			worker.config.Logger.Warn("retention cleanup failed", "table", clickHouseTTLTable, "error", err)
		}
		results = append(results, Result{Table: clickHouseTTLTable, Err: err})
	}
	return results
}

// Run prunes once per interval until ctx ends.
func (worker *Worker) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		worker.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (worker *Worker) prune(ctx context.Context, item target) (int64, error) {
	var total int64
	for batch := 0; batch < worker.config.MaxBatches; batch++ {
		deleted, err := worker.batch(ctx, item)
		total += deleted
		if err != nil || deleted < int64(worker.config.BatchSize) {
			return total, err
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(worker.config.BatchPause):
		}
	}
	return total, nil
}

func (worker *Worker) batch(ctx context.Context, item target) (int64, error) {
	var deleted int64
	err := pgx.BeginFunc(ctx, worker.pool, func(tx pgx.Tx) error {
		var locked, member bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1),
			CASE WHEN to_regrole($2) IS NULL THEN false ELSE pg_has_role(current_user, $2, 'MEMBER') END`,
			advisoryLockKey, Role).Scan(&locked, &member); err != nil {
			return err
		}
		if !member {
			return ErrRoleUnavailable
		}
		if !locked {
			return nil
		}
		var cutoff *time.Time
		if err := tx.QueryRow(ctx, item.cutoffSQL, item.setting).Scan(&cutoff); err != nil {
			return err
		}
		if cutoff == nil {
			return nil
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+Role); err != nil {
			return err
		}
		count, err := deleteExpired(ctx, tx, item, worker.config.BatchSize)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "RESET ROLE"); err != nil {
			return err
		}
		deleted = count
		if deleted == 0 {
			return nil
		}
		scopeID, err := platformAuditScope(ctx, tx)
		if err != nil {
			return err
		}
		return worker.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: AuditAction, ResourceType: "retention_table", ResourceID: item.table,
			RequestID: "retention-" + uuid.NewString(), Result: "success",
			Payload: map[string]any{"table": item.table, "setting": item.setting, "cutoff": cutoff.UTC().Format(time.RFC3339Nano),
				"deleted": deleted},
		})
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// execer is the part of pgx.Tx deleteExpired uses.
type execer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// deleteExpired runs one batch of item as the cleanup role and returns how
// many rows of item.table it removed. A target with selectSQL picks the IDs
// first and deletes their child rows before the rows themselves.
func deleteExpired(ctx context.Context, tx execer, item target, batchSize int) (int64, error) {
	if item.selectSQL == "" {
		command, err := tx.Exec(ctx, item.deleteSQL, batchSize)
		return command.RowsAffected(), err
	}
	var ids []uuid.UUID
	if err := tx.QueryRow(ctx, item.selectSQL, batchSize).Scan(&ids); err != nil || len(ids) == 0 {
		return 0, err
	}
	for _, statement := range item.childSQL {
		if _, err := tx.Exec(ctx, statement, ids); err != nil {
			return 0, err
		}
	}
	var deleted int64
	for _, statement := range []string{item.deleteSQL, item.finalSQL} {
		command, err := tx.Exec(ctx, statement, ids)
		if err != nil {
			return 0, err
		}
		deleted += command.RowsAffected()
	}
	return deleted, nil
}
