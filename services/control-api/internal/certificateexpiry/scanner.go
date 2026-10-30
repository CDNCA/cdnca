// Package certificateexpiry records when the certificate a tenant is serving
// approaches or reaches its expiry. Each (certificate version, stage) is
// written once to certificate_expiry_facts_371; that insert appends the
// public io.cdnca.certificate.v1.expiry_reached domain event and an audit
// event in the same transaction, so plugins and the log center see one fact
// per stage no matter how often or on how many control nodes the scan runs.
package certificateexpiry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Stage names, nearest-to-expiry last. They match migration 371.
const (
	StageExpiring30d = "expiring_30d"
	StageExpiring7d  = "expiring_7d"
	StageExpiring1d  = "expiring_1d"
	StageExpired     = "expired"
)

const (
	AuditAction  = "certificate.asset.expiry_reached"
	auditJobRef  = "job:certificate-expiry-scan"
	maxBatchSize = 500
)

type stage struct {
	name   string
	before time.Duration
}

// stages are checked from the nearest threshold: a certificate first seen
// already 3 days from expiry records expiring_7d only, not the 30-day notice.
var stages = []stage{
	{StageExpired, 0},
	{StageExpiring1d, 24 * time.Hour},
	{StageExpiring7d, 7 * 24 * time.Hour},
	{StageExpiring30d, 30 * 24 * time.Hour},
}

// Fact is one recorded expiry stage.
type Fact struct {
	TenantScopeID, AssetID, VersionID uuid.UUID
	Stage                             string
	NotAfter                          time.Time
}

type Scanner struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
	batch   int
	notices NoticeEnqueuer
}

// NoticeEnqueuer is notification.Store.
type NoticeEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// EnableNotices makes each recorded stage notify the certificate owner
// (certificate.expiring / certificate.expired, migration 371). Call before Run.
func (scanner *Scanner) EnableNotices(enqueuer NoticeEnqueuer) {
	scanner.notices = enqueuer
}

func New(pool *pgxpool.Pool, now func() time.Time) (*Scanner, error) {
	if pool == nil || now == nil {
		return nil, errors.New("certificate expiry scanner requires a PostgreSQL pool and clock")
	}
	return &Scanner{pool: pool, auditor: audit.NewWithClock(pool, now), now: now, batch: maxBatchSize}, nil
}

// StageAt is the nearest stage reached at now, or "" when more than 30 days remain.
func StageAt(notAfter, now time.Time) string {
	for _, candidate := range stages {
		if !now.Before(notAfter.Add(-candidate.before)) {
			return candidate.name
		}
	}
	return ""
}

type candidate struct {
	tenantScopeID, assetID, versionID uuid.UUID
	notAfter                          time.Time
	source                            string
}

// RunOnce records every stage newly reached by an in-use certificate version
// and returns the facts it wrote. A version is in use when it is its asset's
// latest activation, not revoked, and the asset is not deleted.
func (scanner *Scanner) RunOnce(ctx context.Context) ([]Fact, error) {
	now := scanner.now().UTC().Truncate(time.Microsecond)
	rows, err := scanner.pool.Query(ctx, `
		WITH active AS (
			SELECT DISTINCT ON (fact.tenant_scope_id, fact.asset_id)
				fact.tenant_scope_id, fact.asset_id, fact.version_id
			FROM certificate_asset_activation_facts fact
			ORDER BY fact.tenant_scope_id, fact.asset_id, fact.sequence DESC
		)
		SELECT v.tenant_scope_id, v.asset_id, v.id, v.not_after, asset.source
		FROM active
		JOIN certificate_asset_versions v ON v.tenant_scope_id=active.tenant_scope_id
			AND v.asset_id=active.asset_id AND v.id=active.version_id
		JOIN certificate_assets asset ON asset.tenant_scope_id=v.tenant_scope_id AND asset.id=v.asset_id
		WHERE asset.deleted_at IS NULL AND v.not_after <= $1::timestamptz + interval '30 days'
		  AND NOT EXISTS (SELECT 1 FROM certificate_asset_revocation_facts revoked
			WHERE revoked.tenant_scope_id=v.tenant_scope_id AND revoked.asset_id=v.asset_id
			  AND revoked.version_id=v.id)
		  AND NOT EXISTS (SELECT 1 FROM certificate_expiry_facts_371 fact
			WHERE fact.tenant_scope_id=v.tenant_scope_id AND fact.version_id=v.id AND fact.stage=CASE
				WHEN v.not_after <= $1 THEN 'expired'
				WHEN v.not_after <= $1::timestamptz + interval '1 day' THEN 'expiring_1d'
				WHEN v.not_after <= $1::timestamptz + interval '7 days' THEN 'expiring_7d'
				ELSE 'expiring_30d' END)
		ORDER BY v.not_after, v.tenant_scope_id, v.id
		LIMIT $2`, now, scanner.batch)
	if err != nil {
		return nil, fmt.Errorf("list certificate expiry candidates: %w", err)
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidate, error) {
		var item candidate
		err := row.Scan(&item.tenantScopeID, &item.assetID, &item.versionID, &item.notAfter, &item.source)
		return item, err
	})
	if err != nil {
		return nil, fmt.Errorf("read certificate expiry candidates: %w", err)
	}
	facts := make([]Fact, 0, len(candidates))
	for _, item := range candidates {
		fact, recorded, err := scanner.record(ctx, item, now)
		if err != nil {
			return facts, err
		}
		if recorded {
			facts = append(facts, fact)
		}
	}
	return facts, nil
}

func (scanner *Scanner) record(ctx context.Context, item candidate, now time.Time) (Fact, bool, error) {
	fact := Fact{TenantScopeID: item.tenantScopeID, AssetID: item.assetID, VersionID: item.versionID,
		Stage: StageAt(item.notAfter, now), NotAfter: item.notAfter}
	if fact.Stage == "" {
		return Fact{}, false, nil
	}
	recorded := false
	err := pgx.BeginFunc(ctx, scanner.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO certificate_expiry_facts_371(
				tenant_scope_id,asset_id,version_id,stage,not_after,observed_at)
			VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			fact.TenantScopeID, fact.AssetID, fact.VersionID, fact.Stage, fact.NotAfter, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil // another control node recorded it first
		}
		recorded = true
		scanner.notify(ctx, tx, fact, now)
		return scanner.auditor.Append(ctx, tx, audit.Event{
			ScopeID: fact.TenantScopeID, Action: AuditAction, ResourceType: "certificate_asset",
			ResourceID: fact.AssetID.String(), RequestID: "certificate-expiry:" + fact.VersionID.String() + ":" + fact.Stage,
			Result: "success", ActorKind: audit.ActorSystem, ActorRef: auditJobRef, OccurredAt: now,
			Payload: map[string]any{"version_id": fact.VersionID.String(), "stage": fact.Stage,
				"not_after": fact.NotAfter.UTC().Format(time.RFC3339), "source": item.source},
		})
	})
	if err != nil {
		return Fact{}, false, fmt.Errorf("record certificate expiry %s/%s: %w", fact.VersionID, fact.Stage, err)
	}
	return fact, recorded, nil
}

// Run scans every interval until ctx ends; errors are logged and retried.
func (scanner *Scanner) Run(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	for {
		facts, err := scanner.RunOnce(ctx)
		if err != nil && ctx.Err() == nil {
			logger.Warn("certificate expiry scan failed", "error", err)
		}
		delay := interval
		if err == nil && len(facts) == scanner.batch {
			delay = 0 // a full batch: more may be due
		}
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		} else if ctx.Err() != nil {
			return
		}
	}
}
