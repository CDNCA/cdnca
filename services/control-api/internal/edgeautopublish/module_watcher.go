package edgeautopublish

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ModuleEntitlementSourceID is the source resource of module_entitlement
// republication requests: the installation's lease, not a row of its own.
var ModuleEntitlementSourceID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("cdnca.entitlement.modules"))

// ModuleWatcher turns a change of the module codes the verified lease grants
// into publication state: a revoked module leaves the
// scopes whose latest publication uses it pending republication; a module
// granted again releases them and, once a scope has no pending module left,
// republishes it through the system channel (trigger module_entitlement).
// The first observed grant is recorded as the baseline.
type ModuleWatcher struct {
	pool         *pgxpool.Pool
	grants       edgepublish.ModuleGrantReader
	requirements []edgepublish.ModuleRequirement
	auditor      edgepublish.AuditAppender
	interval     time.Duration
	now          func() time.Time
	last         time.Time
}

func NewModuleWatcher(pool *pgxpool.Pool, grants edgepublish.ModuleGrantReader,
	requirements []edgepublish.ModuleRequirement, auditor edgepublish.AuditAppender, interval time.Duration,
) (*ModuleWatcher, error) {
	if pool == nil || grants == nil || auditor == nil || interval < 0 || interval > time.Hour {
		return nil, ErrInvalidInput
	}
	return &ModuleWatcher{pool: pool, grants: grants, requirements: slices.Clone(requirements), auditor: auditor,
		interval: interval, now: time.Now}, nil
}

// RunOnce sweeps at most once per interval (the runtime polls faster).
func (watcher *ModuleWatcher) RunOnce(ctx context.Context) (bool, error) {
	if watcher == nil || ctx == nil {
		return false, ErrInvalidInput
	}
	now := watcher.now()
	if !watcher.last.IsZero() && now.Sub(watcher.last) < watcher.interval {
		return false, nil
	}
	watcher.last = now
	result, err := watcher.SweepOnce(ctx)
	return len(result.Pending) > 0 || len(result.Republished) > 0, err
}

// ModuleSweepResult is what one sweep changed, in scope order.
type ModuleSweepResult struct {
	Revoked, Granted     []string
	Pending, Republished []uuid.UUID
}

// SweepOnce compares the lease's module grant with the last one acted on.
func (watcher *ModuleWatcher) SweepOnce(ctx context.Context) (ModuleSweepResult, error) {
	var result ModuleSweepResult
	err := pgx.BeginFunc(ctx, watcher.pool, func(tx pgx.Tx) error {
		result = ModuleSweepResult{}
		codes, err := watcher.grants.GrantedModuleCodes(ctx, tx)
		if err != nil {
			return err
		}
		codes = append([]string{}, slices.Compact(slices.Sorted(slices.Values(codes)))...)
		var previous []string
		err = tx.QueryRow(ctx, `SELECT module_codes FROM edge_module_grant_marks WHERE singleton FOR UPDATE`).Scan(&previous)
		first := errors.Is(err, pgx.ErrNoRows)
		if err != nil && !first {
			return err
		}
		if !first && slices.Equal(previous, codes) {
			return nil
		}
		for _, code := range previous {
			if !slices.Contains(codes, code) {
				result.Revoked = append(result.Revoked, code)
			}
		}
		for _, code := range codes {
			if first || !slices.Contains(previous, code) {
				result.Granted = append(result.Granted, code)
			}
		}
		if result.Pending, err = edgepublish.MarkModuleRevocationTx(ctx, tx, watcher.auditor, watcher.requirements,
			result.Revoked); err != nil {
			return err
		}
		scopes, err := edgepublish.ReleaseModuleHoldsTx(ctx, tx, watcher.auditor, result.Granted)
		if err != nil {
			return err
		}
		for _, scopeID := range scopes {
			if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
				ScopeID: scopeID, Trigger: edgepublish.SystemTriggerModuleEntitlement,
				SourceResourceID: ModuleEntitlementSourceID, SourceRequestID: "module-entitlement." + scopeID.String(),
				Immediate: true,
			}); err != nil {
				return err
			}
		}
		result.Republished = scopes
		_, err = tx.Exec(ctx, `INSERT INTO edge_module_grant_marks(singleton,module_codes,observed_at)
			VALUES(true,$1,clock_timestamp())
			ON CONFLICT (singleton) DO UPDATE SET module_codes=EXCLUDED.module_codes,observed_at=EXCLUDED.observed_at`,
			codes)
		return err
	})
	return result, err
}
