package cachecontrol

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Daily purge/prewarm quotas count per account (fix-cachequota, user 10-28):
// an account is a tenant scope, so the tenant owner and its members share one
// quota, and a platform administrator's operations on the tenant's sites count
// toward it too. The limits are the system settings defaults (resource limits:
// daily URL purges, directory purges, prewarms) unless an administrator set
// the account's own limit (cache_operation_account_quotas, NULL = default).
// The day is the calendar day in UTC+8 (the control plane's Beijing time);
// targets of the user operations created that day count whatever their state.
// System follow-ups for nodes that start carrying a site (SyncCarryingNodes,
// parent_operation_id set) do not count (Q6). A whole-site purge counts as one
// directory purge.

// dailyLimitLocation is the day the daily limits count in.
var dailyLimitLocation = time.FixedZone("UTC+8", 8*3600)

// Maximum account limits, the same as the system settings ranges.
const (
	maxAccountURLPurgeLimit       = 10_000_000
	maxAccountDirectoryPurgeLimit = 1_000_000
	maxAccountPrewarmLimit        = 10_000_000
)

// Quota names a daily quota in errors and requests.
type Quota string

const (
	QuotaURLPurge       Quota = "url_purge"
	QuotaDirectoryPurge Quota = "directory_purge"
	QuotaPrewarm        Quota = "prewarm"
)

// DailyLimitError is the ErrDailyLimitExceeded refusal of a create: which
// quota, its limit, what the account used today and what the create asked for.
type DailyLimitError struct {
	Quota     Quota
	Limit     int
	Used      int
	Requested int
}

func (err *DailyLimitError) Error() string {
	return fmt.Sprintf("cache operation daily %s limit exceeded: limit %d, used %d, requested %d",
		err.Quota, err.Limit, err.Used, err.Requested)
}

func (err *DailyLimitError) Unwrap() error { return ErrDailyLimitExceeded }

// AccountLimits are an account's own limits; nil follows the default.
type AccountLimits struct {
	URLPurge       *int `json:"url_purge_limit"`
	DirectoryPurge *int `json:"directory_purge_limit"`
	Prewarm        *int `json:"prewarm_limit"`
}

// DailyQuota is one daily limit of an account: the limit a create is checked
// against (the account's own limit, else the default) and today's count.
type DailyQuota struct {
	Limit        int  `json:"limit"`
	Used         int  `json:"used"`
	Remaining    int  `json:"remaining"`
	DefaultLimit int  `json:"default_limit"`
	Override     *int `json:"override"`
}

// DailyUsage is an account's cache operation quotas for the current UTC+8
// day. Revision is the account limits' revision (0 = never set), the
// expected_revision of the next SetAccountLimits.
type DailyUsage struct {
	ScopeID        uuid.UUID  `json:"scope_id"`
	URLPurge       DailyQuota `json:"url_purge"`
	DirectoryPurge DailyQuota `json:"directory_purge"`
	Prewarm        DailyQuota `json:"prewarm"`
	ResetsAt       time.Time  `json:"resets_at"`
	Revision       int64      `json:"revision"`
}

// SetAccountLimitsRequest replaces the account's own limits.
type SetAccountLimitsRequest struct {
	ExpectedRevision int64
	Limits           AccountLimits
	RequestID        string
}

func dailyLimitDayStart(now time.Time) time.Time {
	local := now.In(dailyLimitLocation)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, dailyLimitLocation)
}

// quotaOf is the quota an operation kind counts toward and the
// action:target_type pairs that share it.
func quotaOf(action Action, targetType TargetType) (Quota, []string) {
	switch {
	case action == ActionPrewarm:
		return QuotaPrewarm, []string{string(ActionPrewarm) + ":" + string(TargetExactURL)}
	case targetType == TargetExactURL:
		return QuotaURLPurge, []string{string(ActionPurge) + ":" + string(TargetExactURL)}
	default:
		return QuotaDirectoryPurge, []string{
			string(ActionPurge) + ":" + string(TargetDirectoryPrefix), string(ActionPurge) + ":" + string(TargetWholeSite),
		}
	}
}

// effectiveLimit is the quota's default and the account's own limit.
func effectiveLimit(defaults systemconfig.ResourceLimits, own AccountLimits, quota Quota) (int, *int) {
	switch quota {
	case QuotaPrewarm:
		return defaults.DailyPrewarmLimit, own.Prewarm
	case QuotaURLPurge:
		return defaults.DailyURLPurgeLimit, own.URLPurge
	default:
		return defaults.DailyDirectoryPurgeLimit, own.DirectoryPurge
	}
}

func quotaView(defaultLimit int, override *int, used int) DailyQuota {
	limit := defaultLimit
	if override != nil {
		limit = *override
	}
	return DailyQuota{Limit: limit, Used: used, Remaining: max(limit-used, 0), DefaultLimit: defaultLimit, Override: override}
}

// countsTowardsDailyLimit: the tenant's own sessions (owner and members, all
// authenticated in the tenant scope) share its quota; a platform administrator
// submitting on the tenant's behalf (authenticated in the platform scope) is
// neither counted nor refused by it. Only platform sessions may
// target another scope (iamlock), so a differing actor scope is the platform.
func countsTowardsDailyLimit(actor Actor) bool {
	return actor.ActorScopeID == actor.ScopeID
}

// checkDailyLimit refuses an operation that would take the account past its
// daily limit for the operation's kind.
func checkDailyLimit(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, action Action,
	targetType TargetType, targets int, now time.Time) error {
	quota, kinds := quotaOf(action, targetType)
	// One lock per account and quota: concurrent creates of one account count
	// each other's targets.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"cache-daily-limit:"+scopeID.String()+":"+string(quota)); err != nil {
		return fmt.Errorf("lock cache operation daily limit: %w", err)
	}
	defaults, err := loadDailyLimits(ctx, tx)
	if err != nil {
		return err
	}
	own, _, err := loadAccountLimits(ctx, tx, scopeID)
	if err != nil {
		return err
	}
	defaultLimit, override := effectiveLimit(defaults, own, quota)
	limit := defaultLimit
	if override != nil {
		limit = *override
	}
	used, err := dailyUsed(ctx, tx, scopeID, kinds, dailyLimitDayStart(now))
	if err != nil {
		return err
	}
	if used+targets > limit {
		return &DailyLimitError{Quota: quota, Limit: limit, Used: used, Requested: targets}
	}
	return nil
}

// loadDailyLimits is the platform's effective resource limits (the
// bootstrap ones without an active platform configuration).
func loadDailyLimits(ctx context.Context, tx pgx.Tx) (systemconfig.ResourceLimits, error) {
	limits := systemconfig.ProjectBootstrapConfiguration().Resources
	var platform bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM access_scopes
		WHERE kind='platform' AND tenant_id IS NULL)`).Scan(&platform); err != nil {
		return limits, fmt.Errorf("read cache operation platform scope: %w", err)
	}
	if platform {
		resources, err := systemconfig.LoadEffectivePlatformResources(ctx, tx, systemconfig.EffectiveResourceTarget{})
		if err != nil {
			return limits, fmt.Errorf("read cache operation daily limits: %w", err)
		}
		limits = resources.Resources
	}
	return limits, nil
}

// loadAccountLimits is the account's own limits and their revision (0 and
// all defaults when never set).
func loadAccountLimits(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (AccountLimits, int64, error) {
	var own AccountLimits
	var revision int64
	err := tx.QueryRow(ctx, `SELECT url_purge_limit,directory_purge_limit,prewarm_limit,revision
		FROM cache_operation_account_quotas WHERE scope_id=$1`, scopeID).Scan(
		&own.URLPurge, &own.DirectoryPurge, &own.Prewarm, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return AccountLimits{}, 0, nil
	}
	if err != nil {
		return AccountLimits{}, 0, fmt.Errorf("read cache operation account limits: %w", err)
	}
	return own, revision, nil
}

// dailyUsed counts the targets of the account's own operations of the kinds
// that day (system follow-ups excluded, Q6; platform submissions on the
// tenant's behalf excluded, fix-cachequota2).
func dailyUsed(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, kinds []string, dayStart time.Time) (int, error) {
	var used int
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(sum(target_count),0)::integer FROM cache_operations
		WHERE scope_id=$1 AND created_at >= $2 AND created_at < $3
		  AND parent_operation_id IS NULL AND actor_scope_id=scope_id AND action || ':' || target_type = ANY($4)`,
		scopeID, dayStart, dayStart.AddDate(0, 0, 1), kinds).Scan(&used); err != nil {
		return 0, fmt.Errorf("count cache operation daily use: %w", err)
	}
	return used, nil
}

func readDailyUsage(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, now time.Time) (DailyUsage, error) {
	defaults, err := loadDailyLimits(ctx, tx)
	if err != nil {
		return DailyUsage{}, err
	}
	own, revision, err := loadAccountLimits(ctx, tx, scopeID)
	if err != nil {
		return DailyUsage{}, err
	}
	dayStart := dailyLimitDayStart(now)
	result := DailyUsage{ScopeID: scopeID, ResetsAt: dayStart.AddDate(0, 0, 1).UTC(), Revision: revision}
	for _, item := range []struct {
		quota       Quota
		action      Action
		targetType  TargetType
		destination *DailyQuota
	}{
		{QuotaURLPurge, ActionPurge, TargetExactURL, &result.URLPurge},
		{QuotaDirectoryPurge, ActionPurge, TargetDirectoryPrefix, &result.DirectoryPurge},
		{QuotaPrewarm, ActionPrewarm, TargetExactURL, &result.Prewarm},
	} {
		_, kinds := quotaOf(item.action, item.targetType)
		used, err := dailyUsed(ctx, tx, scopeID, kinds, dayStart)
		if err != nil {
			return DailyUsage{}, err
		}
		defaultLimit, override := effectiveLimit(defaults, own, item.quota)
		*item.destination = quotaView(defaultLimit, override, used)
	}
	return result, nil
}

// DailyUsage reads the actor scope's account quotas: the reader needs
// sites.read on the tenant scope (a platform administrator reading a
// tenant's quotas, platform.admin).
func (store *Store) DailyUsage(ctx context.Context, actor Actor) (DailyUsage, error) {
	if ctx == nil || !validActor(actor) {
		return DailyUsage{}, ErrInvalidInput
	}
	var result DailyUsage
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if _, err := store.authorizeActor(ctx, tx, actor, "sites.read"); err != nil {
			return err
		}
		var err error
		result, err = readDailyUsage(ctx, tx, actor.ScopeID, store.timestamp())
		return err
	})
	return result, err
}

func validAccountLimits(limits AccountLimits) bool {
	for _, item := range []struct {
		value   *int
		maximum int
	}{
		{limits.URLPurge, maxAccountURLPurgeLimit},
		{limits.DirectoryPurge, maxAccountDirectoryPurgeLimit},
		{limits.Prewarm, maxAccountPrewarmLimit},
	} {
		if item.value != nil && (*item.value < 0 || *item.value > item.maximum) {
			return false
		}
	}
	return true
}

// SetAccountLimits replaces a tenant account's own daily limits (nil =
// follow the default) and returns the account's quotas after the change. A
// platform administrator with identity.users.manage (or platform.admin)
// writes it; ExpectedRevision is the DailyUsage revision it read. The change
// is audited as cache.account_quota.update with the before/after limits.
func (store *Store) SetAccountLimits(ctx context.Context, actor Actor, request SetAccountLimitsRequest) (DailyUsage, error) {
	if ctx == nil || !validActor(actor) || actor.ActorScopeID == actor.ScopeID || request.ExpectedRevision < 0 ||
		!validAccountLimits(request.Limits) || !validSafeText(request.RequestID, 128) {
		return DailyUsage{}, ErrInvalidInput
	}
	var result DailyUsage
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorizeActor(ctx, tx, actor, accountQuotaManagePermission); err != nil {
			return err
		}
		// The account's quota locks: a concurrent create is checked against
		// the limits before or after this change, never a mix.
		for _, quota := range []Quota{QuotaURLPurge, QuotaDirectoryPurge, QuotaPrewarm} {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
				"cache-daily-limit:"+actor.ScopeID.String()+":"+string(quota)); err != nil {
				return fmt.Errorf("lock cache operation daily limit: %w", err)
			}
		}
		previous, revision, err := loadAccountLimits(ctx, tx, actor.ScopeID)
		if err != nil {
			return err
		}
		if revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		now := store.timestamp()
		if _, err := tx.Exec(ctx, `
			INSERT INTO cache_operation_account_quotas
			    (scope_id,url_purge_limit,directory_purge_limit,prewarm_limit,revision,updated_by_user_id,updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (scope_id) DO UPDATE SET url_purge_limit=EXCLUDED.url_purge_limit,
			    directory_purge_limit=EXCLUDED.directory_purge_limit, prewarm_limit=EXCLUDED.prewarm_limit,
			    revision=EXCLUDED.revision, updated_by_user_id=EXCLUDED.updated_by_user_id, updated_at=EXCLUDED.updated_at`,
			actor.ScopeID, request.Limits.URLPurge, request.Limits.DirectoryPurge, request.Limits.Prewarm,
			revision+1, actor.UserID, now.UTC()); err != nil {
			return fmt.Errorf("write cache operation account limits: %w", err)
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: accountQuotaUpdateAction,
			ResourceType: "cache_account_quota", ResourceID: actor.ScopeID.String(),
			RequestID: request.RequestID, Result: "success",
			Changes: accountLimitChanges(previous, request.Limits),
			Payload: map[string]any{
				"actor_scope_id": actor.ActorScopeID.String(), "previous_revision": revision, "revision": revision + 1,
			},
		}); err != nil {
			return err
		}
		result, err = readDailyUsage(ctx, tx, actor.ScopeID, now)
		return err
	})
	return result, err
}

const (
	accountQuotaUpdateAction     = "cache.account_quota.update"
	accountQuotaManagePermission = "identity.users.manage"
)

// accountLimitChanges is the audit summary: every limit with its before and
// after value (nil = follows the default).
func accountLimitChanges(before, after AccountLimits) []audit.Change {
	value := func(limit *int) any {
		if limit == nil {
			return nil
		}
		return *limit
	}
	return []audit.Change{
		{Field: "url_purge_limit", Before: value(before.URLPurge), After: value(after.URLPurge)},
		{Field: "directory_purge_limit", Before: value(before.DirectoryPurge), After: value(after.DirectoryPurge)},
		{Field: "prewarm_limit", Before: value(before.Prewarm), After: value(after.Prewarm)},
	}
}
