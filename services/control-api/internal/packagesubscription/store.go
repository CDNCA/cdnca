package packagesubscription

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cdnca/cdnca/services/control-api/internal/bridgeauth"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/packageautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	operationOpen    = "package.subscription.open"
	operationRenew   = "package.subscription.renew"
	operationCancel  = "package.subscription.cancel"
	permissionRead   = "package_subscriptions.read"
	permissionManage = "package_subscriptions.manage"
	// PermissionResellerCustomersManage lets a reseller act on its customers'
	// subscriptions (same name as packagecommerce's).
	PermissionResellerCustomersManage = "reseller.customers.manage"
	operationSuspend                  = "package.subscription.suspend"
	operationUnsuspend                = "package.subscription.unsuspend"
	auditSuspended                    = "package_subscription.suspended"
	auditUnsuspended                  = "package_subscription.unsuspended"
	maxMoneyMinor                     = int64(1_000_000_000_000_000)
)

type productPrices struct {
	month   int64
	quarter int64
	year    int64
}

func (prices productPrices) forDuration(duration packageperiod.Duration) (int64, error) {
	switch duration {
	case packageperiod.DurationMonth:
		return prices.month, nil
	case packageperiod.DurationQuarter:
		return prices.quarter, nil
	case packageperiod.DurationYear:
		return prices.year, nil
	default:
		return 0, ErrInvalidInput
	}
}

type auditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Store struct {
	pool    *pgxpool.Pool
	auditor auditAppender
	now     func() time.Time
	// cancelTx runs in the cancel transaction (CNAME owner retirement,
	// cnameallocation.RetireSubscriptionOwnersTx; injected: import cycle).
	cancelTx func(ctx context.Context, tx pgx.Tx, tenantScopeID, subscriptionID uuid.UUID, now time.Time) error
	// republishTx republishes the scope at once after a suspension change
	// (edgeautopublish.RequestPackageSuspensionRepublicationTx; injected: import cycle).
	republishTx func(ctx context.Context, tx pgx.Tx, tenantScopeID, subscriptionID uuid.UUID, fromRevision int64,
		suspend bool, requestID string) error
}

// WithSuspensionRepublishTx sets the republication Suspend runs in its transaction.
func (s *Store) WithSuspensionRepublishTx(fn func(ctx context.Context, tx pgx.Tx, tenantScopeID, subscriptionID uuid.UUID,
	fromRevision int64, suspend bool, requestID string) error) *Store {
	s.republishTx = fn
	return s
}

// WithCancelTx sets the step Cancel runs in its transaction.
func (s *Store) WithCancelTx(fn func(ctx context.Context, tx pgx.Tx, tenantScopeID, subscriptionID uuid.UUID, now time.Time) error) *Store {
	s.cancelTx = fn
	return s
}

type rowScanner interface {
	Scan(dest ...any) error
}

type storedWrite struct {
	response []byte
	found    bool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return NewStoreWithClock(pool, time.Now)
}

func NewStoreWithClock(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.New(pool), now: now}
}

func (s *Store) Get(ctx context.Context, actor Actor, tenantScopeID, subscriptionID uuid.UUID) (Subscription, error) {
	var subscription Subscription
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		if err := authorizeActor(ctx, tx, actor, tenantScopeID, permissionRead, now); err != nil {
			return err
		}
		var err error
		subscription, err = scanSubscription(tx.QueryRow(ctx, subscriptionSelect+`
			WHERE tenant_scope_id = $1 AND id = $2`, tenantScopeID, subscriptionID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err == nil {
			subscription.Quotas.Domains, subscription.Quotas.TrafficBytes, err = packageaddon.EffectiveCounts(ctx, tx, subscriptionID, now, subscription.Quotas.Domains, subscription.Quotas.TrafficBytes)
		}
		return err
	})
	if err != nil {
		return Subscription{}, fmt.Errorf("get package subscription: %w", err)
	}
	return subscription, nil
}

func (s *Store) Open(ctx context.Context, actor Actor, request OpenRequest, digest [32]byte) (MutationResult, error) {
	var result MutationResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		if err := authorizeActor(ctx, tx, actor, request.TenantScopeID, permissionManage, now); err != nil {
			return err
		}
		if err := verifySubscriptionOwner(ctx, tx, request.TenantScopeID, request.OwnerUserID); err != nil {
			return err
		}
		write, err := s.replayOrClaim(ctx, tx, actor, request.TenantScopeID, operationOpen,
			request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if write.found {
			return decodeReplay(write.response, &result)
		}
		product, domains, traffic, prices, err := loadProductSnapshot(ctx, tx, request.ProductID, request.ProductRevision)
		if err != nil {
			return err
		}
		location, err := loadIANAZone(request.TimeZone)
		if err != nil {
			return err
		}
		validity, err := packageperiod.NewValidity(now, location, request.Terms)
		if err != nil {
			return ErrInvalidInput
		}
		subscriptionID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		subscription := Subscription{
			ID: subscriptionID, TenantScopeID: request.TenantScopeID, Product: product,
			Quotas: QuotaSnapshot{Sites: request.SiteLimit, Domains: domains, Nodes: request.NodeLimit, TrafficBytes: traffic},
			Period: PeriodSnapshot{
				StartsAt: validity.StartsAt(), EndsAt: validity.EndsAt(), TimeZone: request.TimeZone,
				CyclePolicy: request.CyclePolicy,
				TrafficFactor: RationalSnapshot{
					Numerator: request.TrafficFactor.Numerator(), Denominator: request.TrafficFactor.Denominator(),
				},
			},
			LifecycleStatus: LifecycleActive, Revision: 1, CreatedAt: now, UpdatedAt: now,
		}
		productJSON, err := json.Marshal(subscription.Product)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO package_subscriptions (
				id, tenant_scope_id, product_id, product_revision, product_snapshot,
				site_limit, domain_limit, node_limit, traffic_limit_bytes,
				starts_at, ends_at, timezone, cycle_kind, custom_cycle_days,
				tcp_factor_numerator, tcp_factor_denominator, lifecycle_status,
				created_by_user_id, updated_by_user_id, created_at, updated_at
				) VALUES (
					$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'active',$17,$18,$19,$19
				)`, subscription.ID, subscription.TenantScopeID, subscription.Product.ID, subscription.Product.Revision,
			productJSON, subscription.Quotas.Sites, subscription.Quotas.Domains, subscription.Quotas.Nodes,
			subscription.Quotas.TrafficBytes, subscription.Period.StartsAt, subscription.Period.EndsAt,
			subscription.Period.TimeZone, subscription.Period.CyclePolicy.Kind,
			subscription.Period.CyclePolicy.CustomDays, int64(subscription.Period.TrafficFactor.Numerator),
			int64(subscription.Period.TrafficFactor.Denominator), request.OwnerUserID, actor.UserID, now); err != nil {
			return err
		}
		var packagePeriod *string
		var periodPrice *int64
		if request.Terms.Duration != nil {
			value := string(*request.Terms.Duration)
			price, err := prices.forDuration(*request.Terms.Duration)
			if err != nil {
				return err
			}
			packagePeriod, periodPrice = &value, &price
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO package_subscription_entitlement_versions (
				subscription_id, revision, supersedes_subscription_id, supersedes_revision,
				tenant_scope_id, effective_at, effective_until, product_id, product_revision,
				product_snapshot, site_limit, domain_limit, node_limit, traffic_limit_bytes,
				timezone, cycle_kind, custom_cycle_days, tcp_factor_numerator,
				tcp_factor_denominator, package_period, period_price_minor, currency,
				entitlement_status, source_order_id, operation, created_by_user_id, created_at
			) VALUES (
				$1,1,NULL,NULL,$2,$3,NULL,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
				$16,$17,'CNY','active',NULL,'manual_open',$18,$19
			)`, subscription.ID, subscription.TenantScopeID, subscription.Period.StartsAt,
			subscription.Product.ID, subscription.Product.Revision, productJSON,
			subscription.Quotas.Sites, subscription.Quotas.Domains, subscription.Quotas.Nodes,
			subscription.Quotas.TrafficBytes, subscription.Period.TimeZone,
			subscription.Period.CyclePolicy.Kind, subscription.Period.CyclePolicy.CustomDays,
			int64(subscription.Period.TrafficFactor.Numerator),
			int64(subscription.Period.TrafficFactor.Denominator), packagePeriod, periodPrice,
			actor.UserID, now); err != nil {
			return err
		}
		cycle, err := packageperiod.CurrentCycle(subscription.ID.String(), validity, request.CyclePolicy, now)
		if err != nil {
			return err
		}
		result = MutationResult{Subscription: subscription, Intent: &TaskIntent{
			SubscriptionID: subscription.ID, TenantScopeID: subscription.TenantScopeID,
			Action: TaskActionActivate, Reason: TaskReasonOpened, ResetKey: cycle.ResetKey(), DesiredEnabled: true,
		}}
		if err := appendSubscriptionVersion(ctx, tx, result.Subscription, "open", actor.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO package_monitor_subscription_owners(
			subscription_id,state_revision,tenant_scope_id,owner_user_id,source_kind,created_at
		) VALUES($1,$2,$3,$4,'subscription_state',$5)`,
			result.Subscription.ID, result.Subscription.Revision, result.Subscription.TenantScopeID,
			request.OwnerUserID, now); err != nil {
			return err
		}
		// User decision 10-22: opening a package publishes the tenant's sites
		// automatically, as the package owner.
		if _, err := packageautopublish.EnsureTx(ctx, tx, request.TenantScopeID, request.TenantScopeID,
			request.OwnerUserID); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, request.RequestID, operationOpen, result.Subscription, map[string]any{
			"owner_user_id": request.OwnerUserID.String(), "product_id": product.ID.String(),
			"product_revision": product.Revision,
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, operationOpen, request.IdempotencyKey,
			result.Subscription.ID, result, now)
	})
	if err != nil {
		return MutationResult{}, fmt.Errorf("open package subscription: %w", err)
	}
	return result, nil
}

func (s *Store) Renew(ctx context.Context, actor Actor, request RenewRequest, digest [32]byte) (MutationResult, error) {
	var result MutationResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		if err := authorizeActor(ctx, tx, actor, request.TenantScopeID, permissionManage, now); err != nil {
			return err
		}
		write, err := s.replayOrClaim(ctx, tx, actor, request.TenantScopeID, operationRenew,
			request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if write.found {
			return decodeReplay(write.response, &result)
		}
		subscription, err := lockSubscription(ctx, tx, request.TenantScopeID, request.SubscriptionID)
		if err != nil {
			return err
		}
		if subscription.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if subscription.LifecycleStatus != LifecycleActive {
			return ErrInvalidState
		}
		location, err := loadIANAZone(subscription.Period.TimeZone)
		if err != nil {
			return err
		}
		oldEnd := subscription.Period.EndsAt
		validity, err := packageperiod.NewValidity(oldEnd, location, request.Terms)
		if err != nil || !validity.EndsAt().After(now) {
			return ErrInvalidInput
		}
		command, err := tx.Exec(ctx, `
			UPDATE package_subscriptions SET
				ends_at = $3, revision = revision + 1, updated_by_user_id = $4, updated_at = $5
			WHERE id = $1 AND tenant_scope_id = $2 AND revision = $6 AND lifecycle_status = 'active'`,
			subscription.ID, subscription.TenantScopeID, validity.EndsAt(), actor.UserID, now, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		subscription.Period.EndsAt = validity.EndsAt()
		subscription.Revision++
		subscription.UpdatedAt = now
		result.Subscription = subscription
		if !now.Before(oldEnd) {
			activeEnd := subscription.Period.EndsAt
			activeValidity, err := packageperiod.NewValidity(subscription.Period.StartsAt, location,
				packageperiod.Terms{EndAt: &activeEnd})
			if err != nil {
				return err
			}
			cycle, err := packageperiod.CurrentCycle(subscription.ID.String(), activeValidity,
				subscription.Period.CyclePolicy, now)
			if err != nil {
				return err
			}
			result.Intent = &TaskIntent{SubscriptionID: subscription.ID, TenantScopeID: subscription.TenantScopeID,
				Action: TaskActionActivate, Reason: TaskReasonRenewed, ResetKey: cycle.ResetKey(), DesiredEnabled: true}
		}
		if err := appendSubscriptionVersion(ctx, tx, result.Subscription, "renew", actor.UserID, now); err != nil {
			return err
		}
		var ownerUserID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT created_by_user_id FROM package_subscriptions WHERE id=$1`,
			subscription.ID).Scan(&ownerUserID); err != nil {
			return err
		}
		if _, err := packageautopublish.EnsureTx(ctx, tx, subscription.TenantScopeID, subscription.TenantScopeID,
			ownerUserID); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, request.RequestID, operationRenew, result.Subscription, map[string]any{
			"previous_ends_at": oldEnd, "ends_at": result.Subscription.Period.EndsAt,
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, operationRenew, request.IdempotencyKey,
			result.Subscription.ID, result, now)
	})
	if err != nil {
		return MutationResult{}, fmt.Errorf("renew package subscription: %w", err)
	}
	return result, nil
}

func (s *Store) Cancel(ctx context.Context, actor Actor, request CancelRequest, digest [32]byte) (MutationResult, error) {
	var result MutationResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		if err := authorizeActor(ctx, tx, actor, request.TenantScopeID, permissionManage, now); err != nil {
			return err
		}
		write, err := s.replayOrClaim(ctx, tx, actor, request.TenantScopeID, operationCancel,
			request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if write.found {
			return decodeReplay(write.response, &result)
		}
		subscription, err := lockSubscription(ctx, tx, request.TenantScopeID, request.SubscriptionID)
		if err != nil {
			return err
		}
		if subscription.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if subscription.LifecycleStatus != LifecycleActive {
			return ErrInvalidState
		}
		command, err := tx.Exec(ctx, `
			UPDATE package_subscriptions SET lifecycle_status = 'cancelled', cancelled_at = $3,
				revision = revision + 1, updated_by_user_id = $4, updated_at = $3
			WHERE id = $1 AND tenant_scope_id = $2 AND revision = $5 AND lifecycle_status = 'active'`,
			subscription.ID, subscription.TenantScopeID, now, actor.UserID, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		subscription.LifecycleStatus = LifecycleCancelled
		subscription.CancelledAt = &now
		subscription.Revision++
		subscription.UpdatedAt = now
		result = MutationResult{Subscription: subscription, Intent: &TaskIntent{
			SubscriptionID: subscription.ID, TenantScopeID: subscription.TenantScopeID,
			Action: TaskActionSuspend, Reason: TaskReasonCancelled, DesiredEnabled: false,
		}}
		if err := appendSubscriptionVersion(ctx, tx, result.Subscription, "cancel", actor.UserID, now); err != nil {
			return err
		}
		// The policy fact's actor must be a platform operator or act in the
		// target tenant scope (086). A reseller (directly or through a billing
		// bridge key) acts in its own scope, so its cancel stops publication as
		// the package owner in the tenant scope, as opening and renewing do.
		stopScope, stopUser := actor.ScopeID, actor.UserID
		if actor.ScopeKind != ScopePlatform && actor.ScopeID != subscription.TenantScopeID {
			stopScope = subscription.TenantScopeID
			if err := tx.QueryRow(ctx, `SELECT created_by_user_id FROM package_subscriptions WHERE id=$1`,
				subscription.ID).Scan(&stopUser); err != nil {
				return err
			}
		}
		if _, err := packageautopublish.StopTx(ctx, tx, subscription.TenantScopeID, stopScope, stopUser, now); err != nil {
			return err
		}
		if s.cancelTx != nil {
			if err := s.cancelTx(ctx, tx, subscription.TenantScopeID, subscription.ID, now); err != nil {
				return err
			}
		}
		if err := s.appendAudit(ctx, tx, actor, request.RequestID, operationCancel, result.Subscription, nil); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, operationCancel, request.IdempotencyKey,
			result.Subscription.ID, result, now)
	})
	if err != nil {
		return MutationResult{}, fmt.Errorf("cancel package subscription: %w", err)
	}
	return result, nil
}

// Suspend suspends or unsuspends one subscription (ADR 0019 §5, migration
// 555): only suspended_at/suspend_reason change (revision+1, version row
// suspend/unsuspend); the term keeps running. Publication filters suspended
// subscriptions out, so the scope is republished at once through the system
// channel (trigger package_suspension). A subscription already in the
// requested state succeeds without a write. Other subscriptions of the tenant
// are untouched.
func (s *Store) Suspend(ctx context.Context, actor Actor, request SuspendRequest, digest [32]byte) (MutationResult, error) {
	var result MutationResult
	operation := operationUnsuspend
	if request.Suspend {
		operation = operationSuspend
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		if err := authorizeActor(ctx, tx, actor, request.TenantScopeID, permissionManage, now); err != nil {
			return err
		}
		// Publication lock order: configuration scope before resource rows.
		if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
			VALUES($1,1,$2) ON CONFLICT(scope_id) DO NOTHING`, request.TenantScopeID, now); err != nil {
			return err
		}
		var fromRevision int64
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
			request.TenantScopeID).Scan(&fromRevision); err != nil {
			return err
		}
		write, err := s.replayOrClaim(ctx, tx, actor, request.TenantScopeID, operation,
			request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if write.found {
			return decodeReplay(write.response, &result)
		}
		subscription, err := lockSubscription(ctx, tx, request.TenantScopeID, request.SubscriptionID)
		if err != nil {
			return err
		}
		var deleted bool
		if err := tx.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM package_subscriptions WHERE id=$1`,
			subscription.ID).Scan(&deleted); err != nil {
			return err
		}
		if subscription.LifecycleStatus != LifecycleActive || deleted {
			return ErrInvalidState
		}
		result = MutationResult{Subscription: subscription}
		if (subscription.SuspendedAt != nil) == request.Suspend {
			return s.completeWrite(ctx, tx, actor.UserID, operation, request.IdempotencyKey, subscription.ID, result, now)
		}
		var reason *string
		version := "unsuspend"
		if request.Suspend {
			reason, version = &request.Reason, "suspend"
			subscription.SuspendedAt, subscription.SuspendReason = &now, request.Reason
		} else {
			subscription.SuspendedAt, subscription.SuspendReason = nil, ""
		}
		subscription.Revision++
		subscription.UpdatedAt = now
		// The version row first: the snapshot trigger reads it.
		if err := appendSubscriptionVersion(ctx, tx, subscription, version, actor.UserID, now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `
			UPDATE package_subscriptions SET suspended_at = $3, suspend_reason = $4,
				revision = revision + 1, updated_by_user_id = $5, updated_at = $6
			WHERE id = $1 AND tenant_scope_id = $2 AND revision = $7`,
			subscription.ID, subscription.TenantScopeID, subscription.SuspendedAt, reason, actor.UserID, now,
			subscription.Revision-1)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		if s.republishTx != nil {
			if err := s.republishTx(ctx, tx, subscription.TenantScopeID, subscription.ID, fromRevision,
				request.Suspend, request.RequestID); err != nil {
				return err
			}
		}
		result.Subscription = subscription
		extra := map[string]any{"suspended": request.Suspend}
		if request.Suspend {
			extra["reason"] = request.Reason
		}
		action := auditUnsuspended
		if request.Suspend {
			action = auditSuspended
		}
		if err := s.appendAudit(ctx, tx, actor, request.RequestID, action, subscription, extra); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, operation, request.IdempotencyKey, subscription.ID, result, now)
	})
	if err != nil {
		return MutationResult{}, fmt.Errorf("%s package subscription: %w", operation, err)
	}
	return result, nil
}

// authorizeBridgeActor is the billing bridge branch (ADR 0019 §4.4): in tx
// the key is still active and unexpired, its owner valid and the module
// licensed. A (reseller) acts on its own customers with
// reseller.customers.manage; B (platform) on direct customers with
// package_subscriptions.manage. Any other target is not found.
func authorizeBridgeActor(ctx context.Context, tx pgx.Tx, actor Actor, targetTenantScopeID uuid.UUID) error {
	grant := actor.bridge
	permission := PermissionResellerCustomersManage
	if grant.Platform() {
		permission = permissionManage
	}
	if !grant.Valid() || actor.SessionID != uuid.Nil || targetTenantScopeID == uuid.Nil ||
		actor.UserID != grant.ActingUserID() || actor.ScopeID != grant.OwnerScopeID() ||
		actor.ScopeID == targetTenantScopeID || !grant.Allows(permission) ||
		(grant.Platform() != (actor.ScopeKind == ScopePlatform)) {
		return ErrPermissionDenied
	}
	if err := protocol.AcquireShared(ctx, tx); err != nil {
		return fmt.Errorf("acquire package subscription IAM global lock: %w", err)
	}
	if _, err := protocol.AcquireScopes(ctx, tx, []uuid.UUID{actor.ScopeID, targetTenantScopeID}); err != nil {
		return fmt.Errorf("acquire package subscription IAM scope locks: %w", err)
	}
	if err := grant.VerifyTx(ctx, tx); err != nil {
		if errors.Is(err, bridgeauth.ErrNotLicensed) {
			return errors.Join(ErrPermissionDenied, err)
		}
		if errors.Is(err, bridgeauth.ErrDenied) {
			return errors.Join(ErrUnauthenticated, err)
		}
		return err
	}
	var inScope bool
	var err error
	if grant.Platform() {
		inScope, err = bridgeauth.DirectCustomerTx(ctx, tx, targetTenantScopeID)
	} else {
		inScope, err = bridgeauth.ResellerCustomerTx(ctx, tx, actor.ScopeID, targetTenantScopeID)
	}
	if err != nil {
		return err
	}
	if !inScope {
		return ErrNotFound
	}
	var tenantActive bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_scopes scope
		JOIN tenants tenant ON tenant.id = scope.tenant_id AND tenant.status = 'active'
		WHERE scope.id = $1 AND scope.kind = 'tenant')`, targetTenantScopeID).Scan(&tenantActive); err != nil {
		return err
	}
	if !tenantActive {
		return ErrPermissionDenied
	}
	return nil
}

func authorizeActor(ctx context.Context, tx pgx.Tx, actor Actor, targetTenantScopeID uuid.UUID,
	permission string, now time.Time,
) error {
	if actor.bridge != nil {
		return authorizeBridgeActor(ctx, tx, actor, targetTenantScopeID)
	}
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.SessionID == uuid.Nil ||
		targetTenantScopeID == uuid.Nil ||
		(actor.ScopeKind != ScopePlatform && actor.ScopeKind != ScopeTenant) {
		return ErrUnauthenticated
	}
	if err := protocol.AcquireShared(ctx, tx); err != nil {
		return fmt.Errorf("acquire package subscription IAM global lock: %w", err)
	}
	if _, err := protocol.AcquireScopes(ctx, tx, []uuid.UUID{actor.ScopeID, targetTenantScopeID}); err != nil {
		return fmt.Errorf("acquire package subscription IAM scope locks: %w", err)
	}

	var actualKind, userStatus, membershipStatus string
	var actorTenantID *uuid.UUID
	var revokedAt *time.Time
	var expiresAt time.Time
	err := tx.QueryRow(ctx, `
		SELECT scope.kind, scope.tenant_id, account.status, membership.status,
			session.revoked_at, session.expires_at
		FROM auth_sessions session
		JOIN users account ON account.id = session.user_id
		JOIN memberships membership
		  ON membership.scope_id = session.scope_id AND membership.user_id = session.user_id
		JOIN access_scopes scope ON scope.id = session.scope_id
		WHERE session.id = $1 AND session.user_id = $2 AND session.scope_id = $3
		FOR UPDATE OF session, account, membership, scope`, actor.SessionID, actor.UserID, actor.ScopeID).Scan(
		&actualKind, &actorTenantID, &userStatus, &membershipStatus, &revokedAt, &expiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthenticated
	}
	if err != nil {
		return err
	}
	if actualKind != actor.ScopeKind || revokedAt != nil || !now.Before(expiresAt) ||
		userStatus != "active" || membershipStatus != "active" {
		return ErrUnauthenticated
	}
	if (actualKind == ScopePlatform && actorTenantID != nil) ||
		(actualKind == ScopeTenant && actorTenantID == nil) {
		return ErrPermissionDenied
	}
	// ADR 0019 §5 (bb03): a tenant acts on its own subscriptions, or a reseller
	// on its customers' (reseller.customers.manage, checked below).
	resellerActor := false
	if actualKind == ScopeTenant && actor.ScopeID != targetTenantScopeID {
		if permission != permissionManage {
			return ErrPermissionDenied
		}
		if err := tx.QueryRow(ctx, `SELECT reseller_scope_active_480($1) AND EXISTS (
			SELECT 1 FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
			WHERE scope.id = $2 AND scope.kind = 'tenant' AND tenant.parent_scope_id = $1)`,
			actor.ScopeID, targetTenantScopeID).Scan(&resellerActor); err != nil {
			return err
		}
		if !resellerActor {
			return ErrPermissionDenied
		}
		permission = PermissionResellerCustomersManage
	}

	var tenantActive, granted bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM access_scopes scope
		JOIN tenants tenant ON tenant.id = scope.tenant_id AND tenant.status = 'active'
		WHERE scope.id = $1 AND scope.kind = 'tenant'
	)`, targetTenantScopeID).Scan(&tenantActive); err != nil {
		return err
	}
	if !tenantActive {
		return ErrPermissionDenied
	}
	if actualKind == ScopeTenant {
		err = tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM custom_rbac_effective_permissions($1, $2)
			WHERE permission_name = $3
		)`, actor.ScopeID, actor.UserID, permission).Scan(&granted)
	} else {
		err = tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM role_assignments assignment
			JOIN roles role ON role.id = assignment.role_id AND role.scope_id = assignment.scope_id
			JOIN role_permissions grant_row ON grant_row.role_id = role.id
			WHERE assignment.scope_id = $1 AND assignment.user_id = $2
			  AND grant_row.permission_name IN ($3, 'platform.admin')
		)`, actor.ScopeID, actor.UserID, permission).Scan(&granted)
	}
	if err != nil {
		return err
	}
	if !granted {
		return ErrPermissionDenied
	}
	return nil
}

func verifySubscriptionOwner(ctx context.Context, tx pgx.Tx, tenantScopeID, ownerUserID uuid.UUID) error {
	var userStatus, membershipStatus string
	err := tx.QueryRow(ctx, `
		SELECT account.status, membership.status
		FROM users account
		JOIN memberships membership ON membership.user_id = account.id
		WHERE account.id = $1 AND membership.scope_id = $2
		FOR SHARE OF account, membership`, ownerUserID, tenantScopeID).Scan(&userStatus, &membershipStatus)
	if errors.Is(err, pgx.ErrNoRows) || userStatus != "active" || membershipStatus != "active" {
		return ErrInvalidInput
	}
	return err
}

func loadProductSnapshot(ctx context.Context, tx pgx.Tx, productID uuid.UUID,
	revision int64,
) (ProductSnapshot, int64, int64, productPrices, error) {
	var snapshot ProductSnapshot
	var raw string
	err := tx.QueryRow(ctx, `
		SELECT version.name, version.spec::text
		FROM package_product_versions version
		JOIN package_products product
		  ON product.id = version.product_id AND product.revision = version.revision
		WHERE version.product_id = $1 AND version.revision = $2
		  AND version.enabled AND NOT version.deleted
		  AND product.enabled AND product.deleted_at IS NULL
		FOR SHARE OF product`, productID, revision).Scan(&snapshot.Name, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProductSnapshot{}, 0, 0, productPrices{}, ErrProductNotFound
	}
	if err != nil {
		return ProductSnapshot{}, 0, 0, productPrices{}, err
	}
	var spec struct {
		Limits struct {
			Domains             int64 `json:"domains"`
			MonthlyTrafficBytes int64 `json:"monthly_traffic_bytes"`
		} `json:"limits"`
		Prices struct {
			Currency       string `json:"currency"`
			MonthlyMinor   *int64 `json:"monthly_minor"`
			QuarterlyMinor *int64 `json:"quarterly_minor"`
			YearlyMinor    *int64 `json:"yearly_minor"`
		} `json:"prices"`
	}
	if err := json.Unmarshal([]byte(raw), &spec); err != nil || !validLimit(spec.Limits.Domains) ||
		(spec.Limits.MonthlyTrafficBytes != -1 && spec.Limits.MonthlyTrafficBytes < 0) ||
		spec.Prices.Currency != "CNY" || spec.Prices.MonthlyMinor == nil ||
		spec.Prices.QuarterlyMinor == nil || spec.Prices.YearlyMinor == nil ||
		!validPrice(*spec.Prices.MonthlyMinor) || !validPrice(*spec.Prices.QuarterlyMinor) ||
		!validPrice(*spec.Prices.YearlyMinor) {
		return ProductSnapshot{}, 0, 0, productPrices{}, ErrInvalidInput
	}
	snapshot.ID, snapshot.Revision, snapshot.Spec = productID, revision, json.RawMessage(append([]byte(nil), raw...))
	prices := productPrices{month: *spec.Prices.MonthlyMinor, quarter: *spec.Prices.QuarterlyMinor,
		year: *spec.Prices.YearlyMinor}
	return snapshot, spec.Limits.Domains, spec.Limits.MonthlyTrafficBytes, prices, nil
}

func validPrice(value int64) bool {
	return value >= 0 && value <= maxMoneyMinor
}

func lockSubscription(ctx context.Context, tx pgx.Tx, tenantScopeID,
	subscriptionID uuid.UUID,
) (Subscription, error) {
	subscription, err := scanSubscription(tx.QueryRow(ctx, subscriptionSelect+`
		WHERE tenant_scope_id = $1 AND id = $2 FOR UPDATE`, tenantScopeID, subscriptionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Subscription{}, ErrNotFound
	}
	return subscription, err
}

func appendSubscriptionVersion(ctx context.Context, tx pgx.Tx, subscription Subscription,
	operation string, actorID uuid.UUID, now time.Time,
) error {
	payload, err := json.Marshal(subscription)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO package_subscription_versions (
			subscription_id, revision, operation, snapshot, created_by_user_id, created_at
		) VALUES ($1,$2,$3,$4,$5,$6)`,
		subscription.ID, subscription.Revision, operation, payload, actorID, now)
	return err
}

func (s *Store) replayOrClaim(ctx context.Context, tx pgx.Tx, actor Actor,
	tenantScopeID uuid.UUID, operation, key string, digest [32]byte, now time.Time,
) (storedWrite, error) {
	write, err := readStoredWrite(ctx, tx, actor.UserID, tenantScopeID, operation, key, digest)
	if err != nil || write.found {
		return write, err
	}
	requestID, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO package_subscription_write_requests (
			id, actor_user_id, actor_scope_id, target_tenant_scope_id,
			operation, idempotency_key, request_digest, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (actor_user_id, operation, idempotency_key) DO NOTHING`,
		requestID, actor.UserID, actor.ScopeID, tenantScopeID, operation, key, digest[:], now)
	if err != nil {
		return storedWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, nil
	}
	write, err = readStoredWrite(ctx, tx, actor.UserID, tenantScopeID, operation, key, digest)
	if err != nil {
		return storedWrite{}, err
	}
	if !write.found {
		return storedWrite{}, ErrIdempotencyConflict
	}
	return write, nil
}

func readStoredWrite(ctx context.Context, tx pgx.Tx, actorID, tenantScopeID uuid.UUID,
	operation, key string, digest [32]byte,
) (storedWrite, error) {
	var storedDigest []byte
	var storedTenant uuid.UUID
	var response *string
	err := tx.QueryRow(ctx, `
		SELECT target_tenant_scope_id, request_digest, response_body::text
		FROM package_subscription_write_requests
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3
		FOR UPDATE`, actorID, operation, key).Scan(&storedTenant, &storedDigest, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedWrite{}, nil
	}
	if err != nil {
		return storedWrite{}, err
	}
	if storedTenant != tenantScopeID || !bytes.Equal(storedDigest, digest[:]) || response == nil {
		return storedWrite{}, ErrIdempotencyConflict
	}
	return storedWrite{response: []byte(*response), found: true}, nil
}

func (s *Store) completeWrite(ctx context.Context, tx pgx.Tx, actorID uuid.UUID,
	operation, key string, subscriptionID uuid.UUID, result MutationResult, now time.Time,
) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE package_subscription_write_requests
		SET subscription_id = $4, response_body = $5, completed_at = $6
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3 AND completed_at IS NULL`,
		actorID, operation, key, subscriptionID, payload, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func decodeReplay(payload []byte, result *MutationResult) error {
	if err := json.Unmarshal(payload, result); err != nil {
		return fmt.Errorf("decode stored package subscription response: %w", err)
	}
	result.Replayed = true
	return nil
}

func (s *Store) appendAudit(ctx context.Context, tx pgx.Tx, actor Actor, requestID,
	action string, subscription Subscription, extra map[string]any,
) error {
	payload := map[string]any{
		"tenant_scope_id":  subscription.TenantScopeID.String(),
		"revision":         subscription.Revision,
		"lifecycle_status": subscription.LifecycleStatus,
	}
	for key, value := range extra {
		payload[key] = value
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: action,
		ResourceType: "package_subscription", ResourceID: subscription.ID.String(),
		RequestID: requestID, Result: "success", Payload: payload,
	})
}

const subscriptionSelect = `
	SELECT id, tenant_scope_id, product_snapshot::text,
	       site_limit, domain_limit, node_limit, traffic_limit_bytes,
	       starts_at, ends_at, timezone, cycle_kind, custom_cycle_days,
	       tcp_factor_numerator, tcp_factor_denominator,
	       lifecycle_status, cancelled_at, suspended_at, COALESCE(suspend_reason, ''), revision, created_at, updated_at
	FROM package_subscriptions `

// LoadSystem reads one subscription for a platform worker (no actor). The
// result is the stored base subscription; effective add-on limits are separate.
func LoadSystem(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenantScopeID, subscriptionID uuid.UUID) (Subscription, error) {
	subscription, err := scanSubscription(query.QueryRow(ctx, subscriptionSelect+`
		WHERE tenant_scope_id = $1 AND id = $2`, tenantScopeID, subscriptionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Subscription{}, ErrNotFound
	}
	return subscription, err
}

func scanSubscription(scanner rowScanner) (Subscription, error) {
	var subscription Subscription
	var productRaw string
	var cycleKind string
	var customDays int32
	var numerator, denominator int64
	if err := scanner.Scan(
		&subscription.ID, &subscription.TenantScopeID, &productRaw,
		&subscription.Quotas.Sites, &subscription.Quotas.Domains, &subscription.Quotas.Nodes,
		&subscription.Quotas.TrafficBytes, &subscription.Period.StartsAt, &subscription.Period.EndsAt,
		&subscription.Period.TimeZone, &cycleKind, &customDays, &numerator, &denominator,
		&subscription.LifecycleStatus, &subscription.CancelledAt, &subscription.SuspendedAt,
		&subscription.SuspendReason, &subscription.Revision,
		&subscription.CreatedAt, &subscription.UpdatedAt,
	); err != nil {
		return Subscription{}, err
	}
	if err := json.Unmarshal([]byte(productRaw), &subscription.Product); err != nil {
		return Subscription{}, fmt.Errorf("decode package product snapshot: %w", err)
	}
	subscription.Period.CyclePolicy = packageperiod.CyclePolicy{Kind: packageperiod.CycleKind(cycleKind), CustomDays: uint32(customDays)}
	subscription.Period.TrafficFactor = RationalSnapshot{Numerator: uint64(numerator), Denominator: uint64(denominator)}
	return subscription, nil
}
