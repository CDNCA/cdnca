package packagesubscription

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresSubscriptionLifecycleSnapshotAndTenantIsolation(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	actor := insertPlatformActor(t, pool, "package-admin")
	tenantA := insertSubscriptionTenant(t, pool, "Alpha", "package-alpha")
	tenantB := insertSubscriptionTenant(t, pool, "Beta", "package-beta")
	productID := insertPackageProductVersion(t, pool, actor, 1, 10, 1_000)
	location := mustZone(t, "Asia/Shanghai")
	fixedNow := time.Date(2024, time.January, 31, 8, 0, 0, 123456000, location)
	service := NewService(NewStoreWithClock(pool, func() time.Time { return fixedNow }))
	factor, err := packageperiod.NewTrafficFactor(1_100_000, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	duration := packageperiod.DurationMonth
	valid := OpenRequest{
		TenantScopeID: tenantA.scopeID, OwnerUserID: tenantA.userID,
		ProductID: productID, ProductRevision: 1,
		SiteLimit: 2, NodeLimit: 3, Terms: packageperiod.Terms{Duration: &duration},
		TimeZone: "Asia/Shanghai", CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly},
		TrafficFactor: factor, IdempotencyKey: "subscription-open", RequestID: "subscription-open-request",
	}
	endAt := fixedNow.AddDate(0, 1, 0)
	for name, terms := range map[string]packageperiod.Terms{
		"neither": {},
		"both":    {Duration: &duration, EndAt: &endAt},
	} {
		request := valid
		request.Terms = terms
		request.IdempotencyKey = "invalid-" + name
		request.RequestID = "invalid-" + name
		if _, err := service.Open(context.Background(), actor, request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Open(%s oneOf) error = %v, want %v", name, err, ErrInvalidInput)
		}
	}

	opened, err := service.Open(context.Background(), actor, valid)
	if err != nil {
		t.Fatal(err)
	}
	wantEnd := time.Date(2024, time.February, 29, 8, 0, 0, 123456000, location).UTC()
	if opened.Replayed || opened.Subscription.Revision != 1 ||
		!opened.Subscription.Period.StartsAt.Equal(fixedNow.UTC()) || !opened.Subscription.Period.EndsAt.Equal(wantEnd) ||
		opened.Subscription.Period.TimeZone != "Asia/Shanghai" ||
		opened.Subscription.Period.TrafficFactor != (RationalSnapshot{Numerator: 11, Denominator: 10}) ||
		opened.Subscription.Quotas != (QuotaSnapshot{Sites: 2, Domains: 10, Nodes: 3, TrafficBytes: 1_000}) ||
		opened.Intent == nil || opened.Intent.Action != TaskActionActivate || opened.Intent.Reason != TaskReasonOpened {
		t.Fatalf("opened subscription = %#v", opened)
	}
	replayed, err := service.Open(context.Background(), actor, valid)
	if err != nil || !replayed.Replayed || replayed.Subscription.ID != opened.Subscription.ID {
		t.Fatalf("replayed Open() = (%#v, %v)", replayed, err)
	}
	conflict := valid
	conflict.SiteLimit++
	if _, err := service.Open(context.Background(), actor, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting Open() error = %v, want %v", err, ErrIdempotencyConflict)
	}

	for _, test := range []struct {
		name    string
		message string
		query   string
		args    []any
	}{
		{
			name: "subscription id", message: "snapshot is immutable",
			query: `UPDATE package_subscriptions SET id = $2, revision = revision + 1, updated_at = updated_at WHERE id = $1`,
			args:  []any{opened.Subscription.ID, uuid.New()},
		},
		{
			// created_by_user_id is the owner since 4e2a63b2 (tenantA.userID):
			// change it to someone else.
			name: "creator", message: "snapshot is immutable",
			query: `UPDATE package_subscriptions SET created_by_user_id = $2, revision = revision + 1, updated_at = updated_at WHERE id = $1`,
			args:  []any{opened.Subscription.ID, actor.UserID},
		},
		{
			name: "creation time", message: "snapshot is immutable",
			query: `UPDATE package_subscriptions SET created_at = created_at - interval '1 second', revision = revision + 1, updated_at = updated_at WHERE id = $1`,
			args:  []any{opened.Subscription.ID},
		},
		{
			name: "shorter end", message: "renewal must strictly extend",
			query: `UPDATE package_subscriptions SET ends_at = ends_at - interval '1 second', revision = revision + 1, updated_at = updated_at WHERE id = $1`,
			args:  []any{opened.Subscription.ID},
		},
		{
			name: "backdated update", message: "updated_at cannot move backwards",
			query: `UPDATE package_subscriptions SET ends_at = ends_at + interval '1 second', revision = revision + 1, updated_at = updated_at - interval '1 second' WHERE id = $1`,
			args:  []any{opened.Subscription.ID},
		},
		{
			name: "forged cancellation time", message: "cancellation facts are invalid",
			query: `UPDATE package_subscriptions SET lifecycle_status = 'cancelled', cancelled_at = updated_at + interval '1 second', revision = revision + 1, updated_at = updated_at WHERE id = $1`,
			args:  []any{opened.Subscription.ID},
		},
	} {
		t.Run("reject "+test.name+" mutation", func(t *testing.T) {
			assertMutationRejected(t, pool, test.message, test.query, test.args...)
		})
	}

	for _, test := range []struct {
		name  string
		query string
		args  []any
	}{
		{name: "update", query: `UPDATE package_subscription_versions SET operation = operation WHERE subscription_id = $1`, args: []any{opened.Subscription.ID}},
		{name: "delete", query: `DELETE FROM package_subscription_versions WHERE subscription_id = $1`, args: []any{opened.Subscription.ID}},
		{name: "truncate", query: `TRUNCATE package_subscription_versions`},
	} {
		t.Run("reject version history "+test.name, func(t *testing.T) {
			assertMutationRejected(t, pool, "versions are append-only", test.query, test.args...)
		})
	}

	for _, test := range []struct {
		name    string
		message string
		query   string
		args    []any
	}{
		{
			name: "update", message: "completed package subscription write request is immutable",
			query: `UPDATE package_subscription_write_requests SET response_body = '{"forged":true}' WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3`,
			args:  []any{actor.UserID, operationOpen, valid.IdempotencyKey},
		},
		{
			name: "delete", message: "write requests cannot be deleted",
			query: `DELETE FROM package_subscription_write_requests WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3`,
			args:  []any{actor.UserID, operationOpen, valid.IdempotencyKey},
		},
		{name: "truncate", message: "write requests cannot be truncated", query: `TRUNCATE package_subscription_write_requests`},
	} {
		t.Run("reject completed idempotency "+test.name, func(t *testing.T) {
			assertMutationRejected(t, pool, test.message, test.query, test.args...)
		})
	}
	assertMutationRejected(t, pool, "write request must start unfinished", `
		INSERT INTO package_subscription_write_requests (
			id,actor_user_id,actor_scope_id,target_tenant_scope_id,operation,
			idempotency_key,request_digest,subscription_id,response_body,created_at,completed_at
		) VALUES ($1,$2,$3,$4,$5,'forged-completed',$6,$7,'{}',$8,$8)`,
		uuid.New(), actor.UserID, actor.ScopeID, tenantA.scopeID, operationOpen, make([]byte, 32),
		opened.Subscription.ID, fixedNow.UTC())
	unfinishedWriteID := uuid.New()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO package_subscription_write_requests (
			id,actor_user_id,actor_scope_id,target_tenant_scope_id,operation,
			idempotency_key,request_digest,created_at
		) VALUES ($1,$2,$3,$4,$5,'unfinished-direct',$6,$7)`,
		unfinishedWriteID, actor.UserID, actor.ScopeID, tenantA.scopeID, operationOpen, make([]byte, 32), fixedNow.UTC()); err != nil {
		t.Fatal(err)
	}
	assertMutationRejected(t, pool, "write request must complete atomically", `
		UPDATE package_subscription_write_requests SET subscription_id = $2 WHERE id = $1`,
		unfinishedWriteID, opened.Subscription.ID)

	updatePackageProductVersion(t, pool, actor, productID, 2, 1, 1)
	persisted, err := service.Get(context.Background(), actor, tenantA.scopeID, opened.Subscription.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Product.Revision != 1 || persisted.Quotas.Domains != 10 || persisted.Quotas.TrafficBytes != 1_000 {
		t.Fatalf("catalog change contaminated sold snapshot: %#v", persisted)
	}
	tenantAActor := Actor{UserID: tenantA.userID, ScopeID: tenantA.scopeID, SessionID: tenantA.sessionID, ScopeKind: ScopeTenant}
	if _, err := service.Get(context.Background(), tenantAActor, tenantA.scopeID, persisted.ID); err != nil {
		t.Fatalf("tenant owner Get() error = %v", err)
	}
	tenantBActor := Actor{UserID: tenantB.userID, ScopeID: tenantB.scopeID, SessionID: tenantB.sessionID, ScopeKind: ScopeTenant}
	if _, err := service.Get(context.Background(), tenantBActor, tenantA.scopeID, persisted.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant Get() error = %v, want %v", err, ErrPermissionDenied)
	}
	if _, err := service.Get(context.Background(), actor, tenantB.scopeID, persisted.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong target tenant Get() error = %v, want %v", err, ErrNotFound)
	}
	// A tenant session claiming platform scope kind does not match its own
	// session's scope: authorizeActor treats that as an unauthenticated actor
	// (store.go, since the baseline), never as a platform actor.
	spoofedAdmin := tenantAActor
	spoofedAdmin.ScopeKind = ScopePlatform
	if _, err := service.Get(context.Background(), spoofedAdmin, tenantA.scopeID, persisted.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("spoofed platform Get() error = %v, want %v", err, ErrUnauthenticated)
	}
	spoofedOpen := valid
	spoofedOpen.IdempotencyKey = "spoofed-open"
	spoofedOpen.RequestID = "spoofed-open"
	if _, err := service.Open(context.Background(), spoofedAdmin, spoofedOpen); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("spoofed platform Open() error = %v, want %v", err, ErrUnauthenticated)
	}

	year := packageperiod.DurationYear
	wrongTenantRenew := RenewRequest{
		TenantScopeID: tenantB.scopeID, SubscriptionID: persisted.ID, ExpectedRevision: 1,
		Terms: packageperiod.Terms{Duration: &year}, IdempotencyKey: "wrong-tenant-renew", RequestID: "wrong-tenant-renew",
	}
	if _, err := service.Renew(context.Background(), actor, wrongTenantRenew); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Renew() error = %v, want %v", err, ErrNotFound)
	}
	renewRequest := RenewRequest{
		TenantScopeID: tenantA.scopeID, SubscriptionID: persisted.ID, ExpectedRevision: 1,
		Terms: packageperiod.Terms{Duration: &year}, IdempotencyKey: "subscription-renew", RequestID: "subscription-renew-request",
	}
	renewed, err := service.Renew(context.Background(), actor, renewRequest)
	if err != nil {
		t.Fatal(err)
	}
	wantRenewedEnd := time.Date(2025, time.February, 28, 8, 0, 0, 123456000, location).UTC()
	if renewed.Subscription.Revision != 2 || !renewed.Subscription.Period.EndsAt.Equal(wantRenewedEnd) ||
		renewed.Subscription.Product.Revision != 1 || renewed.Subscription.Quotas != opened.Subscription.Quotas ||
		renewed.Intent != nil {
		t.Fatalf("renewed subscription = %#v", renewed)
	}
	replayedRenew, err := service.Renew(context.Background(), actor, renewRequest)
	if err != nil || !replayedRenew.Replayed || replayedRenew.Subscription.Revision != 2 ||
		replayedRenew.Subscription.ID != renewed.Subscription.ID {
		t.Fatalf("replayed Renew() = (%#v, %v)", replayedRenew, err)
	}
	cancelRequest := CancelRequest{
		TenantScopeID: tenantA.scopeID, SubscriptionID: persisted.ID, ExpectedRevision: 2,
		IdempotencyKey: "subscription-cancel", RequestID: "subscription-cancel-request",
	}
	cancelled, err := service.Cancel(context.Background(), actor, cancelRequest)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Subscription.Revision != 3 || cancelled.Subscription.LifecycleStatus != LifecycleCancelled ||
		cancelled.Subscription.CancelledAt == nil || cancelled.Intent == nil ||
		cancelled.Intent.Action != TaskActionSuspend || cancelled.Intent.Reason != TaskReasonCancelled {
		t.Fatalf("cancelled subscription = %#v", cancelled)
	}
	replayedCancel, err := service.Cancel(context.Background(), actor, cancelRequest)
	if err != nil || !replayedCancel.Replayed || replayedCancel.Subscription.Revision != 3 ||
		replayedCancel.Subscription.ID != cancelled.Subscription.ID {
		t.Fatalf("replayed Cancel() = (%#v, %v)", replayedCancel, err)
	}

	// opening the package put the tenant on automatic
	// publication as the owner, renewing kept it, and cancelling its only
	// package returned it to manual; tenant B was never touched.
	rows, err := pool.Query(context.Background(), `SELECT mode,reason,actor_scope_id,actor_user_id,cardinality(node_ids)
		FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1 ORDER BY revision`, tenantA.scopeID)
	if err != nil {
		t.Fatal(err)
	}
	type policyFact struct {
		mode, reason          string
		actorScope, actorUser uuid.UUID
		nodes                 int
	}
	policies, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (policyFact, error) {
		var fact policyFact
		return fact, row.Scan(&fact.mode, &fact.reason, &fact.actorScope, &fact.actorUser, &fact.nodes)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 || policies[0] != (policyFact{"automatic", "package_opened", tenantA.scopeID, tenantA.userID, 0}) ||
		policies[1] != (policyFact{"manual", "package_ended", actor.ScopeID, actor.UserID, 0}) {
		t.Fatalf("tenant A publication policies = %+v", policies)
	}
	var otherPolicies int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM edge_automatic_publication_policy_facts
		WHERE target_scope_id=$1`, tenantB.scopeID).Scan(&otherPolicies); err != nil || otherPolicies != 0 {
		t.Fatalf("tenant B publication policies = %d (%v)", otherPolicies, err)
	}

	var versions, writes, events int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM package_subscription_versions WHERE subscription_id = $1`, persisted.ID).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM package_subscription_write_requests WHERE completed_at IS NOT NULL`).Scan(&writes); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action LIKE 'package.subscription.%'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if versions != 3 || writes != 3 || events != 3 {
		t.Fatalf("versions/writes/audits = %d/%d/%d, want 3/3/3", versions, writes, events)
	}
	if err := audit.New(pool).VerifyScope(context.Background(), actor.ScopeID); err != nil {
		t.Fatalf("VerifyScope() error = %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE package_subscriptions SET site_limit = site_limit + 1, revision = revision + 1
		WHERE id = $1`, persisted.ID); err == nil {
		t.Fatal("immutable sold package snapshot was modified")
	}
}

func TestPostgresSubscriptionConcurrentRevisionHasSingleWinner(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	actor := insertPlatformActor(t, pool, "package-race-admin")
	tenant := insertSubscriptionTenant(t, pool, "Race", "package-race")
	productID := insertPackageProductVersion(t, pool, actor, 1, 10, 1_000)
	fixedNow := time.Date(2026, time.July, 22, 10, 0, 0, 0, time.UTC)
	service := NewService(NewStoreWithClock(pool, func() time.Time { return fixedNow }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := service.Open(context.Background(), actor, OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		ProductID: productID, ProductRevision: 1,
		SiteLimit: 2, NodeLimit: 2, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "UTC",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "race-open", RequestID: "race-open",
	})
	if err != nil {
		t.Fatal(err)
	}
	quarter := packageperiod.DurationQuarter
	requests := []RenewRequest{
		{TenantScopeID: tenant.scopeID, SubscriptionID: opened.Subscription.ID, ExpectedRevision: 1,
			Terms: packageperiod.Terms{Duration: &month}, IdempotencyKey: "race-renew-a", RequestID: "race-renew-a"},
		{TenantScopeID: tenant.scopeID, SubscriptionID: opened.Subscription.ID, ExpectedRevision: 1,
			Terms: packageperiod.Terms{Duration: &quarter}, IdempotencyKey: "race-renew-b", RequestID: "race-renew-b"},
	}
	results := make(chan error, len(requests))
	var wait sync.WaitGroup
	wait.Add(len(requests))
	for _, request := range requests {
		go func(input RenewRequest) {
			defer wait.Done()
			_, renewErr := service.Renew(context.Background(), actor, input)
			results <- renewErr
		}(request)
	}
	wait.Wait()
	close(results)
	succeeded, conflicted := 0, 0
	for result := range results {
		switch {
		case result == nil:
			succeeded++
		case errors.Is(result, ErrRevisionConflict):
			conflicted++
		default:
			t.Fatalf("concurrent Renew() error = %v", result)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent renew results = success %d conflict %d", succeeded, conflicted)
	}
	persisted, err := service.Get(context.Background(), actor, tenant.scopeID, opened.Subscription.ID)
	if err != nil || persisted.Revision != 2 {
		t.Fatalf("concurrent persisted subscription = (%#v, %v)", persisted, err)
	}
}

func TestPostgresSubscriptionConcurrentOpenReplaysSingleWinner(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	actor := insertPlatformActor(t, pool, "package-open-race-admin")
	tenant := insertSubscriptionTenant(t, pool, "Open Race", "package-open-race")
	productID := insertPackageProductVersion(t, pool, actor, 1, 10, 1_000)
	fixedNow := time.Date(2026, time.July, 22, 10, 0, 0, 0, time.UTC)
	service := NewService(NewStoreWithClock(pool, func() time.Time { return fixedNow }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	request := OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		ProductID: productID, ProductRevision: 1,
		SiteLimit: 2, NodeLimit: 2, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "UTC",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "race-open-same", RequestID: "race-open-same",
	}
	type outcome struct {
		result MutationResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			<-start
			result, err := service.Open(context.Background(), actor, request)
			results <- outcome{result: result, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	var outcomes []MutationResult
	for item := range results {
		if item.err != nil {
			t.Fatalf("concurrent Open() error = %v", item.err)
		}
		outcomes = append(outcomes, item.result)
	}
	if len(outcomes) != 2 || outcomes[0].Subscription.ID != outcomes[1].Subscription.ID ||
		outcomes[0].Replayed == outcomes[1].Replayed {
		t.Fatalf("concurrent Open() outcomes = %#v", outcomes)
	}
	var subscriptions, versions, writes, events int
	if err := pool.QueryRow(t.Context(), `
		SELECT
			(SELECT count(*) FROM package_subscriptions),
			(SELECT count(*) FROM package_subscription_versions),
			(SELECT count(*) FROM package_subscription_write_requests WHERE completed_at IS NOT NULL),
			(SELECT count(*) FROM audit_events WHERE action = 'package.subscription.open')`,
	).Scan(&subscriptions, &versions, &writes, &events); err != nil {
		t.Fatal(err)
	}
	if [4]int{subscriptions, versions, writes, events} != [4]int{1, 1, 1, 1} {
		t.Fatalf("concurrent Open() facts = %d/%d/%d/%d, want 1/1/1/1",
			subscriptions, versions, writes, events)
	}
}

func TestPostgresSubscriptionAuditFailureRollsBackEverything(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	actor := insertPlatformActor(t, pool, "package-audit-admin")
	tenant := insertSubscriptionTenant(t, pool, "Audit", "package-audit")
	productID := insertPackageProductVersion(t, pool, actor, 1, 10, 1_000)
	fixedNow := time.Date(2026, time.July, 22, 10, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(pool, func() time.Time { return fixedNow })
	store.auditor = failingAuditAppender{}
	service := NewService(store)
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	duration := packageperiod.DurationMonth
	if _, err := service.Open(context.Background(), actor, OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		ProductID: productID, ProductRevision: 1,
		SiteLimit: 1, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &duration}, TimeZone: "UTC",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "audit-failure", RequestID: "audit-failure",
	}); err == nil {
		t.Fatal("Open() succeeded despite audit failure")
	}
	for _, table := range []string{"package_subscriptions", "package_subscription_versions", "package_subscription_write_requests"} {
		var count int
		if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s count = %d after audit rollback", table, count)
		}
	}
}

func TestPostgresSubscriptionRenewAndCancelAuditFailuresRollBackEverything(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	actor := insertPlatformActor(t, pool, "package-transition-audit-admin")
	tenant := insertSubscriptionTenant(t, pool, "Transition Audit", "package-transition-audit")
	productID := insertPackageProductVersion(t, pool, actor, 1, 10, 1_000)
	fixedNow := time.Date(2026, time.July, 22, 10, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(pool, func() time.Time { return fixedNow })
	service := NewService(store)
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := service.Open(context.Background(), actor, OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		ProductID: productID, ProductRevision: 1,
		SiteLimit: 1, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "UTC",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "transition-audit-open", RequestID: "transition-audit-open",
	})
	if err != nil {
		t.Fatal(err)
	}
	store.auditor = failingAuditAppender{}
	if _, err := service.Renew(context.Background(), actor, RenewRequest{
		TenantScopeID: tenant.scopeID, SubscriptionID: opened.Subscription.ID, ExpectedRevision: 1,
		Terms: packageperiod.Terms{Duration: &month}, IdempotencyKey: "transition-audit-renew",
		RequestID: "transition-audit-renew",
	}); err == nil {
		t.Fatal("Renew() succeeded despite audit failure")
	}
	if _, err := service.Cancel(context.Background(), actor, CancelRequest{
		TenantScopeID: tenant.scopeID, SubscriptionID: opened.Subscription.ID, ExpectedRevision: 1,
		IdempotencyKey: "transition-audit-cancel", RequestID: "transition-audit-cancel",
	}); err == nil {
		t.Fatal("Cancel() succeeded despite audit failure")
	}
	persisted, err := NewService(NewStoreWithClock(pool, func() time.Time { return fixedNow })).Get(
		context.Background(), actor, tenant.scopeID, opened.Subscription.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Revision != 1 || persisted.LifecycleStatus != LifecycleActive || persisted.CancelledAt != nil ||
		!persisted.Period.EndsAt.Equal(opened.Subscription.Period.EndsAt) {
		t.Fatalf("subscription changed after audit failures: %#v", persisted)
	}
	var versions, writes, events int
	if err := pool.QueryRow(t.Context(), `
		SELECT
			(SELECT count(*) FROM package_subscription_versions WHERE subscription_id = $1),
			(SELECT count(*) FROM package_subscription_write_requests WHERE completed_at IS NOT NULL),
			(SELECT count(*) FROM audit_events WHERE action LIKE 'package.subscription.%')`,
		opened.Subscription.ID).Scan(&versions, &writes, &events); err != nil {
		t.Fatal(err)
	}
	if [3]int{versions, writes, events} != [3]int{1, 1, 1} {
		t.Fatalf("transition audit rollback facts = %d/%d/%d, want 1/1/1", versions, writes, events)
	}
}

func TestPostgresFixedClockDSTSnapshotAndEvaluation(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	actor := insertPlatformActor(t, pool, "package-dst-admin")
	tenant := insertSubscriptionTenant(t, pool, "DST", "package-dst")
	productID := insertPackageProductVersion(t, pool, actor, 1, 5, 1_000)
	location := mustZone(t, "America/New_York")
	fixedNow := time.Date(2026, time.March, 7, 12, 0, 0, 0, location)
	service := NewService(NewStoreWithClock(pool, func() time.Time { return fixedNow }))
	factor, _ := packageperiod.NewTrafficFactor(1_100_000, 1_000_000)
	duration := packageperiod.DurationMonth
	opened, err := service.Open(context.Background(), actor, OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		ProductID: productID, ProductRevision: 1,
		SiteLimit: 2, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &duration}, TimeZone: "America/New_York",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleDaily}, TrafficFactor: factor,
		IdempotencyKey: "dst-open", RequestID: "dst-open",
	})
	if err != nil {
		t.Fatal(err)
	}
	end := opened.Subscription.Period.EndsAt
	validity, err := packageperiod.NewValidity(opened.Subscription.Period.StartsAt, location, packageperiod.Terms{EndAt: &end})
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := packageperiod.CurrentCycle(opened.Subscription.ID.String(), validity,
		opened.Subscription.Period.CyclePolicy, time.Date(2026, time.March, 8, 11, 59, 0, 0, location))
	if err != nil || cycle.EndsAt().Sub(cycle.StartsAt()) != 23*time.Hour {
		t.Fatalf("persisted DST cycle = [%s,%s), %v", cycle.StartsAt(), cycle.EndsAt(), err)
	}
	evaluation, err := Evaluate(time.Date(2026, time.March, 8, 11, 0, 0, 0, location), opened.Subscription,
		Usage{Sites: 3}, packageperiod.ServiceState{Enabled: true})
	if err != nil || len(evaluation.BlockedResources) != 1 || evaluation.Intent != nil {
		t.Fatalf("persisted capacity evaluation = (%#v, %v)", evaluation, err)
	}
	var revision int64
	var status string
	if err := pool.QueryRow(context.Background(), `SELECT revision, lifecycle_status FROM package_subscriptions WHERE id = $1`,
		opened.Subscription.ID).Scan(&revision, &status); err != nil {
		t.Fatal(err)
	}
	if revision != 1 || status != LifecycleActive {
		t.Fatalf("evaluation directly changed subscription = revision %d status %q", revision, status)
	}
}

func TestPackageSubscriptionMigration028UpDownUpAndChecks(t *testing.T) {
	// The round trips load only 1..028: rolling the release head back to 028
	// crosses migration 268's one-way down gate (P2682).
	pool := isolatedSubscriptionPoolThrough(t, 28)
	if err := database.Migrate(context.Background(), pool, "down"); err != nil {
		t.Fatalf("Migrate(down 028) error = %v", err)
	}
	for _, table := range []string{"package_subscriptions", "package_subscription_versions", "package_subscription_write_requests"} {
		var relation *string
		if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1)::text`, table).Scan(&relation); err != nil {
			t.Fatal(err)
		}
		if relation != nil {
			t.Fatalf("%s still exists after 028 down", table)
		}
	}
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", 28); err != nil {
		t.Fatalf("Migrate(up 028) error = %v", err)
	}
	// The fixtures need later IAM migrations; check the 028 constraints on
	// the release head as before.
	if err := database.Migrate(context.Background(), pool, "up"); err != nil {
		t.Fatalf("Migrate(up after 028) error = %v", err)
	}
	actor := insertPlatformActor(t, pool, "package-migration-admin")
	tenant := insertSubscriptionTenant(t, pool, "Migration", "package-migration")
	productID := insertPackageProductVersion(t, pool, actor, 1, 10, 1_000)

	for _, test := range []struct {
		name        string
		timeZone    string
		cycleKind   string
		customDays  int
		numerator   int64
		denominator int64
	}{
		{name: "process local timezone", timeZone: "Local", cycleKind: "monthly", numerator: 1, denominator: 1},
		{name: "fixed offset timezone", timeZone: "+08:00", cycleKind: "monthly", numerator: 1, denominator: 1},
		{name: "unloadable timezone", timeZone: "Mars/Olympus", cycleKind: "monthly", numerator: 1, denominator: 1},
		{name: "custom days above maximum", timeZone: "UTC", cycleKind: "custom_days", customDays: 367, numerator: 1, denominator: 1},
		{name: "factor component above maximum", timeZone: "UTC", cycleKind: "monthly", numerator: 1_000_001, denominator: 1},
		{name: "factor multiplier above maximum", timeZone: "UTC", cycleKind: "monthly", numerator: 1_001, denominator: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := insertRawSubscription(pool, uuid.New(), tenant.scopeID, productID, actor.UserID,
				test.timeZone, test.cycleKind, test.customDays, test.numerator, test.denominator)
			assertCheckViolation(t, err)
		})
	}
	if err := insertRawSubscription(pool, uuid.New(), tenant.scopeID, productID, actor.UserID,
		"Asia/Shanghai", "custom_days", 366, 11, 10, "Business"); err != nil {
		t.Fatalf("valid 028 row rejected: %v", err)
	}
	if err := insertRawSubscription(pool, uuid.New(), tenant.scopeID, productID, actor.UserID,
		"UTC", "monthly", 0, 11, 10, "forged name"); err == nil || !strings.Contains(err.Error(), "product snapshot does not match") {
		t.Fatalf("mismatched product snapshot error = %v", err)
	}

	pool = isolatedSubscriptionPoolThrough(t, 28)
	if err := database.Migrate(context.Background(), pool, "down"); err != nil {
		t.Fatalf("second Migrate(down 028) error = %v", err)
	}
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", 28); err != nil {
		t.Fatalf("second Migrate(up 028) error = %v", err)
	}
	var applied bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 28)`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("migration 028 is not applied after up/down/up")
	}
}

type tenantFixture struct {
	scopeID   uuid.UUID
	userID    uuid.UUID
	sessionID uuid.UUID
}

func isolatedSubscriptionPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return isolatedSubscriptionPoolThrough(t, 0)
}

// isolatedSubscriptionPoolThrough migrates a fresh schema through target only
// (0 means the release head).
func isolatedSubscriptionPoolThrough(t *testing.T, target int64) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "package_subscription_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^package_subscription_test_[a-f0-9]{32}$`).MatchString(schema) {
		adminPool.Close()
		t.Fatalf("refusing unexpected schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatal(err)
	}
	migrate := func() error { return database.Migrate(ctx, pool, "up") }
	if target > 0 {
		migrate = func() error { return databasetest.MigrateThrough(ctx, pool, "up", target) }
	}
	if err := migrate(); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatalf("migrate isolated subscription schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated subscription schema: %v", err)
		}
		adminPool.Close()
	})
	return pool
}

func insertPlatformActor(t *testing.T, pool *pgxpool.Pool, username string) Actor {
	t.Helper()
	scopeID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes (id, kind) VALUES ($1, 'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	insertSubscriptionUser(t, pool, scopeID, userID, username)
	assignSubscriptionRole(t, pool, scopeID, userID, "platform_owner",
		permissionRead, permissionManage)
	return Actor{UserID: userID, ScopeID: scopeID, SessionID: insertSubscriptionSession(t, pool, scopeID, userID), ScopeKind: ScopePlatform}
}

func insertSubscriptionTenant(t *testing.T, pool *pgxpool.Pool, name, username string) tenantFixture {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO tenants (id, display_name) VALUES ($1,$2)`, tenantID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	insertSubscriptionUser(t, pool, scopeID, userID, username)
	assignSubscriptionRole(t, pool, scopeID, userID, "tenant_viewer", permissionRead)
	return tenantFixture{scopeID: scopeID, userID: userID, sessionID: insertSubscriptionSession(t, pool, scopeID, userID)}
}

func insertSubscriptionUser(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, username string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO users (id, username, display_name, password_hash) VALUES ($1,$2,$3,'test-password-hash')`,
		userID, username, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO memberships (scope_id, user_id) VALUES ($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
}

func assignSubscriptionRole(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID,
	roleName string, permissions ...string,
) {
	t.Helper()
	roleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO roles (id,scope_id,name,description,system_role)
		VALUES ($1,$2,$3,'Package subscription test role',true)`, roleID, scopeID, roleName); err != nil {
		t.Fatal(err)
	}
	for _, permission := range permissions {
		if roleName == "tenant_viewer" && permission == permissionRead {
			continue
		}
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO role_permissions (role_id,permission_name) VALUES ($1,$2)
			ON CONFLICT DO NOTHING`, roleID, permission); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO role_assignments (scope_id,user_id,role_id) VALUES ($1,$2,$3)`, scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
}

func insertSubscriptionSession(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) uuid.UUID {
	t.Helper()
	sessionID := uuid.New()
	digest := sha256.Sum256(sessionID[:])
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO auth_sessions (
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, scopeID, digest[:],
		time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2035, time.January, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	return sessionID
}

func insertPackageProductVersion(t *testing.T, pool *pgxpool.Pool, actor Actor,
	revision, domains, traffic int64,
) uuid.UUID {
	t.Helper()
	productID := uuid.New()
	now := time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)
	spec := []byte(`{"name":"Business","limits":{"domains":` + intString(domains) +
		`,"monthly_traffic_bytes":` + intString(traffic) +
		`},"prices":{"currency":"CNY","monthly_minor":1000,"quarterly_minor":2800,"yearly_minor":10000}}`)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, actor.ScopeID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO package_products (
				id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at
			) VALUES ($1,'Business',true,100,$2,$3,$4,$4,$5,$5)`, productID, spec, revision, actor.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO package_product_versions (
				product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at
			) VALUES ($1,$2,'Business',true,100,$3,false,$4,$5)`, productID, revision, spec, actor.UserID, now); err != nil {
			return err
		}
		return audit.NewWithClock(pool, func() time.Time { return now }).Append(t.Context(), tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: "package.product.create", ResourceType: "package_product", ResourceID: productID.String(),
			RequestID: "package-subscription-product-create-" + productID.String(), Result: "success",
			Payload: map[string]any{"revision": revision, "enabled": true},
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return productID
}

func updatePackageProductVersion(t *testing.T, pool *pgxpool.Pool, actor Actor, productID uuid.UUID,
	revision, domains, traffic int64,
) {
	t.Helper()
	now := time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC)
	spec := []byte(`{"name":"Business v2","limits":{"domains":` + intString(domains) +
		`,"monthly_traffic_bytes":` + intString(traffic) +
		`},"prices":{"currency":"CNY","monthly_minor":1000,"quarterly_minor":2800,"yearly_minor":10000}}`)
	// As insertPackageProductVersion: since 090 a package product write takes
	// the IAM locks and its package.product.* audit completes the catalog
	// sequence in the same transaction.
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, actor.ScopeID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `
			UPDATE package_products SET name = 'Business v2', spec = $2, revision = $3,
				updated_by_user_id = $4, updated_at = $5 WHERE id = $1`, productID, spec, revision, actor.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO package_product_versions (
				product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at
			) VALUES ($1,$2,'Business v2',true,100,$3,false,$4,$5)`, productID, revision, spec, actor.UserID, now); err != nil {
			return err
		}
		return audit.NewWithClock(pool, func() time.Time { return now }).Append(t.Context(), tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: "package.product.update", ResourceType: "package_product", ResourceID: productID.String(),
			RequestID: "package-subscription-product-update-" + productID.String() + "-" + intString(revision), Result: "success",
			Payload: map[string]any{"revision": revision, "enabled": true},
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func insertRawSubscription(pool *pgxpool.Pool, id, tenantScopeID, productID, actorID uuid.UUID,
	timeZone, cycleKind string, customDays int, numerator, denominator int64, snapshotName ...string,
) error {
	nameExpression := "version.name"
	arguments := []any{id, tenantScopeID, productID, timeZone, cycleKind, customDays, numerator, denominator, actorID}
	if len(snapshotName) != 0 {
		nameExpression = "$10::text"
		arguments = append(arguments, snapshotName[0])
	}
	_, err := pool.Exec(context.Background(), `
		INSERT INTO package_subscriptions (
			id,tenant_scope_id,product_id,product_revision,product_snapshot,
			site_limit,domain_limit,node_limit,traffic_limit_bytes,
			starts_at,ends_at,timezone,cycle_kind,custom_cycle_days,
			tcp_factor_numerator,tcp_factor_denominator,lifecycle_status,
			created_by_user_id,updated_by_user_id,created_at,updated_at
		) SELECT
			$1,$2,version.product_id,version.revision,
			jsonb_build_object('id',version.product_id::text,'revision',version.revision,
				'name',`+nameExpression+`,'spec',version.spec),1,1,1,1000,
			'2026-01-01T00:00:00Z','2026-02-01T00:00:00Z',$4,$5,$6,$7,$8,'active',$9,$9,now(),now()
		FROM package_product_versions version
		WHERE version.product_id = $3 AND version.revision = 1`, arguments...)
	return err
}

func assertCheckViolation(t *testing.T, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("database error = %v, want check violation 23514", err)
	}
}

func assertMutationRejected(t *testing.T, pool *pgxpool.Pool, message, query string, args ...any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), query, args...)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || !strings.Contains(pgErr.Message, message) {
		t.Fatalf("database mutation error = %v, want message containing %q", err, message)
	}
}

type failingAuditAppender struct{}

func (failingAuditAppender) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("injected audit failure")
}

func intString(value int64) string {
	return strconv.FormatInt(value, 10)
}
