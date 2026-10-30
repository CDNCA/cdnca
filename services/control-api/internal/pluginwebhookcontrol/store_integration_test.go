//go:build integration

package pluginwebhookcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStoreHead084ActorIdempotencyRotationAndRevoke(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Operations", TargetURL: "https://hooks.example.com/v1/events", EventTypes: []string{EventTypeTest}, IdempotencyKey: "create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Replayed || len(created.Value.Secret) != 43 || created.Value.Subscription.Revision != 1 {
		t.Fatalf("create replayed=%t subscription=%s revision=%d secret_valid=%t", created.Replayed, created.Value.Subscription.ID, created.Value.Subscription.Revision, len(created.Value.Secret) == 43)
	}
	replayed, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{Name: "Operations", TargetURL: "https://hooks.example.com/v1/events", EventTypes: []string{EventTypeTest}, IdempotencyKey: "create-1"})
	if err != nil || !replayed.Replayed || replayed.Value.Secret != created.Value.Secret || replayed.Value.Subscription.ID != created.Value.Subscription.ID {
		t.Fatalf("replay replayed=%t subscription=%s secret_matches=%t error=%v", replayed.Replayed, replayed.Value.Subscription.ID, replayed.Value.Secret == created.Value.Secret, err)
	}
	if _, err = fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{Name: "Different", TargetURL: "https://hooks.example.com/v1/events", EventTypes: []string{EventTypeTest}, IdempotencyKey: "create-1"}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("digest conflict=%v", err)
	}
	platformCreated, err := fixture.store.CreateSubscription(t.Context(), fixture.platformActor, CreateSubscriptionRequest{Name: "Operations", TargetURL: "https://hooks.example.com/v1/events", EventTypes: []string{EventTypeTest}, IdempotencyKey: "create-1"})
	if err != nil || platformCreated.Replayed || platformCreated.Value.Subscription.ID == created.Value.Subscription.ID || platformCreated.Value.Subscription.TenantScopeID != fixture.actor.TargetScopeID {
		t.Fatalf("platform actor create replayed=%t subscription=%s target=%s error=%v", platformCreated.Replayed, platformCreated.Value.Subscription.ID, platformCreated.Value.Subscription.TenantScopeID, err)
	}

	subscription := created.Value.Subscription.ID
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if delivery.Value.Delivery.Status != "pending" {
		t.Fatalf("delivery=%+v", delivery)
	}
	for index := 2; index <= 5; index++ {
		if _, err = fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: fmt.Sprintf("test-%d", index)}); err != nil {
			t.Fatalf("test delivery %d: %v", index, err)
		}
	}
	rateClock, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rateClock.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err == nil {
		_, err = rateClock.Exec(t.Context(), `UPDATE plugin_webhook_rate_events SET plugin_webhook_physical_recorded_at=clock_timestamp()-interval '40 seconds' WHERE tenant_scope_id=$1 AND subscription_id=$2 AND operation=$3 AND outcome='allowed'`, fixture.actor.TargetScopeID, subscription, opTest)
	}
	if err == nil {
		_, err = rateClock.Exec(t.Context(), `SET LOCAL session_replication_role='origin'`)
	}
	if err == nil {
		err = rateClock.Commit(t.Context())
	} else {
		_ = rateClock.Rollback(t.Context())
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "test-6"}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("sixth test delivery=%v", err)
	}
	var limited RateLimitError
	if !errors.As(err, &limited) || limited.RetryAfter%time.Second != 0 || limited.RetryAfter < 18*time.Second || limited.RetryAfter > 20*time.Second {
		t.Fatalf("sixth test delivery retry after=%v, want remaining integer seconds", limited.RetryAfter)
	}
	if _, err = fixture.store.ReplayDelivery(t.Context(), fixture.actor, subscription, delivery.Value.Delivery.ID, WriteRequest{IdempotencyKey: "replay-1"}); !errors.Is(err, ErrDeliveryNotReplayable) {
		t.Fatalf("pending replay=%v", err)
	}

	rotation, err := fixture.store.RotateSecret(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "rotate-1", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Value.Status != "pending" || len(rotation.Value.Secret) != 43 {
		t.Fatalf("rotation replayed=%t id=%s status=%s revision=%d secret_valid=%t", rotation.Replayed, rotation.Value.RotationID, rotation.Value.Status, rotation.Value.SubscriptionRevision, len(rotation.Value.Secret) == 43)
	}
	activated, err := fixture.store.ActivateSecret(t.Context(), fixture.actor, subscription, rotation.Value.RotationID, WriteRequest{IdempotencyKey: "activate-1", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if activated.Value.Subscription.Revision != 2 || activated.Value.Subscription.ActiveSecretVersionID != rotation.Value.RotationID {
		t.Fatalf("activated=%+v", activated)
	}
	rotationReplay, err := fixture.store.RotateSecret(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "rotate-1", Revision: 1})
	if err != nil || !rotationReplay.Replayed || rotationReplay.Value.Secret != rotation.Value.Secret || rotationReplay.Value.Status != "pending" || rotationReplay.Value.SubscriptionRevision != 1 {
		t.Fatalf("rotation replay replayed=%t id=%s status=%s revision=%d secret_matches=%t error=%v", rotationReplay.Replayed, rotationReplay.Value.RotationID, rotationReplay.Value.Status, rotationReplay.Value.SubscriptionRevision, rotationReplay.Value.Secret == rotation.Value.Secret, err)
	}
	if _, err = fixture.store.RotateSecret(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "rotate-1", Revision: 2}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed rotation revision=%v", err)
	}

	forged := fixture.actor
	forged.ActorScopeID = uuid.New()
	if _, err = fixture.store.GetSubscription(t.Context(), forged, subscription); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("forged actor=%v", err)
	}
	revoked, err := fixture.store.RevokeSubscription(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "revoke-1", Revision: 2})
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Value.Subscription.Status != "revoked" || revoked.Value.Subscription.Revision != 3 {
		t.Fatalf("revoked=%+v", revoked)
	}
	if _, err = fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "post-revoke"}); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("post revoke=%v", err)
	}

	page, err := fixture.store.ListSubscriptions(t.Context(), fixture.actor, ListQuery{Limit: 1})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list=%+v,%v", page, err)
	}
}

func TestStoreConcurrentIdenticalFirstRequestLinearizes(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	request := CreateSubscriptionRequest{
		Name: "Concurrent idempotency", TargetURL: "https://hooks.example.com/v1/concurrent",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "concurrent-create-1",
	}
	blocker, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(t.Context())
	if _, err = blocker.Exec(t.Context(), `SELECT pg_advisory_xact_lock(hashtextextended(
		'plugin-webhook-idempotency:'||$1::uuid::text||':'||$2::uuid::text||':'||$3::uuid::text||':'||$4,84))`,
		fixture.actor.TargetScopeID, fixture.actor.ActorScopeID, fixture.actor.ActorUserID, request.IdempotencyKey); err != nil {
		t.Fatal(err)
	}
	type result struct {
		value WriteResult[SubscriptionReceipt]
		err   error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			value, callErr := fixture.store.CreateSubscription(t.Context(), fixture.actor, request)
			results <- result{value: value, err: callErr}
		}()
	}
	waitForBlockedIdempotencyCalls(t, fixture.pool, 2)
	if err = blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := []result{<-results, <-results}
	for _, current := range got {
		if current.err != nil {
			t.Fatalf("concurrent create error = %v", current.err)
		}
	}
	if got[0].value.Replayed == got[1].value.Replayed {
		t.Fatalf("replayed flags = %t,%t; want one original and one replay", got[0].value.Replayed, got[1].value.Replayed)
	}
	if got[0].value.Value.Subscription.ID != got[1].value.Value.Subscription.ID ||
		got[0].value.Value.Secret != got[1].value.Value.Secret {
		t.Fatal("concurrent identical requests returned different committed results")
	}
	checks := []struct {
		name  string
		query string
		args  []any
	}{
		{"subscriptions", `SELECT count(*) FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND name='Concurrent idempotency'`, []any{fixture.actor.TargetScopeID}},
		{"write requests", `SELECT count(*) FROM plugin_webhook_write_requests WHERE tenant_scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND idempotency_key=$4`, []any{fixture.actor.TargetScopeID, fixture.actor.ActorScopeID, fixture.actor.ActorUserID, request.IdempotencyKey}},
		{"audits", `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3 AND request_id=$4`, []any{fixture.actor.TargetScopeID, fixture.actor.ActorUserID, opCreate, request.IdempotencyKey}},
		{"rates", `SELECT count(*) FROM plugin_webhook_rate_events WHERE tenant_scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND operation=$4 AND outcome='allowed'`, []any{fixture.actor.TargetScopeID, fixture.actor.ActorScopeID, fixture.actor.ActorUserID, opCreate}},
	}
	for _, check := range checks {
		var count int
		if err = fixture.pool.QueryRow(t.Context(), check.query, check.args...).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s = %d,%v; want 1", check.name, count, err)
		}
	}
}

func TestStoreCreateReplayPreservesOriginalSnapshotAfterRotation(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	request := CreateSubscriptionRequest{
		Name: "Original response snapshot", TargetURL: "https://hooks.example.com/v1/original-snapshot",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "original-snapshot-create-1",
	}
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, request)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := fixture.store.RotateSecret(t.Context(), fixture.actor, created.Value.Subscription.ID,
		WriteRequest{IdempotencyKey: "original-snapshot-rotate-1", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.store.ActivateSecret(t.Context(), fixture.actor, created.Value.Subscription.ID,
		rotation.Value.RotationID, WriteRequest{IdempotencyKey: "original-snapshot-activate-1", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	replayed, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, request)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.Value.Secret != created.Value.Secret {
		t.Fatalf("create replay = %+v; want original secret receipt", replayed)
	}
	if !reflect.DeepEqual(replayed.Value.Subscription, created.Value.Subscription) {
		t.Fatalf("create replay subscription = %+v, want original %+v", replayed.Value.Subscription, created.Value.Subscription)
	}
}

// TestStoreEntitlementAndTriggerShareTransactionBoundary: the Go-side guard and
// migration 084's decision triggers judge the same lease. 084 evaluates the
// decision on the physical clock (clock_timestamp) and re-checks it at commit,
// so a protected write whose transaction physically outlives the lease is
// denied and leaves nothing behind (fail closed, like the physical secret
// deadline), while a write inside the lease records a decision between the
// request's physical creation and the commit.
func TestStoreEntitlementAndTriggerShareTransactionBoundary(t *testing.T) {
	// Lease 3s + grace 4s: writes stay usable after expiry until grace ends.
	fixture := newStoreIntegrationFixtureWithLeaseWindow(t, 3*time.Second, 4*time.Second)
	inside, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Inside lease", TargetURL: "https://hooks.example.com/v1/inside-lease",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "shared-boundary-inside-1",
	})
	if err != nil {
		t.Fatalf("create inside lease = %v", err)
	}
	var withinRequest, beforeCommit bool
	if err = fixture.pool.QueryRow(t.Context(), `SELECT
			decision.evaluated_at>=request.plugin_webhook_physical_created_at
				AND decision.evaluated_at>=request.plugin_webhook_recorded_at,
			decision.evaluated_at<decision.lease_expires_at AND decision.evaluated_at<=clock_timestamp()
		FROM plugin_webhook_write_requests request
		JOIN plugin_webhook_entitlement_decisions decision ON decision.request_id=request.id
		WHERE request.tenant_scope_id=$1 AND request.subscription_id=$2`, fixture.actor.TargetScopeID,
		inside.Value.Subscription.ID).Scan(&withinRequest, &beforeCommit); err != nil {
		t.Fatal(err)
	}
	if !withinRequest || !beforeCommit {
		t.Fatalf("decision clock within request=%t before commit/lease=%t", withinRequest, beforeCommit)
	}
	var untilExpiry float64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT extract(epoch FROM (lease.expires_at-clock_timestamp()))
		FROM control_installation_entitlement installation
		JOIN entitlement_cached_leases lease ON lease.serial=installation.current_serial
		WHERE installation.singleton=true`).Scan(&untilExpiry); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Duration(untilExpiry*float64(time.Second)) + 100*time.Millisecond)
	inGrace, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Inside grace", TargetURL: "https://hooks.example.com/v1/inside-grace",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "shared-boundary-grace-1",
	})
	if err != nil {
		t.Fatalf("create after lease expiry inside grace = %v, want allowed", err)
	}
	var graceDecision bool
	if err = fixture.pool.QueryRow(t.Context(), `SELECT decision.evaluated_at>=decision.lease_expires_at
			AND decision.evaluated_at<decision.lease_grace_until
		FROM plugin_webhook_write_requests request
		JOIN plugin_webhook_entitlement_decisions decision ON decision.request_id=request.id
		WHERE request.tenant_scope_id=$1 AND request.subscription_id=$2`, fixture.actor.TargetScopeID,
		inGrace.Value.Subscription.ID).Scan(&graceDecision); err != nil || !graceDecision {
		t.Fatalf("grace decision recorded inside grace=%t err=%v", graceDecision, err)
	}

	if _, err := fixture.pool.Exec(t.Context(), `CREATE FUNCTION plugin_webhook_test_delay_completion_084()
		RETURNS trigger LANGUAGE plpgsql AS $$
		DECLARE deadline timestamptz;
		BEGIN
			IF OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL THEN
				SELECT lease.grace_until INTO deadline
				FROM control_installation_entitlement installation
				JOIN entitlement_cached_leases lease ON lease.serial=installation.current_serial
				WHERE installation.singleton=true;
				IF deadline IS NOT NULL AND clock_timestamp() <= deadline THEN
					PERFORM pg_sleep_until(deadline + interval '50 milliseconds');
				END IF;
			END IF;
			RETURN NEW;
		END
		$$`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `CREATE TRIGGER plugin_webhook_write_requests_01_test_delay_084
		BEFORE UPDATE ON plugin_webhook_write_requests
		FOR EACH ROW EXECUTE FUNCTION plugin_webhook_test_delay_completion_084()`); err != nil {
		t.Fatal(err)
	}
	var seconds float64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT extract(epoch FROM (lease.grace_until-clock_timestamp()))
		FROM control_installation_entitlement installation
		JOIN entitlement_cached_leases lease ON lease.serial=installation.current_serial
		WHERE installation.singleton=true`).Scan(&seconds); err != nil {
		t.Fatal(err)
	}
	if remaining := time.Duration(seconds * float64(time.Second)); remaining <= 250*time.Millisecond {
		t.Fatalf("fixture left only %v before grace end", remaining)
	}
	// The Go guard admits the write at transaction time; the completion then
	// physically crosses the grace end before 084 records its decision.
	_, err = fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Shared transaction boundary", TargetURL: "https://hooks.example.com/v1/shared-boundary",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "shared-boundary-create-1",
	})
	if !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("create across physical grace end = %v, want %v", err, ErrEntitlementDenied)
	}
	var subscriptions, requests, decisions int
	if err = fixture.pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1),
			(SELECT count(*) FROM plugin_webhook_write_requests WHERE tenant_scope_id=$1 AND idempotency_key='shared-boundary-create-1'),
			(SELECT count(*) FROM plugin_webhook_entitlement_decisions WHERE tenant_scope_id=$1)`,
		fixture.actor.TargetScopeID).Scan(&subscriptions, &requests, &decisions); err != nil {
		t.Fatal(err)
	}
	if subscriptions != 2 || requests != 0 || decisions != 2 {
		t.Fatalf("denied create left subscriptions/requests/decisions = %d/%d/%d, want 2/0/2", subscriptions, requests, decisions)
	}
}

func TestStoreActivationSurvivesEntitlementLoss(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Activation contract", TargetURL: "https://hooks.example.com/v1/activation-contract",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "activation-contract-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := fixture.store.RotateSecret(t.Context(), fixture.actor, created.Value.Subscription.ID, WriteRequest{
		IdempotencyKey: "activation-contract-rotate", Revision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	expiredCreated, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Expired activation contract", TargetURL: "https://hooks.example.com/v1/expired-activation-contract",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "expired-activation-contract-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	expiredRotation, err := fixture.store.RotateSecret(t.Context(), fixture.actor, expiredCreated.Value.Subscription.ID, WriteRequest{
		IdempotencyKey: "expired-activation-contract-rotate", Revision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err == nil {
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET created_at=clock_timestamp()-interval '24 hours 1 second',
				plugin_webhook_physical_created_at=clock_timestamp()-interval '24 hours 1 second',
				expires_at=clock_timestamp()-interval '1 second'
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 AND status='pending'`,
			fixture.actor.TargetScopeID, expiredCreated.Value.Subscription.ID, expiredRotation.Value.RotationID)
	}
	if err == nil {
		_, err = tx.Exec(t.Context(), `SET LOCAL session_replication_role='origin'`)
	}
	if err == nil {
		err = tx.Commit(t.Context())
	}
	if err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `UPDATE entitlement_cached_leases
		SET status='expired',not_before=clock_timestamp()-interval '2 hours',
			expires_at=clock_timestamp()-interval '1 hour',grace_until=clock_timestamp()
		WHERE serial=1`); err == nil {
		_, err = tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`)
	}
	if err == nil {
		_, err = tx.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
			SET issued_at=clock_timestamp()-interval '16 minutes',
				expires_at=clock_timestamp()-interval '1 minute',
				accepted_at=clock_timestamp()-interval '2 minutes' WHERE singleton=true`)
	}
	if err == nil {
		err = tx.Commit(t.Context())
	}
	if err != nil {
		t.Fatal(err)
	}

	forged := fixture.actor
	forged.ActorUserID = uuid.New()
	if _, err = fixture.store.ActivateSecret(t.Context(), forged, created.Value.Subscription.ID, rotation.Value.RotationID, WriteRequest{
		IdempotencyKey: "activation-contract-forged", Revision: 1,
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("forged activation error = %v, want permission denied", err)
	}
	if _, err = fixture.store.ActivateSecret(t.Context(), fixture.actor, created.Value.Subscription.ID, rotation.Value.RotationID, WriteRequest{
		IdempotencyKey: "activation-contract-stale", Revision: 2,
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale activation error = %v, want revision conflict", err)
	}

	activated, err := fixture.store.ActivateSecret(t.Context(), fixture.actor, created.Value.Subscription.ID, rotation.Value.RotationID, WriteRequest{
		IdempotencyKey: "activation-contract-activate", Revision: 1,
	})
	if err != nil {
		t.Fatalf("activation after entitlement loss error = %v", err)
	}
	if activated.Value.Subscription.Revision != 2 || activated.Value.Subscription.ActiveSecretVersionID != rotation.Value.RotationID {
		t.Fatalf("activated subscription = %+v", activated.Value.Subscription)
	}
	var activationDecisions int
	if err = fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_entitlement_decisions decision
		JOIN plugin_webhook_write_requests request ON request.id=decision.request_id
		WHERE request.tenant_scope_id=$1 AND request.operation=$2 AND request.rotation_id=$3`,
		fixture.actor.TargetScopeID, opActivate, rotation.Value.RotationID).Scan(&activationDecisions); err != nil || activationDecisions != 0 {
		t.Fatalf("activation entitlement decisions = %d, %v; want 0", activationDecisions, err)
	}
	if _, err = fixture.store.ActivateSecret(t.Context(), fixture.actor, expiredCreated.Value.Subscription.ID, expiredRotation.Value.RotationID, WriteRequest{
		IdempotencyKey: "expired-activation-contract-activate", Revision: 1,
	}); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("expired pending activation error = %v, want state conflict", err)
	}
	if _, err = fixture.store.ActivateSecret(t.Context(), fixture.actor, created.Value.Subscription.ID, rotation.Value.RotationID, WriteRequest{
		IdempotencyKey: "activation-contract-repeat", Revision: 2,
	}); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("repeated activation error = %v, want state conflict", err)
	}
	revoked, err := fixture.store.RevokeSubscription(t.Context(), fixture.actor, created.Value.Subscription.ID, WriteRequest{
		IdempotencyKey: "activation-contract-revoke", Revision: 2,
	})
	if err != nil || revoked.Value.Subscription.Status != "revoked" || revoked.Value.Subscription.Revision != 3 {
		t.Fatalf("revoke after entitlement loss = %+v, %v", revoked, err)
	}
}

func TestStoreRateLimitBoundaryConcurrencyAndReconnect(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	trace := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Rate concurrency", TargetURL: "https://hooks.example.com/v1/rate-concurrency",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "rate-concurrency-create-" + trace,
	})
	if err != nil {
		t.Fatal(err)
	}
	subscription := created.Value.Subscription.ID
	for index := 1; index <= 4; index++ {
		if _, err = fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription, WriteRequest{
			IdempotencyKey: fmt.Sprintf("rate-concurrency-seed-%s-%d", trace, index),
		}); err != nil {
			t.Fatalf("seed final slot %d: %v", index, err)
		}
	}

	boundarySubscription, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Rate boundary", TargetURL: "https://hooks.example.com/v1/rate-boundary",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "rate-boundary-create-" + trace,
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 2; index++ {
		if _, err = fixture.store.CreateTestDelivery(t.Context(), fixture.actor, boundarySubscription.Value.Subscription.ID, WriteRequest{
			IdempotencyKey: fmt.Sprintf("rate-boundary-seed-%s-%d", trace, index),
		}); err != nil {
			t.Fatalf("seed boundary %d: %v", index, err)
		}
	}
	rows, err := fixture.pool.Query(t.Context(), `SELECT id FROM plugin_webhook_rate_events
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND operation=$3 AND outcome='allowed'
		ORDER BY occurred_at,id`, fixture.actor.TargetScopeID, boundarySubscription.Value.Subscription.ID, opTest)
	if err != nil {
		t.Fatal(err)
	}
	boundaryIDs := make([]uuid.UUID, 0, 2)
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		boundaryIDs = append(boundaryIDs, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if len(boundaryIDs) != 2 {
		t.Fatalf("boundary rate facts = %d, want 2", len(boundaryIDs))
	}
	fixedBoundary := time.Now().UTC().Truncate(time.Microsecond)
	boundaryTx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer boundaryTx.Rollback(t.Context())
	if _, err = boundaryTx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err == nil {
		_, err = boundaryTx.Exec(t.Context(), `UPDATE plugin_webhook_rate_events
			SET plugin_webhook_physical_recorded_at=$2
			WHERE id=$1`, boundaryIDs[0], fixedBoundary.Add(-time.Minute))
	}
	if err == nil {
		_, err = boundaryTx.Exec(t.Context(), `UPDATE plugin_webhook_rate_events
			SET plugin_webhook_physical_recorded_at=$2
			WHERE id=$1`, boundaryIDs[1], fixedBoundary.Add(-time.Minute+time.Microsecond))
	}
	if err == nil {
		_, err = boundaryTx.Exec(t.Context(), `SET LOCAL session_replication_role='origin'`)
	}
	if err != nil {
		t.Fatal(err)
	}
	_, _, subscriptionCount, subscriptionRemaining, err := rateWindowCounts(
		t.Context(), boundaryTx, fixture.actor.TargetScopeID, opTest,
		boundarySubscription.Value.Subscription.ID, time.Minute, &fixedBoundary,
	)
	if err != nil {
		t.Fatal(err)
	}
	if subscriptionCount != 1 || subscriptionRemaining != 1 {
		t.Fatalf("strict lower boundary = count:%d remaining:%d, want 1,1", subscriptionCount, subscriptionRemaining)
	}
	if err = boundaryTx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	applicationNames := []string{"plugin-rate-a-" + trace, "plugin-rate-b-" + trace}
	_, firstStore := newRateLimitStore(t, fixture, applicationNames[0])
	_, secondStore := newRateLimitStore(t, fixture, applicationNames[1])
	blocker, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(t.Context())
	var blockerPID int32
	if err = blocker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blockerPID); err == nil {
		_, err = blocker.Exec(t.Context(), `SELECT pg_advisory_xact_lock(hashtextextended(
			'plugin-webhook-rate-tenant:'||$1::uuid::text||':'||$2,84))`, fixture.actor.TargetScopeID, opTest)
	}
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		err error
	}
	results := make(chan result, 2)
	runStore := func(index int, store *Store) {
		go func() {
			_, callErr := store.CreateTestDelivery(context.Background(), fixture.actor, subscription, WriteRequest{
				IdempotencyKey: fmt.Sprintf("rate-concurrency-final-%s-%d", trace, index),
			})
			results <- result{err: callErr}
		}()
	}
	runStore(0, firstStore)
	waitForBlockedRateStores(t, fixture.pool, applicationNames[:1])
	runStore(1, secondStore)
	waitForBlockedRateStores(t, fixture.pool, applicationNames)
	if err = blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	succeeded, denied := 0, 0
	for range 2 {
		result := <-results
		if result.err == nil {
			succeeded++
			continue
		}
		var limited RateLimitError
		if !errors.As(result.err, &limited) || limited.RetryAfter%time.Second != 0 ||
			limited.RetryAfter < time.Second || limited.RetryAfter > time.Minute {
			t.Fatalf("concurrent final slot = %v, retry=%v", result.err, limited.RetryAfter)
		}
		denied++
	}
	if succeeded != 1 || denied != 1 {
		t.Fatalf("concurrent final slot = success:%d denied:%d, want 1,1", succeeded, denied)
	}
	assertCommittedRateDenials(t, fixture, subscription, 1)

	_, reconnectedStore := newRateLimitStore(t, fixture, "plugin-rate-reconnect-"+trace)
	if _, err = reconnectedStore.CreateTestDelivery(t.Context(), fixture.actor, subscription, WriteRequest{
		IdempotencyKey: "rate-concurrency-reconnect-" + trace,
	}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("reconnected rate decision = %v, want rate limited", err)
	}
	var limited RateLimitError
	if !errors.As(err, &limited) || limited.RetryAfter%time.Second != 0 ||
		limited.RetryAfter < time.Second || limited.RetryAfter > time.Minute {
		t.Fatalf("reconnected retry after = %v", limited.RetryAfter)
	}
	assertCommittedRateDenials(t, fixture, subscription, 2)
}

func newRateLimitStore(t *testing.T, fixture storeIntegrationFixture, applicationName string) (*pgxpool.Pool, *Store) {
	t.Helper()
	config := fixture.pool.Config().Copy()
	params := make(map[string]string, len(config.ConnConfig.RuntimeParams)+1)
	for key, value := range config.ConnConfig.RuntimeParams {
		params[key] = value
	}
	params["application_name"] = applicationName
	config.ConnConfig.RuntimeParams = params
	config.MinConns = 0
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store := *fixture.store
	store.pool = pool
	store.commitBusinessWrite = commitTransaction
	return pool, &store
}

func waitForBlockedRateStores(t *testing.T, pool *pgxpool.Pool, applicationNames []string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE application_name=ANY($1::text[]) AND cardinality(pg_blocking_pids(pid))>0`, applicationNames).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked == len(applicationNames) {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("blocked rate stores = %d, want %d", blocked, len(applicationNames))
		case <-ticker.C:
		}
	}
}

func waitForBlockedIdempotencyCalls(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE pid<>pg_backend_pid() AND cardinality(pg_blocking_pids(pid))>0
			  AND query LIKE '%plugin-webhook-idempotency:%'`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("blocked idempotency calls = %d, want %d", blocked, want)
		case <-ticker.C:
		}
	}
}

func assertCommittedRateDenials(t *testing.T, fixture storeIntegrationFixture, subscription uuid.UUID, want int) {
	t.Helper()
	var count int
	err := fixture.pool.QueryRow(t.Context(), `SELECT count(*)
		FROM plugin_webhook_rate_events rate
		JOIN audit_events audit ON audit.id=rate.audit_event_id
		WHERE rate.tenant_scope_id=$1 AND rate.subscription_id=$2
		  AND rate.actor_scope_id=$3 AND rate.actor_user_id=$4
		  AND rate.operation=$5 AND rate.outcome='denied' AND rate.reason_code='rate_limited'
		  AND audit.scope_id=$1 AND audit.actor_user_id=$4 AND audit.action=$5 AND audit.result='denied'
		  AND audit.payload->>'actor_scope_id'=$3::uuid::text
		  AND audit.payload->>'target_scope_id'=$1::uuid::text
		  AND audit.payload->>'operation'=$5 AND audit.payload->>'reason'='rate_limited'`,
		fixture.actor.TargetScopeID, subscription, fixture.actor.ActorScopeID,
		fixture.actor.ActorUserID, opTest).Scan(&count)
	if err != nil || count != want {
		t.Fatalf("committed rate denials = %d,%v, want %d", count, err, want)
	}
}

func TestStoreAmbiguousCommitRecoversWithSameIdempotencyKey(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	restoreCommit := injectCommitResponseLoss(fixture.store)
	request := CreateSubscriptionRequest{
		Name: "Ambiguous commit", TargetURL: "https://hooks.example.com/v1/ambiguous",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "ambiguous-create-1",
	}
	if result, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, request); !errors.Is(err, ErrResultUnknown) || result.Value.Subscription.ID != uuid.Nil {
		t.Fatalf("ambiguous create replayed=%t subscription=%s error=%v; want result unknown", result.Replayed, result.Value.Subscription.ID, err)
	}
	restoreCommit()
	replayed, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, request)
	if err != nil || !replayed.Replayed || replayed.Value.Subscription.ID == uuid.Nil || len(replayed.Value.Secret) != 43 {
		t.Fatalf("same-key recovery replayed=%t subscription=%s secret_valid=%t error=%v", replayed.Replayed, replayed.Value.Subscription.ID, len(replayed.Value.Secret) == 43, err)
	}
	for name, query := range map[string]string{
		"subscriptions":  `SELECT count(*) FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND name='Ambiguous commit'`,
		"write requests": `SELECT count(*) FROM plugin_webhook_write_requests WHERE tenant_scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND idempotency_key='ambiguous-create-1'`,
		"audit events":   `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND payload->>'actor_scope_id'=$2::uuid::text AND actor_user_id=$3 AND action='plugin_webhook.subscription.create' AND request_id='ambiguous-create-1'`,
		"rate events":    `SELECT count(*) FROM plugin_webhook_rate_events WHERE tenant_scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND operation='plugin_webhook.subscription.create' AND outcome='allowed'`,
	} {
		var count int
		if err = fixture.pool.QueryRow(t.Context(), query, fixture.actor.TargetScopeID, fixture.actor.ActorScopeID, fixture.actor.ActorUserID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s count = %d, %v; want 1", name, count, err)
		}
	}
}

func TestStoreAmbiguousCommitRecoversEveryBusinessOperation(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Ambiguous operation matrix", TargetURL: "https://hooks.example.com/v1/ambiguous-matrix",
		EventTypes: []string{EventTypeTest}, IdempotencyKey: "ambiguous-matrix-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	subscription := created.Value.Subscription.ID

	testRequest := WriteRequest{IdempotencyKey: "ambiguous-test-1"}
	restoreCommit := injectCommitResponseLoss(fixture.store)
	if result, callErr := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription, testRequest); !errors.Is(callErr, ErrResultUnknown) || result.Value.Delivery.ID != uuid.Nil {
		t.Fatalf("ambiguous test delivery = %+v, %v; want result unknown", result, callErr)
	}
	restoreCommit()
	testDelivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription, testRequest)
	if err != nil || !testDelivery.Replayed || testDelivery.Value.Delivery.ID == uuid.Nil {
		t.Fatalf("test delivery recovery = %+v, %v", testDelivery, err)
	}
	assertAmbiguousOperationFacts(t, fixture, opTest, testRequest.IdempotencyKey, 1)
	assertDeliveryBusinessFacts(t, fixture, subscription, testDelivery.Value.Delivery.ID, uuid.Nil)
	markDeliveryDelivered(t, fixture, testDelivery.Value.Delivery.ID)

	replayRequest := WriteRequest{IdempotencyKey: "ambiguous-replay-1"}
	restoreCommit = injectCommitResponseLoss(fixture.store)
	if result, callErr := fixture.store.ReplayDelivery(t.Context(), fixture.actor, subscription, testDelivery.Value.Delivery.ID, replayRequest); !errors.Is(callErr, ErrResultUnknown) || result.Value.Delivery.ID != uuid.Nil {
		t.Fatalf("ambiguous replay delivery = %+v, %v; want result unknown", result, callErr)
	}
	restoreCommit()
	replayDelivery, err := fixture.store.ReplayDelivery(t.Context(), fixture.actor, subscription, testDelivery.Value.Delivery.ID, replayRequest)
	if err != nil || !replayDelivery.Replayed || replayDelivery.Value.Delivery.ID == uuid.Nil || replayDelivery.Value.Delivery.ReplayOf == nil || *replayDelivery.Value.Delivery.ReplayOf != testDelivery.Value.Delivery.ID {
		t.Fatalf("replay delivery recovery = %+v, %v", replayDelivery, err)
	}
	assertAmbiguousOperationFacts(t, fixture, opReplay, replayRequest.IdempotencyKey, 1)
	assertDeliveryBusinessFacts(t, fixture, subscription, replayDelivery.Value.Delivery.ID, testDelivery.Value.Delivery.ID)

	rotateRequest := WriteRequest{IdempotencyKey: "ambiguous-rotate-1", Revision: 1}
	restoreCommit = injectCommitResponseLoss(fixture.store)
	if result, callErr := fixture.store.RotateSecret(t.Context(), fixture.actor, subscription, rotateRequest); !errors.Is(callErr, ErrResultUnknown) || result.Value.RotationID != uuid.Nil || result.Value.Secret != "" {
		t.Fatalf("ambiguous rotation replayed=%t id=%s status=%s secret_empty=%t error=%v; want result unknown", result.Replayed, result.Value.RotationID, result.Value.Status, result.Value.Secret == "", callErr)
	}
	restoreCommit()
	rotation, err := fixture.store.RotateSecret(t.Context(), fixture.actor, subscription, rotateRequest)
	if err != nil || !rotation.Replayed || rotation.Value.RotationID == uuid.Nil || rotation.Value.Secret == "" {
		t.Fatalf("rotation recovery replayed=%t id=%s status=%s revision=%d secret_present=%t error=%v", rotation.Replayed, rotation.Value.RotationID, rotation.Value.Status, rotation.Value.SubscriptionRevision, rotation.Value.Secret != "", err)
	}
	rotationAgain, err := fixture.store.RotateSecret(t.Context(), fixture.actor, subscription, rotateRequest)
	if err != nil || !rotationAgain.Replayed || rotationAgain.Value.RotationID != rotation.Value.RotationID || rotationAgain.Value.Secret != rotation.Value.Secret {
		t.Fatalf("stable rotation replay replayed=%t id=%s status=%s revision=%d secret_matches=%t first_id=%s first_status=%s first_revision=%d error=%v", rotationAgain.Replayed, rotationAgain.Value.RotationID, rotationAgain.Value.Status, rotationAgain.Value.SubscriptionRevision, rotationAgain.Value.Secret == rotation.Value.Secret, rotation.Value.RotationID, rotation.Value.Status, rotation.Value.SubscriptionRevision, err)
	}
	assertAmbiguousOperationFacts(t, fixture, opRotate, rotateRequest.IdempotencyKey, 1)
	assertSecretVersionCount(t, fixture, rotation.Value.RotationID, "pending", 1)

	activateRequest := WriteRequest{IdempotencyKey: "ambiguous-activate-1", Revision: 1}
	restoreCommit = injectCommitResponseLoss(fixture.store)
	if result, callErr := fixture.store.ActivateSecret(t.Context(), fixture.actor, subscription, rotation.Value.RotationID, activateRequest); !errors.Is(callErr, ErrResultUnknown) || result.Value.Subscription.ID != uuid.Nil {
		t.Fatalf("ambiguous activation = %+v, %v; want result unknown", result, callErr)
	}
	restoreCommit()
	activated, err := fixture.store.ActivateSecret(t.Context(), fixture.actor, subscription, rotation.Value.RotationID, activateRequest)
	if err != nil || !activated.Replayed || activated.Value.Subscription.ID != subscription || activated.Value.Subscription.Revision != 2 || activated.Value.Subscription.ActiveSecretVersionID != rotation.Value.RotationID {
		t.Fatalf("activation recovery = %+v, %v", activated, err)
	}
	assertAmbiguousOperationFacts(t, fixture, opActivate, activateRequest.IdempotencyKey, 0)
	assertSecretVersionCount(t, fixture, rotation.Value.RotationID, "active", 1)

	revokeRequest := WriteRequest{IdempotencyKey: "ambiguous-revoke-1", Revision: 2}
	restoreCommit = injectCommitResponseLoss(fixture.store)
	if result, callErr := fixture.store.RevokeSubscription(t.Context(), fixture.actor, subscription, revokeRequest); !errors.Is(callErr, ErrResultUnknown) || result.Value.Subscription.ID != uuid.Nil {
		t.Fatalf("ambiguous revoke = %+v, %v; want result unknown", result, callErr)
	}
	restoreCommit()
	revoked, err := fixture.store.RevokeSubscription(t.Context(), fixture.actor, subscription, revokeRequest)
	if err != nil || !revoked.Replayed || revoked.Value.Subscription.ID != subscription || revoked.Value.Subscription.Status != "revoked" || revoked.Value.Subscription.Revision != 3 {
		t.Fatalf("revoke recovery = %+v, %v", revoked, err)
	}
	assertAmbiguousOperationFacts(t, fixture, opRevoke, revokeRequest.IdempotencyKey, 0)
}

func injectCommitResponseLoss(store *Store) func() {
	originalCommit := store.commitBusinessWrite
	injected := false
	store.commitBusinessWrite = func(ctx context.Context, tx pgx.Tx) error {
		if injected {
			return originalCommit(ctx, tx)
		}
		injected = true
		if err := originalCommit(ctx, tx); err != nil {
			return err
		}
		return errors.New("injected commit response loss")
	}
	return func() { store.commitBusinessWrite = originalCommit }
}

func assertAmbiguousOperationFacts(t *testing.T, fixture storeIntegrationFixture, operation, key string, wantRate int) {
	t.Helper()
	queries := []struct {
		name  string
		query string
		want  int
	}{
		{"write requests", `SELECT count(*) FROM plugin_webhook_write_requests WHERE tenant_scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND operation=$4 AND idempotency_key=$5`, 1},
		{"success audit events", `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND payload->>'actor_scope_id'=$2::uuid::text AND actor_user_id=$3 AND action=$4 AND request_id=$5 AND result='success'`, 1},
		{"allowed rate events", `SELECT count(*) FROM plugin_webhook_rate_events rate JOIN audit_events audit ON audit.id=rate.audit_event_id WHERE rate.tenant_scope_id=$1 AND rate.actor_scope_id=$2 AND rate.actor_user_id=$3 AND rate.operation=$4 AND audit.request_id=$5 AND rate.outcome='allowed'`, wantRate},
	}
	for _, current := range queries {
		var count int
		if err := fixture.pool.QueryRow(t.Context(), current.query, fixture.actor.TargetScopeID, fixture.actor.ActorScopeID, fixture.actor.ActorUserID, operation, key).Scan(&count); err != nil || count != current.want {
			t.Fatalf("%s for %s count = %d, %v; want %d", current.name, operation, count, err, current.want)
		}
	}
}

func assertDeliveryBusinessFacts(t *testing.T, fixture storeIntegrationFixture, subscription, delivery, replayOf uuid.UUID) {
	t.Helper()
	var outboxCount int
	var storedReplay *uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT replay_of FROM plugin_webhook_deliveries WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.actor.TargetScopeID, subscription, delivery).Scan(&storedReplay); err != nil {
		t.Fatal(err)
	}
	if replayOf == uuid.Nil && storedReplay != nil || replayOf != uuid.Nil && (storedReplay == nil || *storedReplay != replayOf) {
		t.Fatalf("delivery %s replay = %v; want %s", delivery, storedReplay, replayOf)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_outbox WHERE tenant_scope_id=$1 AND delivery_id=$2`, fixture.actor.TargetScopeID, delivery).Scan(&outboxCount); err != nil || outboxCount != 1 {
		t.Fatalf("outbox for delivery %s count = %d, %v; want 1", delivery, outboxCount, err)
	}
}

func markDeliveryDelivered(t *testing.T, fixture storeIntegrationFixture, delivery uuid.UUID) {
	t.Helper()
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err == nil {
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries SET status='delivered',nats_stream_sequence=1,nats_stream_created_unix_nano=1,attempt_count=1,queued_at=created_at,claimed_at=created_at,completed_at=created_at,next_attempt_at=NULL WHERE tenant_scope_id=$1 AND id=$2`, fixture.actor.TargetScopeID, delivery)
	}
	if err == nil {
		// Migration 084's published-outbox CHECK requires the full publication
		// identity; replica mode skips the attestation verification triggers.
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_outbox SET status='published',publish_attempt=1,
			leased_at=created_at,published_at=created_at,lease_token=NULL,lease_expires_at=NULL,
			publication_lease_token=gen_random_uuid(),publication_publish_attempt=1,publication_nats_domain='',
			publication_nats_stream='PLUGIN_WEBHOOK_DELIVERY_V2',publication_stream_created_unix_nano=1,
			publication_nats_subject='cdnca.plugin-webhook.delivery.v2.store-test',publication_nats_sequence=1,
			publication_expected_last_subject_sequence=0,publication_attestation_generation=1,
			publication_attestation_key_id='store-test-attestation-key',
			publication_attestation_sha256=sha256('store-test'::bytea),
			publication_attestation_signature=decode(repeat('00',64),'hex')
			WHERE tenant_scope_id=$1 AND delivery_id=$2`, fixture.actor.TargetScopeID, delivery)
	}
	if err == nil {
		_, err = tx.Exec(t.Context(), `SET LOCAL session_replication_role='origin'`)
	}
	if err == nil {
		err = tx.Commit(t.Context())
	}
	if err != nil {
		t.Fatal(err)
	}
}

func assertSecretVersionCount(t *testing.T, fixture storeIntegrationFixture, secret uuid.UUID, status string, want int) {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_secret_versions WHERE tenant_scope_id=$1 AND id=$2 AND status=$3`, fixture.actor.TargetScopeID, secret, status).Scan(&count); err != nil || count != want {
		t.Fatalf("secret %s status %s count = %d, %v; want %d", secret, status, count, err, want)
	}
}

type storeIntegrationFixture struct {
	pool          *pgxpool.Pool
	store         *Store
	actor         Actor
	platformActor Actor
}

func newStoreIntegrationFixture(t *testing.T) storeIntegrationFixture {
	return newStoreIntegrationFixtureWithLeaseWindow(t, time.Hour, time.Hour)
}

func newStoreIntegrationFixtureWithLeaseWindow(t *testing.T, leaseWindow, graceWindow time.Duration) storeIntegrationFixture {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "plugin_webhook_control_impl_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	if err = database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, targetScope, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	platformScope, platformUser, platformRole, platformSession := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Plugin control implementation')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{targetScope, tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL)`, []any{platformScope}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Plugin operator','unused')`, []any{userID, "plugin-impl-" + strings.ReplaceAll(userID.String(), "-", "")[:16]}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Plugin platform operator','unused')`, []any{platformUser, "plugin-platform-" + strings.ReplaceAll(platformUser.String(), "-", "")[:16]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{targetScope, userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{platformScope, platformUser}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','owner',true)`, []any{roleID, targetScope}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'platform_admin','platform admin',true)`, []any{platformRole, platformScope}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{targetScope, userID, roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{platformScope, platformUser, platformRole}},
	} {
		if _, err = pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("w", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := tokens.Mint(userID, targetScope, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	platformRaw, _, err := tokens.Mint(platformUser, platformScope, platformSession)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range []struct {
		id, user, scope uuid.UUID
	}{
		{sessionID, userID, targetScope},
		{platformSession, platformUser, platformScope},
	} {
		refresh := sha256.Sum256(session.id[:])
		if _, err = pool.Exec(ctx, `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, session.id, uuid.New(), session.user, session.scope, refresh[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x84}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	guard := installWebhookEntitlement(t, pool, now, leaseWindow, graceWindow)
	keyring := fixedKeyring{active: WrappingKey{ID: "plugin-webhook-kek-v1", Key: [32]byte{1, 2, 3, 4}}}
	store, err := NewStore(pool, iam, guard, keyring, NewTargetValidator())
	if err != nil {
		t.Fatal(err)
	}
	actor, err := NewActor(userID, targetScope, targetScope, ScopeTenant, raw)
	if err != nil {
		t.Fatal(err)
	}
	platformActor, err := NewActor(platformUser, platformScope, targetScope, ScopePlatform, platformRaw)
	if err != nil {
		t.Fatal(err)
	}
	return storeIntegrationFixture{pool: pool, store: store, actor: actor, platformActor: platformActor}
}

type entitlementSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (s entitlementSigner) KeyID() string { return s.id }
func (s entitlementSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.private, payload), nil
}

func installWebhookEntitlement(t *testing.T, pool *pgxpool.Pool, now time.Time, leaseWindow, graceWindow time.Duration) *entitlementguard.Guard {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	until := now.Add(24 * time.Hour)
	signer := entitlementSigner{id: "plugin-control-test-key", private: private}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: signer.id, PublicKey: public, NotBefore: now.Add(-24 * time.Hour), SignUntil: &until, VerifyUntil: &until}})
	if err != nil {
		t.Fatal(err)
	}
	keyFingerprint := sha256.Sum256(public)
	keysetPayload := []byte(fmt.Sprintf(
		`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[`+
			`{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,`+
			`"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		signer.id, signer.id, base64.RawURLEncoding.EncodeToString(public),
		base64.RawURLEncoding.EncodeToString(keyFingerprint[:]), now.Add(-24*time.Hour).Format(time.RFC3339Nano),
		until.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano)))
	keysetDigest := sha256.Sum256(keysetPayload)
	if _, err = pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(
		singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at
	) VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
		`"`+base64.RawURLEncoding.EncodeToString(keysetDigest[:])+`"`, signer.id,
		keysetPayload, keysetDigest[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at
	) VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, signer.id, public, now.Add(-24*time.Hour),
		until, keysetDigest[:], now); err != nil {
		t.Fatal(err)
	}
	const customer = "11111111-1111-4111-8111-111111111111"
	const installation = "22222222-2222-4222-8222-222222222222"
	const license = "33333333-3333-4333-8333-333333333333"
	issuedAt := now.Add(-time.Minute)
	revocation, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience, CustomerID: customer, InstallationID: installation, LicenseID: license, Revision: 1, IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(), RevokedSerials: []uint64{}}, signer, entitlement.RevocationKeyWindow{NotBefore: now.Add(-time.Hour), SignUntil: &until, VerifyUntil: &until})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := revocation.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entitlementguard.NewRevocationService(pool, trust).Accept(t.Context(), artifact, now); err != nil {
		t.Fatal(err)
	}
	lease := entitlement.Lease{Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience, CustomerID: customer, InstallationID: installation, LicenseID: license, Serial: 1, NotBefore: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(leaseWindow).Unix(), GraceUntil: now.Add(leaseWindow + graceWindow).Unix(), Version: entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"}, Features: []entitlement.Feature{{Code: entitlementguard.FeatureExtensionsWebhooks}}, Quotas: []entitlement.Quota{{Code: entitlementguard.QuotaExtensionsWebhooksCount, Limit: 100}}}
	signed, err := entitlement.Sign(t.Context(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entitlementguard.NewService(pool, trust).Install(t.Context(), entitlementguard.InstallBundle{InstallationID: installation, SignedLease: signed}, now); err != nil {
		t.Fatal(err)
	}
	return entitlementguard.NewGuard(pool, func() time.Time { return now }, trust)
}
