//go:build integration

package controlupgrade

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestLicenseReceiptOutboxClaimCASPredecessorDeliveryAndFailure(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	now := time.Now().UTC()

	store := NewStore(pool, nil, nil, func() time.Time { return now })
	claims, err := store.ClaimParentGrantReceipts(t.Context(), "receipt-worker", now, time.Minute, 8)
	if err != nil || len(claims) != 1 || claims[0].Receipt.Status != parentGrantReceiptFetched {
		t.Fatalf("initial claim = (%#v,%v)", claims, err)
	}
	if blocked, err := store.ClaimParentGrantReceipts(t.Context(), "second-worker", now, time.Minute, 8); err != nil || len(blocked) != 0 {
		t.Fatalf("successor claimed before predecessor delivery = (%#v,%v)", blocked, err)
	}
	fetched := claims[0]
	response := ParentGrantReceiptResponse{Schema: parentGrantReceiptResponseSchema,
		RequestID: fetched.Receipt.ID, ReceiptID: "00000000-0000-4000-8000-0000000000b1",
		AcceptedStatus: fetched.Receipt.Status, ReceivedAt: time.Now().UTC().Truncate(time.Second)}
	if err := store.SettleParentGrantReceipt(t.Context(), ParentGrantReceiptSettlement{
		ReceiptID: fetched.Receipt.ID, ClaimToken: fetched.ClaimToken,
		LogicalDigest: fetched.Receipt.LogicalDigest, Disposition: ParentGrantReceiptDelivered,
		Response: response, SettledAt: now.Add(365 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SettleParentGrantReceipt(t.Context(), ParentGrantReceiptSettlement{
		ReceiptID: fetched.Receipt.ID, ClaimToken: fetched.ClaimToken,
		LogicalDigest: fetched.Receipt.LogicalDigest, Disposition: ParentGrantReceiptDelivered,
		Response: response, SettledAt: now.Add(2 * time.Second),
	}); !errors.Is(err, ErrLicenseReceiptClaimLost) {
		t.Fatalf("stale settlement error = %v", err)
	}

	claims, err = store.ClaimParentGrantReceipts(t.Context(), "receipt-worker", now, time.Minute, 8)
	if err != nil || len(claims) != 1 || claims[0].Receipt.Status != parentGrantReceiptVerified {
		t.Fatalf("successor claim = (%#v,%v)", claims, err)
	}
	verified := claims[0]
	callerFuture := time.Now().UTC().Add(365 * 24 * time.Hour)
	if err := store.SettleParentGrantReceipt(t.Context(), ParentGrantReceiptSettlement{
		ReceiptID: verified.Receipt.ID, ClaimToken: verified.ClaimToken,
		LogicalDigest: verified.Receipt.LogicalDigest, Disposition: ParentGrantReceiptRetryable,
		AvailableAt: callerFuture, ErrorCode: "license_unavailable", SettledAt: now.Add(-365 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	var availableAt, updatedAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT available_at,updated_at
		FROM control_upgrade_license_receipt_outbox_097 WHERE id=$1`, verified.Receipt.ID).
		Scan(&availableAt, &updatedAt); err != nil {
		t.Fatal(err)
	}
	if delay := availableAt.Sub(updatedAt); delay != 500*time.Millisecond {
		t.Fatalf("retry schedule used caller clock: available=%s updated=%s delay=%s", availableAt, updatedAt, delay)
	}
	if claims, err = store.ClaimParentGrantReceipts(t.Context(), "receipt-worker", now, time.Minute, 8); err != nil || len(claims) != 0 {
		t.Fatalf("receipt claimed before retry time = (%#v,%v)", claims, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(claims) == 0 && time.Now().Before(deadline) {
		claims, err = store.ClaimParentGrantReceipts(t.Context(), "receipt-worker", now, time.Minute, 8)
	}
	if err != nil || len(claims) != 1 || claims[0].AttemptCount != verified.AttemptCount+1 {
		t.Fatalf("retry claim = (%#v,%v)", claims, err)
	}
	if err := store.SettleParentGrantReceipt(t.Context(), ParentGrantReceiptSettlement{
		ReceiptID: claims[0].Receipt.ID, ClaimToken: claims[0].ClaimToken,
		LogicalDigest: claims[0].Receipt.LogicalDigest, Disposition: ParentGrantReceiptFailed,
		ErrorCode: "permanent_response", SettledAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if failed, err := store.HasFailedParentGrantReceipt(t.Context()); err != nil || !failed {
		t.Fatalf("failed readiness = (%t,%v)", failed, err)
	}

	if _, err := pool.Exec(t.Context(), `UPDATE control_upgrade_license_receipt_outbox_097
		SET installed_version='9.9.9' WHERE id=$1`, claims[0].Receipt.ID); !postgresCode097(err, "P9702") {
		t.Fatalf("immutable outbox update error = %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE control_upgrade_license_receipt_deliveries_097
		SET accepted_status='verified' WHERE request_id=$1`, fetched.Receipt.ID); !postgresCode097(err, "P9702") {
		t.Fatalf("immutable delivery update error = %v", err)
	}
}

func TestLicenseReceiptOutboxUsesDatabaseClockAndTwoRuntimeCAS(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)

	stores := []*Store{NewStore(pool, nil, nil, time.Now), NewStore(pool, nil, nil, time.Now)}
	skewed := time.Now().UTC().Add(365 * 24 * time.Hour)
	type result struct {
		claims []ParentGrantReceiptClaim
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, len(stores))
	var workers sync.WaitGroup
	for index, store := range stores {
		workers.Add(1)
		go func(index int, store *Store) {
			defer workers.Done()
			<-start
			claims, err := store.ClaimParentGrantReceipts(context.Background(),
				"receipt-cas-"+string(rune('a'+index)), skewed, time.Minute, 1)
			results <- result{claims: claims, err: err}
		}(index, store)
	}
	close(start)
	workers.Wait()
	close(results)
	var claimed ParentGrantReceiptClaim
	claimCount := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		claimCount += len(result.claims)
		if len(result.claims) == 1 {
			claimed = result.claims[0]
		}
	}
	if claimCount != 1 {
		t.Fatalf("two-runtime claim count = %d, want 1", claimCount)
	}
	var claimedAt, expiresAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT claimed_at,claim_expires_at
		FROM control_upgrade_license_receipt_outbox_097 WHERE id=$1`, claimed.Receipt.ID).
		Scan(&claimedAt, &expiresAt); err != nil {
		t.Fatal(err)
	}
	databaseNow := time.Now().UTC()
	if claimedAt.After(databaseNow.Add(5*time.Second)) || claimedAt.Before(databaseNow.Add(-5*time.Second)) ||
		expiresAt.Sub(claimedAt) < 59*time.Second || expiresAt.Sub(claimedAt) > 61*time.Second {
		t.Fatalf("claim used caller clock: claimed=%s expires=%s db-now=%s", claimedAt, expiresAt, databaseNow)
	}

	response := ParentGrantReceiptResponse{Schema: parentGrantReceiptResponseSchema,
		RequestID: claimed.Receipt.ID, ReceiptID: "00000000-0000-4000-8000-0000000000d1",
		AcceptedStatus: claimed.Receipt.Status, ReceivedAt: time.Now().UTC().Truncate(time.Second)}
	if err := stores[0].SettleParentGrantReceipt(t.Context(), ParentGrantReceiptSettlement{
		ReceiptID: claimed.Receipt.ID, ClaimToken: claimed.ClaimToken,
		LogicalDigest: claimed.Receipt.LogicalDigest, Disposition: ParentGrantReceiptDelivered,
		Response: response, SettledAt: skewed,
	}); err != nil {
		t.Fatal(err)
	}
	var updatedAt, recordedAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT receipt.updated_at,delivery.created_at
		FROM control_upgrade_license_receipt_outbox_097 receipt
		JOIN control_upgrade_license_receipt_deliveries_097 delivery ON delivery.request_id=receipt.id
		WHERE receipt.id=$1`, claimed.Receipt.ID).Scan(&updatedAt, &recordedAt); err != nil {
		t.Fatal(err)
	}
	databaseNow = time.Now().UTC()
	if updatedAt.After(databaseNow.Add(5*time.Second)) || recordedAt.After(databaseNow.Add(5*time.Second)) ||
		updatedAt.Before(databaseNow.Add(-5*time.Second)) || recordedAt.Before(databaseNow.Add(-5*time.Second)) {
		t.Fatalf("settlement used caller clock: updated=%s recorded=%s db-now=%s", updatedAt, recordedAt, databaseNow)
	}
}

func TestLicenseReceiptDeliveryRejectsForgedServerFactsWithP9702(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	now := time.Now().UTC().Truncate(time.Second)
	store := NewStore(pool, nil, nil, time.Now)
	claims, err := store.ClaimParentGrantReceipts(t.Context(), "receipt-forgery", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim = (%#v,%v)", claims, err)
	}
	claim := claims[0]
	for name, query := range map[string]string{
		"nil receipt": `INSERT INTO control_upgrade_license_receipt_deliveries_097(
			request_id,logical_digest,response_schema,receipt_id,accepted_status,received_at,
			response_bytes,response_sha256,created_at)
			SELECT id,logical_digest,'upgrade-grant.receipt-response/v1',
			'00000000-0000-0000-0000-000000000000',status,to_timestamp(1),
			convert_to('{}','UTF8'),sha256(convert_to('{}','UTF8')),transaction_timestamp()
			FROM control_upgrade_license_receipt_outbox_097 WHERE id=$1`,
		"response schema": `INSERT INTO control_upgrade_license_receipt_deliveries_097(
			request_id,logical_digest,response_schema,receipt_id,accepted_status,received_at,
			response_bytes,response_sha256,created_at)
			SELECT id,logical_digest,'wrong-schema','00000000-0000-4000-8000-0000000000d2',
			status,to_timestamp(1),convert_to('{}','UTF8'),sha256(convert_to('{}','UTF8')),
			transaction_timestamp() FROM control_upgrade_license_receipt_outbox_097 WHERE id=$1`,
		"nonpositive received": `INSERT INTO control_upgrade_license_receipt_deliveries_097(
			request_id,logical_digest,response_schema,receipt_id,accepted_status,received_at,
			response_bytes,response_sha256,created_at)
			SELECT id,logical_digest,'upgrade-grant.receipt-response/v1',
			'00000000-0000-4000-8000-0000000000d3',status,to_timestamp(0),
			convert_to('{}','UTF8'),sha256(convert_to('{}','UTF8')),transaction_timestamp()
			FROM control_upgrade_license_receipt_outbox_097 WHERE id=$1`,
		"forged recorded time": `INSERT INTO control_upgrade_license_receipt_deliveries_097(
			request_id,logical_digest,response_schema,receipt_id,accepted_status,received_at,
			response_bytes,response_sha256,created_at)
			SELECT id,logical_digest,'upgrade-grant.receipt-response/v1',
			'00000000-0000-4000-8000-0000000000d4',status,to_timestamp(1),
			convert_to('{}','UTF8'),sha256(convert_to('{}','UTF8')),to_timestamp(1)
			FROM control_upgrade_license_receipt_outbox_097 WHERE id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pool.Exec(t.Context(), query, claim.Receipt.ID); !postgresCode097(err, "P9702") {
				t.Fatalf("forged delivery error = %v", err)
			}
		})
	}
}

func TestTerminalLicenseReceiptUsesDatabaseClockUnderFutureSkew(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	input := validRolloutPlanInput()
	input.Groups = input.Groups[:1]
	plan, err := NewRolloutPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	store := NewStore(pool, nil, nil, func() time.Time {
		return time.Now().UTC().Add(365 * 24 * time.Hour)
	})
	startCommand := planCommand(PlanStart, plan.Revision, "start_requested")
	startCause, _ := rolloutCause(t, startCommand)
	started, err := store.TransactLocked(t.Context(), identity, plan.ID, startCause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			return rolloutStartMutation(t, locked, startCause, time.Now().UTC()), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	health := currentPlanHealth(started.Plan, nodeID(1), true)
	healthCause, healthBytes := rolloutCause(t, health)
	completed, err := store.TransactLocked(t.Context(), identity, plan.ID, healthCause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			result := mustPlanHealth(t, locked.Plan, health)
			event := rolloutEventMutation(t, healthCause, healthBytes, result.Event)
			return rolloutMutation(t, locked.Plan.Revision, result.Plan,
				[]RolloutEventMutation{event}, nil, nil), nil
		})
	if err != nil || completed.Plan.State != PlanCompleted || completed.Plan.Completion != CompletionUpgraded {
		t.Fatalf("terminal commit = (%#v,%v)", completed.Plan, err)
	}
	var eventAt, planAt, observedAt, availableAt, createdAt, updatedAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT event.created_at,plan.updated_at,receipt.observed_at,
		receipt.available_at,receipt.created_at,receipt.updated_at
		FROM control_upgrade_rollout_plans plan
		JOIN control_upgrade_rollout_events event ON event.plan_id=plan.id AND event.revision=$2
		JOIN control_upgrade_license_receipt_outbox_097 receipt ON receipt.plan_id=plan.id AND receipt.status='applied'
		WHERE plan.id=$1`, plan.ID, completed.Plan.Revision).
		Scan(&eventAt, &planAt, &observedAt, &availableAt, &createdAt, &updatedAt); err != nil {
		t.Fatal(err)
	}
	databaseNow := time.Now().UTC()
	if eventAt.Before(databaseNow.Add(-5*time.Second)) || eventAt.After(databaseNow.Add(5*time.Second)) ||
		!planAt.Equal(eventAt) || !observedAt.Equal(eventAt.Truncate(time.Second)) ||
		!availableAt.Equal(observedAt) || !createdAt.Equal(observedAt) || !updatedAt.Equal(observedAt) {
		t.Fatalf("terminal receipt clock binding event=%s plan=%s observed=%s available=%s created=%s updated=%s db-now=%s",
			eventAt, planAt, observedAt, availableAt, createdAt, updatedAt, databaseNow)
	}
}

func postgresCode097(err error, code string) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == code
}
