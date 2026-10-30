package acmeworker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPGOperationClaimLeaseFencingAndTenantIsolation(t *testing.T) {
	fixture := newPGFixture(t)
	now := fixture.databaseNow(t)
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "shared-operation")
	fixture.bindIssueRequest(t, request)
	digest := issueRequestDigest(request)
	store := fixture.store

	start := make(chan struct{})
	claims := make([]OperationClaim, 2)
	errs := make([]error, 2)
	var wait sync.WaitGroup
	for index := range claims {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			claims[index], errs[index] = store.Claim(context.Background(), request, digest, now, now.Add(2*time.Second))
		}(index)
	}
	close(start)
	wait.Wait()
	var winner OperationLease
	states := []OperationClaimState{claims[0].State, claims[1].State}
	if !slices.Contains(states, OperationClaimed) || !slices.Contains(states, OperationBusy) || errs[0] != nil || errs[1] != nil {
		t.Fatalf("concurrent claims=%+v errors=%v", claims, errs)
	}
	for _, claim := range claims {
		if claim.State == OperationClaimed {
			winner = claim.Lease
		}
	}

	conflict := request
	conflict.Domains = []string{"different.example.test"}
	if _, err := store.Claim(context.Background(), conflict, issueRequestDigest(conflict), now, now.Add(time.Minute)); ErrorCodeOf(err) != CodeOperationConflict {
		t.Fatalf("different payload claim error = %v", err)
	}

	now = fixture.waitForDatabaseTimeAfter(t, winner.ExpiresAt)
	if _, err := store.Advance(context.Background(), winner, "account_registered",
		OperationState{Phase: PhaseClaimed, Status: OperationActive, AccountURI: "https://ca.example/account/1"},
		now); ErrorCodeOf(err) != CodeLeaseLost {
		t.Fatalf("expired lease Advance() error = %v", err)
	}
	takeover, err := store.Claim(context.Background(), request, digest, now, now.Add(time.Minute))
	if err != nil || takeover.State != OperationClaimed || takeover.Lease.Token == winner.Token {
		t.Fatalf("takeover = %+v, error=%v", takeover, err)
	}
	if _, err := store.Advance(context.Background(), winner, "account_registered",
		OperationState{Phase: PhaseClaimed, Status: OperationActive, AccountURI: "https://ca.example/account/old"},
		now); ErrorCodeOf(err) != CodeLeaseLost {
		t.Fatalf("fenced old lease Advance() error = %v", err)
	}
	seedPGAccountRegistration(t, store, request, "https://ca.example/account/1")
	updated, err := store.Advance(context.Background(), takeover.Lease, "account_registered",
		OperationState{Phase: PhaseClaimed, Status: OperationActive, AccountURI: "https://ca.example/account/1"},
		now)
	if err != nil || updated.Revision != takeover.Lease.Revision+1 {
		t.Fatalf("current lease Advance() = %+v, %v", updated, err)
	}

	secondTenant := fixture.addTenant(t)
	secondRequest := pgIssueRequest(secondTenant, "second-tenant-operation")
	fixture.bindIssueRequest(t, secondRequest)
	now = fixture.databaseNow(t)
	second, err := store.Claim(context.Background(), secondRequest, issueRequestDigest(secondRequest), now, now.Add(time.Minute))
	if err != nil || second.State != OperationClaimed {
		t.Fatalf("second tenant claim = %+v, %v", second, err)
	}
}

func TestPGChallengeFactsPreserveExactSameOwnerValues(t *testing.T) {
	fixture := newPGFixture(t)
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "same-owner-values")
	request.Domains = []string{"*.example.test", "example.test"}
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	lease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now, []string{
		"https://ca.example/authz/apex", "https://ca.example/authz/wildcard",
	})
	first, err := fixture.store.PrepareChallenge(context.Background(), lease, ownedChallenge(lease, ChallengeIdentity{
		ProviderRef:      request.ProviderRef,
		AuthorizationURL: "https://ca.example/authz/apex", ChallengeURL: "https://ca.example/challenge/apex",
		ChallengeType: ChallengeDNS01, Identifier: "example.test", RecordName: "_acme-challenge.example.test.",
		Token: "apex-token", ExactValue: "apex-exact-value",
	}), now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.store.PrepareChallenge(context.Background(), lease, ownedChallenge(lease, ChallengeIdentity{
		ProviderRef:      request.ProviderRef,
		AuthorizationURL: "https://ca.example/authz/wildcard", ChallengeURL: "https://ca.example/challenge/wildcard",
		ChallengeType: ChallengeDNS01, Identifier: "example.test", Wildcard: true,
		RecordName: "_acme-challenge.example.test.", Token: "wildcard-token", ExactValue: "wildcard-exact-value",
	}), now)
	if err != nil {
		t.Fatal(err)
	}
	first.TXTHandle = RemoteTXTHandle{ProviderRef: request.ProviderRef, RecordRef: "record/apex"}
	second.TXTHandle = RemoteTXTHandle{ProviderRef: request.ProviderRef, RecordRef: "record/wildcard"}
	if err := fixture.store.MarkChallenge(context.Background(), lease, first, "published", now); err != nil {
		t.Fatalf("MarkChallenge() error = %v", err)
	}
	if err := fixture.store.MarkChallenge(context.Background(), lease, second, "published", now); err != nil {
		t.Fatal(err)
	}
	cleanup, err := fixture.store.ClaimChallengeCleanup(context.Background(), lease, first, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup.Complete(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	outstanding, err := fixture.store.OutstandingChallenges(context.Background(), lease, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(outstanding) != 1 || outstanding[0].AttemptID != second.AttemptID ||
		outstanding[0].RecordName != first.RecordName || outstanding[0].ExactValue != second.ExactValue ||
		outstanding[0].TXTHandle != second.TXTHandle {
		t.Fatalf("outstanding challenges = %+v", outstanding)
	}
}

func TestPG047DNSRemoteHandleFailsClosed(t *testing.T) {
	fixture := newPGFixtureAt47(t)
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "047-dns-fail-closed")
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	lease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now,
		[]string{"https://ca.example/authz/047"})
	challenge, err := fixture.store.PrepareChallenge(context.Background(), lease, ownedChallenge(lease, ChallengeIdentity{
		ProviderRef: request.ProviderRef, AuthorizationURL: "https://ca.example/authz/047",
		ChallengeURL: "https://ca.example/challenge/047", ChallengeType: ChallengeDNS01,
		Identifier: "example.test", RecordName: "_acme-challenge.example.test.",
		Token: "token-047", ExactValue: "exact-value-047",
	}), now)
	if err != nil {
		t.Fatal(err)
	}
	published := challenge
	published.TXTHandle = RemoteTXTHandle{ProviderRef: request.ProviderRef, RecordRef: "record/047"}
	if err := fixture.store.MarkChallenge(context.Background(), lease, published, "published", now); ErrorCodeOf(err) != CodeOperationStoreFailed {
		t.Fatalf("047 MarkChallenge() error = %v", err)
	}
	outstanding, err := fixture.store.OutstandingChallenges(context.Background(), lease, now)
	if err != nil || len(outstanding) != 1 || outstanding[0].TXTHandle != (RemoteTXTHandle{}) {
		t.Fatalf("047 outstanding=%+v error=%v", outstanding, err)
	}
	records := &challengeRecords{}
	worker := &Worker{
		config: Config{Clock: func() time.Time { return now }, CleanupTimeout: time.Second},
		deps:   Dependencies{Operations: fixture.store, DNS01: records},
	}
	if err := worker.cleanupChallenge(context.Background(), lease, outstanding[0]); ErrorCodeOf(err) != CodeChallengeCleanupFailed {
		t.Fatalf("047 cleanup error = %v", err)
	}
	if len(records.waited) != 0 || len(records.deleted) != 0 {
		t.Fatalf("047 provider calls observed=%v deleted=%v", records.waited, records.deleted)
	}
}

func TestPGDNSChallengeRecordNameRequiresLiteralPrefixAndTrailingDot(t *testing.T) {
	fixture := newPGFixture(t)
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "dns-record-name")
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	lease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now, []string{
		"https://ca.example/authz/valid", "https://ca.example/authz/invalid",
	})
	if _, err := fixture.store.PrepareChallenge(context.Background(), lease, ownedChallenge(lease, ChallengeIdentity{
		ProviderRef: request.ProviderRef, AuthorizationURL: "https://ca.example/authz/valid", ChallengeURL: "https://ca.example/challenge/valid",
		ChallengeType: ChallengeDNS01, Identifier: "example.test",
		RecordName: "_acme-challenge.example.test.", Token: "valid-token", ExactValue: "valid-value",
	}), now); err != nil {
		t.Fatalf("valid DNS record name: %v", err)
	}
	for _, recordName := range []string{
		"xacme-challenge.example.test.",
		"_acme-challenge.other.test.",
		"_acme-challenge.example.test",
	} {
		_, err := fixture.pool.Exec(context.Background(), `
			INSERT INTO acme_issuance_challenge_attempts (
				tenant_scope_id,operation_id,attempt_id,attempt_number,authorization_url,
				challenge_url,challenge_type,identifier,wildcard,record_name,token,exact_value,created_at
			) VALUES ($1,$2,$3,1,$4,$5,'dns-01','example.test',false,$6,$7,$8,$9)`,
			tenantID, request.OperationID, uuid.New(), "https://ca.example/authz/invalid",
			"https://ca.example/challenge/invalid", recordName, "invalid-token", "invalid-value", now)
		assertPGSQLState(t, err, "23514")
	}
	for _, attempt := range []struct {
		identifier string
		wildcard   bool
	}{
		{identifier: "unrelated.test"},
		{identifier: "example.test", wildcard: true},
	} {
		_, err := fixture.pool.Exec(context.Background(), `
			INSERT INTO acme_issuance_challenge_attempts (
				tenant_scope_id,operation_id,attempt_id,attempt_number,authorization_url,
				challenge_url,challenge_type,identifier,wildcard,record_name,token,exact_value,created_at
			) VALUES ($1,$2,$3,1,$4,$5,'dns-01',$6,$7,'_acme-challenge.' || $6 || '.',$8,$9,$10)`,
			tenantID, request.OperationID, uuid.New(), "https://ca.example/authz/invalid",
			"https://ca.example/challenge/invalid", attempt.identifier, attempt.wildcard,
			"invalid-token", "invalid-value", now)
		assertPGGuard(t, err)
	}
}

func TestPGMarkChallengeRejectsCleanupStatesWithoutSideEffects(t *testing.T) {
	fixture := newPGFixture(t)
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "mark-cleanup-state")
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	lease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now,
		[]string{"https://ca.example/authz/mark-cleanup"})
	challenge, err := fixture.store.PrepareChallenge(context.Background(), lease, ownedChallenge(lease, ChallengeIdentity{
		ProviderRef: request.ProviderRef, AuthorizationURL: "https://ca.example/authz/mark-cleanup",
		ChallengeURL: "https://ca.example/challenge/mark-cleanup", ChallengeType: ChallengeDNS01,
		Identifier: "example.test", RecordName: "_acme-challenge.example.test.",
		Token: "mark-cleanup-token", ExactValue: "mark-cleanup-value",
	}), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"cleanup_claimed", "cleaned"} {
		if err := fixture.store.MarkChallenge(context.Background(), lease, challenge, state, now); ErrorCodeOf(err) != CodeInvalidInput {
			t.Fatalf("MarkChallenge(%q) error = %v", state, err)
		}
	}
	var count int
	var state string
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT count(*), min(state)
		FROM acme_issuance_challenge_events
		WHERE tenant_scope_id=$1 AND operation_id=$2 AND attempt_id=$3`,
		tenantID, request.OperationID, challenge.AttemptID).Scan(&count, &state); err != nil {
		t.Fatal(err)
	}
	provider := &challengeRecords{}
	if count != 1 || state != "intent" || len(provider.published) != 0 || len(provider.deleted) != 0 {
		t.Fatalf("facts=%d/%s provider=%+v", count, state, provider)
	}
}

func TestPGLeaseFencingUsesDatabaseClock(t *testing.T) {
	fixture := newPGFixture(t)
	tenantID := fixture.addTenant(t)
	now := fixture.databaseNow(t)
	expiredRequest := pgIssueRequest(tenantID, "database-clock-expired")
	fixture.bindIssueRequest(t, expiredRequest)
	expired, err := fixture.store.Claim(context.Background(), expiredRequest,
		issueRequestDigest(expiredRequest), now, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now = fixture.waitForDatabaseTimeAfter(t, expired.Lease.ExpiresAt)
	_, err = fixture.pool.Exec(context.Background(), `
		INSERT INTO acme_issuance_operation_events (
			tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
			order_intent_pending,lease_token,lease_expires_at,next_reconcile_at,account_uri,
			order_url,finalize_url,authorization_urls,certificate_url,certificate_spki_sha256,
			leaf_fingerprint_sha256,failure_code,occurred_at
		) SELECT tenant_scope_id,operation_id,revision+1,'account_registered','claimed','active',
			fence_token,order_intent_pending,lease_token,lease_expires_at,next_reconcile_at,
			'https://ca.example/account/backdated',order_url,finalize_url,authorization_urls,
			certificate_url,certificate_spki_sha256,leaf_fingerprint_sha256,failure_code,occurred_at
		  FROM acme_issuance_operation_events
		  WHERE tenant_scope_id=$1 AND operation_id=$2 ORDER BY revision DESC LIMIT 1`,
		tenantID, expiredRequest.OperationID)
	assertPGGuard(t, err)

	liveNow := fixture.databaseNow(t)
	liveRequest := pgIssueRequest(tenantID, "database-clock-live")
	fixture.bindIssueRequest(t, liveRequest)
	live, err := fixture.store.Claim(context.Background(), liveRequest,
		issueRequestDigest(liveRequest), liveNow, liveNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	newToken := uuid.New()
	futureEvent := liveNow.Add(2 * time.Minute)
	_, err = fixture.pool.Exec(context.Background(), `
		INSERT INTO acme_issuance_operation_events (
			tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
			order_intent_pending,lease_token,lease_expires_at,next_reconcile_at,account_uri,
			order_url,finalize_url,authorization_urls,certificate_url,certificate_spki_sha256,
			leaf_fingerprint_sha256,failure_code,occurred_at
		) SELECT tenant_scope_id,operation_id,revision+1,'lease_taken_over',phase,'active',$3,
			order_intent_pending,$3,$4,NULL,account_uri,order_url,finalize_url,authorization_urls,
			certificate_url,certificate_spki_sha256,leaf_fingerprint_sha256,NULL,$5
		  FROM acme_issuance_operation_events
		  WHERE tenant_scope_id=$1 AND operation_id=$2 ORDER BY revision DESC LIMIT 1`,
		tenantID, liveRequest.OperationID, newToken, futureEvent.Add(time.Minute), futureEvent)
	assertPGGuard(t, err)
	if live.Lease.Token == newToken {
		t.Fatal("test setup reused the live lease token")
	}
}

func TestPGFenceTxValidatesLeaseWithoutAdvancingState(t *testing.T) {
	fixture := newPGFixture(t)
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "fence-tx")
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(
		context.Background(), request, issueRequestDigest(request), now, now.Add(2*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fenced, databaseNow, err := fixture.store.FenceTx(context.Background(), tx, claim.Lease)
	if err != nil || databaseNow.IsZero() || fenced.Revision != claim.Lease.Revision ||
		fenced.Token != claim.Lease.Token || !issueRequestsEqual(fenced.Request, request) {
		_ = tx.Rollback(context.Background())
		t.Fatalf("FenceTx() lease=%+v database_now=%s error=%v", fenced, databaseNow, err)
	}
	var eventCount int
	var maxRevision int64
	if err := tx.QueryRow(context.Background(), `
		SELECT count(*), max(revision)
		FROM acme_issuance_operation_events
		WHERE tenant_scope_id=$1 AND operation_id=$2`, tenantID, request.OperationID,
	).Scan(&eventCount, &maxRevision); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	if eventCount != 1 || maxRevision != claim.Lease.Revision {
		_ = tx.Rollback(context.Background())
		t.Fatalf("FenceTx advanced state: count=%d revision=%d", eventCount, maxRevision)
	}
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}

	staleLeases := []OperationLease{claim.Lease, claim.Lease, claim.Lease}
	staleLeases[0].Token = uuid.New()
	staleLeases[1].Revision++
	staleLeases[2].Request.ActorUserID = uuid.New()
	for _, stale := range staleLeases {
		tx, err := fixture.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_, _, fenceErr := fixture.store.FenceTx(context.Background(), tx, stale)
		_ = tx.Rollback(context.Background())
		if ErrorCodeOf(fenceErr) != CodeLeaseLost {
			t.Fatalf("stale FenceTx() error = %v", fenceErr)
		}
	}

	fixture.waitForDatabaseTimeAfter(t, claim.Lease.ExpiresAt)
	tx, err = fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = fixture.store.FenceTx(context.Background(), tx, claim.Lease)
	_ = tx.Rollback(context.Background())
	if ErrorCodeOf(err) != CodeLeaseLost {
		t.Fatalf("expired FenceTx() error = %v", err)
	}
}

func TestPGClaimLeaseDurationUsesDatabaseClock(t *testing.T) {
	fixture := newPGFixture(t)
	tenantID := fixture.addTenant(t)
	const leaseDuration = 10 * time.Minute
	for index, skew := range []time.Duration{-4 * time.Minute, 50 * time.Second} {
		databaseNow := fixture.databaseNow(t)
		appNow := databaseNow.Add(skew)
		request := pgIssueRequest(tenantID, fmt.Sprintf("database-lease-duration-%d", index))
		fixture.bindIssueRequest(t, request)
		claim, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request),
			appNow, appNow.Add(leaseDuration))
		if err != nil || claim.State != OperationClaimed {
			t.Fatalf("skew=%s claim=%+v error=%v", skew, claim, err)
		}
		var expiresAt, observedAt time.Time
		if err := fixture.pool.QueryRow(context.Background(), `
			SELECT lease_expires_at, statement_timestamp()
			FROM acme_issuance_operation_events
			WHERE tenant_scope_id=$1 AND operation_id=$2
			ORDER BY revision DESC LIMIT 1`, tenantID, request.OperationID).Scan(&expiresAt, &observedAt); err != nil {
			t.Fatal(err)
		}
		remaining := expiresAt.Sub(observedAt)
		if remaining <= leaseDuration-2*time.Second || remaining > leaseDuration {
			t.Fatalf("skew=%s database lease remaining=%s", skew, remaining)
		}
		busy, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request),
			databaseNow.Add(20*time.Minute), databaseNow.Add(30*time.Minute))
		if err != nil || busy.State != OperationBusy || busy.Lease.Token != claim.Lease.Token {
			t.Fatalf("skew=%s early takeover=%+v error=%v", skew, busy, err)
		}
	}
}

func TestPGCleanupFenceRejectsOldOwnerBeforeProviderDelete(t *testing.T) {
	fixture := newPGFixture(t)
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "cleanup-fence")
	// An HTTP-01 request names no DNS provider or zone at all
	// (normalizeIssueRequest).
	request.ChallengeType = ChallengeHTTP01
	request.ProviderRef, request.ProviderID, request.ZoneID = "", uuid.Nil, uuid.Nil
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request), now, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	oldLease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now,
		[]string{"https://ca.example/authz/cleanup-fence"})
	challenge, err := fixture.store.PrepareChallenge(context.Background(), oldLease, ownedChallenge(oldLease, ChallengeIdentity{
		ProviderRef: request.ProviderRef, AuthorizationURL: "https://ca.example/authz/cleanup-fence",
		ChallengeURL: "https://ca.example/challenge/cleanup-fence", ChallengeType: ChallengeHTTP01,
		Identifier: "example.test", RecordName: "example.test",
		Token: "cleanup-fence-token", ExactValue: "cleanup-fence-value",
	}), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.MarkChallenge(context.Background(), oldLease, challenge, "published", now); err != nil {
		t.Fatal(err)
	}
	now = fixture.waitForDatabaseTimeAfter(t, oldLease.ExpiresAt)
	takeover, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request), now, now.Add(time.Minute))
	if err != nil || takeover.State != OperationClaimed {
		t.Fatalf("takeover=%+v error=%v", takeover, err)
	}
	records := &challengeRecords{}
	if err := records.Publish(context.Background(), challenge); err != nil {
		t.Fatal(err)
	}
	oldWorker := &Worker{
		config: Config{Clock: func() time.Time { return now }, CleanupTimeout: time.Second},
		deps:   Dependencies{Operations: fixture.store, HTTP01: records},
	}
	if err := oldWorker.cleanupChallenge(context.Background(), oldLease, challenge); ErrorCodeOf(err) != CodeLeaseLost {
		t.Fatalf("old owner cleanup error = %v", err)
	}
	if len(records.deleted) != 0 {
		t.Fatalf("old owner called provider Delete: %v", records.deleted)
	}
	newWorker := &Worker{
		config: Config{Clock: func() time.Time { return now }, CleanupTimeout: time.Second},
		deps:   Dependencies{Operations: fixture.store, HTTP01: records},
	}
	if err := newWorker.cleanupChallenge(context.Background(), takeover.Lease, challenge); err != nil {
		t.Fatalf("new owner cleanup error = %v", err)
	}
	if len(records.deleted) != 1 {
		t.Fatalf("new owner deletes = %v", records.deleted)
	}
	outstanding, err := fixture.store.OutstandingChallenges(context.Background(), takeover.Lease, now)
	if err != nil || len(outstanding) != 0 {
		t.Fatalf("outstanding=%v error=%v", outstanding, err)
	}
}

func TestPGCommittedCleanupClaimAllowsTakeoverRecovery(t *testing.T) {
	fixture := newPGFixture(t)
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "cleanup-claim-abort")
	// An HTTP-01 request names no DNS provider or zone at all
	// (normalizeIssueRequest).
	request.ChallengeType = ChallengeHTTP01
	request.ProviderRef, request.ProviderID, request.ZoneID = "", uuid.Nil, uuid.Nil
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request), now, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	oldLease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now,
		[]string{"https://ca.example/authz/cleanup-abort"})
	challenge, err := fixture.store.PrepareChallenge(context.Background(), oldLease, ownedChallenge(oldLease, ChallengeIdentity{
		ProviderRef: request.ProviderRef, AuthorizationURL: "https://ca.example/authz/cleanup-abort",
		ChallengeURL: "https://ca.example/challenge/cleanup-abort", ChallengeType: ChallengeHTTP01,
		Identifier: "example.test", RecordName: "example.test",
		Token: "cleanup-abort-token", ExactValue: "cleanup-abort-value",
	}), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.MarkChallenge(context.Background(), oldLease, challenge, "published", now); err != nil {
		t.Fatal(err)
	}
	cleanup, err := fixture.store.ClaimChallengeCleanup(context.Background(), oldLease, challenge, now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup.Abort(context.Background()) }()
	now = fixture.waitForDatabaseTimeAfter(t, oldLease.ExpiresAt)
	takeover, err := fixture.store.Claim(
		context.Background(), request, issueRequestDigest(request), now, now.Add(time.Minute),
	)
	if err != nil || takeover.State != OperationClaimed {
		t.Fatalf("takeover=%+v error=%v", takeover, err)
	}
	if err := cleanup.Complete(context.Background(), now); ErrorCodeOf(err) != CodeLeaseLost {
		t.Fatalf("stale cleanup completion error=%v", err)
	}
	recovered, err := fixture.store.ClaimChallengeCleanup(context.Background(), takeover.Lease, challenge, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Complete(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	outstanding, err := fixture.store.OutstandingChallenges(context.Background(), takeover.Lease, now)
	if err != nil || len(outstanding) != 0 {
		t.Fatalf("outstanding=%v error=%v", outstanding, err)
	}
}

func TestPGWorkerCompletesAndExactlyReplays(t *testing.T) {
	fixture := newPGFixtureAt47(t)
	now := fixture.databaseNow(t)
	protocol := newProtocolServer(t, now, protocolOptions{finalizeProcessing: true})
	records := &challengeRecords{}
	certificates := &memoryCertificates{items: make(map[string]IssuedCertificate)}
	worker := newTestWorker(t, protocol, records, records, certificates, func(config *Config) {
		config.LeaseDuration = config.OrderTimeout + config.CleanupTimeout + 5*time.Second
	})
	worker.deps.Operations = fixture.store
	worker.config.Clock = func() time.Time { return now }
	request := validIssueRequest(ChallengeHTTP01, "pg-complete.example.test")
	// The request belongs to a real tenant scope with an active member actor
	// (047 binds the snapshot to them).
	request.TenantID = fixture.addTenant(t)
	request.ScopeID = request.TenantID
	setRequestOrderID(&request, "pg-complete")
	fixture.bindIssueRequest(t, request)

	result, err := worker.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if result.Certificate.CertificateKeyRef != request.CertificateKeyRef ||
		result.Certificate.PublicKeySPKISHA256 == "" || protocol.newOrderAttempts != 1 ||
		len(certificates.saveLeases) != 1 || certificates.saveLeases[0].Token == uuid.Nil ||
		certificates.saveLeases[0].Revision < 1 ||
		certificates.saveLeases[0].State.Phase != PhaseFinalizing ||
		certificates.saveLeases[0].OperationID != request.OperationID ||
		certificates.saveLeases[0].Digest != result.Certificate.RequestDigest {
		t.Fatalf("result=%+v order_attempts=%d", result, protocol.newOrderAttempts)
	}
	replay, err := worker.Issue(context.Background(), request)
	if err != nil || !replay.Reused || protocol.newOrderAttempts != 1 || certificates.saveCalls != 1 {
		t.Fatalf("replay=%+v error=%v orders=%d saves=%d", replay, err, protocol.newOrderAttempts, certificates.saveCalls)
	}
}

func TestPGWorkerTakesOverAfterFinalizeBeforeSaveCrash(t *testing.T) {
	fixture := newPGFixtureAt47(t)
	now := fixture.databaseNow(t)
	protocol := newProtocolServer(t, now, protocolOptions{finalizeProcessing: true})
	records := &challengeRecords{}
	certificates := &memoryCertificates{items: make(map[string]IssuedCertificate)}
	certificates.onSave = func() { panic("simulated process crash") }
	worker := newTestWorker(t, protocol, records, records, certificates, func(config *Config) {
		config.LeaseDuration = config.OrderTimeout + config.CleanupTimeout + 5*time.Second
	})
	worker.deps.Operations = fixture.store
	worker.config.Clock = func() time.Time { return now }
	worker.config.MaxConcurrentAuthorizations = 1
	request := validIssueRequest(ChallengeHTTP01, "pg-finalize-crash.example.test")
	// The request belongs to a real tenant scope with an active member actor
	// (047 binds the snapshot to them).
	request.TenantID = fixture.addTenant(t)
	request.ScopeID = request.TenantID
	setRequestOrderID(&request, "pg-finalize-crash")
	fixture.bindIssueRequest(t, request)

	executeUntilCrash(t, worker, request)
	certificates.onSave = nil
	now = fixture.waitForDatabaseTimeAfter(t, fixture.operationLeaseExpiry(t, request))
	if _, err := worker.Issue(context.Background(), request); err != nil {
		t.Fatalf("takeover Issue() error = %v", err)
	}
	if protocol.newOrderAttempts != 1 || certificates.saveCalls != 2 {
		t.Fatalf("orders=%d saves=%d", protocol.newOrderAttempts, certificates.saveCalls)
	}
}

func TestPGWorkerTakesOverAndCleansChallengeAfterPublishCrash(t *testing.T) {
	fixture := newPGFixtureAt47(t)
	now := fixture.databaseNow(t)
	protocol := newProtocolServer(t, now, protocolOptions{})
	records := &challengeRecords{onPublish: func() { panic("simulated process crash") }}
	certificates := &memoryCertificates{items: make(map[string]IssuedCertificate)}
	worker := newTestWorker(t, protocol, records, records, certificates, func(config *Config) {
		config.LeaseDuration = config.OrderTimeout + config.CleanupTimeout + 5*time.Second
	})
	worker.deps.Operations = fixture.store
	worker.config.Clock = func() time.Time { return now }
	worker.config.MaxConcurrentAuthorizations = 1
	request := validIssueRequest(ChallengeHTTP01, "pg-publish-crash.example.test")
	// The request belongs to a real tenant scope with an active member actor
	// (047 binds the snapshot to them).
	request.TenantID = fixture.addTenant(t)
	request.ScopeID = request.TenantID
	setRequestOrderID(&request, "pg-publish-crash")
	fixture.bindIssueRequest(t, request)

	executeUntilCrash(t, worker, request)
	records.onPublish = nil
	now = fixture.waitForDatabaseTimeAfter(t, fixture.operationLeaseExpiry(t, request))
	if _, err := worker.Issue(context.Background(), request); err != nil {
		t.Fatalf("takeover Issue() error = %v", err)
	}
	wantDelete := records.identities[0].RecordName + "|" + records.identities[0].ExactValue
	if protocol.newOrderAttempts != 1 || len(records.deleted) != 2 || records.deleted[0] != wantDelete {
		t.Fatalf("orders=%d published=%v deleted=%v", protocol.newOrderAttempts, records.published, records.deleted)
	}
}

func TestPGExpiredLeaseRejectsOldOwnerFinalizeAndCleanup(t *testing.T) {
	fixture := newPGFixture(t)
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "expired-owner")
	request.Domains = []string{"expired.example.test"}
	// An HTTP-01 request names no DNS provider or zone at all
	// (normalizeIssueRequest).
	request.ChallengeType = ChallengeHTTP01
	request.ProviderRef, request.ProviderID, request.ZoneID = "", uuid.Nil, uuid.Nil
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request), now, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	oldLease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now,
		[]string{"https://ca.example/authz/expired"})
	challenge, err := fixture.store.PrepareChallenge(context.Background(), oldLease, ownedChallenge(oldLease, ChallengeIdentity{
		ProviderRef:      request.ProviderRef,
		AuthorizationURL: "https://ca.example/authz/expired", ChallengeURL: "https://ca.example/challenge/expired",
		ChallengeType: ChallengeHTTP01, Identifier: "expired.example.test", RecordName: "expired.example.test",
		Token: "expired-token", ExactValue: "expired-key-authorization",
	}), now)
	if err != nil {
		t.Fatal(err)
	}
	now = fixture.waitForDatabaseTimeAfter(t, oldLease.ExpiresAt)
	takeover, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request),
		now, now.Add(time.Minute))
	if err != nil || takeover.State != OperationClaimed {
		t.Fatalf("takeover=%+v error=%v", takeover, err)
	}
	next := cloneOperationState(oldLease.State)
	next.Phase = PhaseReady
	if _, err := fixture.store.Advance(context.Background(), oldLease, "authorization_ready", next,
		now); ErrorCodeOf(err) != CodeLeaseLost {
		t.Fatalf("old owner finalize path error = %v", err)
	}
	if _, err := fixture.store.ClaimChallengeCleanup(context.Background(), oldLease, challenge,
		now); ErrorCodeOf(err) != CodeLeaseLost {
		t.Fatalf("old owner cleanup error = %v", err)
	}
	_, err = fixture.pool.Exec(context.Background(), `
		INSERT INTO acme_issuance_challenge_events (
			tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,occurred_at
		) VALUES ($1,$2,$3,2,'cleanup_claimed',$4,$5)`,
		tenantID, request.OperationID, challenge.AttemptID, oldLease.Token, now)
	assertPGGuard(t, err)
	cleanup, err := fixture.store.ClaimChallengeCleanup(context.Background(), takeover.Lease, challenge, now)
	if err != nil {
		t.Fatalf("new owner cleanup error = %v", err)
	}
	if err := cleanup.Complete(context.Background(), now); err != nil {
		t.Fatalf("new owner cleanup completion error = %v", err)
	}
}

func TestPGFactsRejectDirectMutationTruncateAndDownWithFacts(t *testing.T) {
	fixture := newPGFixture(t)
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "immutable-facts")
	request.Domains = []string{"immutable.example.test"}
	// An HTTP-01 request names no DNS provider or zone at all
	// (normalizeIssueRequest).
	request.ChallengeType = ChallengeHTTP01
	request.ProviderRef, request.ProviderID, request.ZoneID = "", uuid.Nil, uuid.Nil
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(context.Background(), request, issueRequestDigest(request), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	lease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now,
		[]string{"https://ca.example/authz/immutable"})
	challenge, err := fixture.store.PrepareChallenge(context.Background(), lease, ownedChallenge(lease, ChallengeIdentity{
		ProviderRef: request.ProviderRef, AuthorizationURL: "https://ca.example/authz/immutable", ChallengeURL: "https://ca.example/challenge/immutable",
		ChallengeType: ChallengeHTTP01, Identifier: "immutable.example.test", RecordName: "immutable.example.test",
		Token: "immutable-token", ExactValue: "immutable-key-authorization",
	}), now)
	if err != nil || challenge.AttemptID == uuid.Nil {
		t.Fatalf("PrepareChallenge() = %+v, %v", challenge, err)
	}

	statements := []string{
		"UPDATE acme_issuance_operations SET operation_id=operation_id",
		"UPDATE acme_issuance_challenge_attempts SET exact_value=exact_value",
		"DELETE FROM acme_issuance_operation_events",
		"TRUNCATE acme_issuance_challenge_events",
	}
	for _, statement := range statements {
		_, err := fixture.pool.Exec(context.Background(), statement)
		assertPGGuard(t, err)
	}
	for _, statement := range []string{
		`INSERT INTO acme_issuance_operation_events (
			tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
			order_intent_pending,lease_token,lease_expires_at,next_reconcile_at,account_uri,
			order_url,finalize_url,authorization_urls,certificate_url,certificate_spki_sha256,
			leaf_fingerprint_sha256,failure_code,occurred_at
		) SELECT tenant_scope_id,operation_id,revision+1,'finalize_intent','finalizing',status,
			fence_token,order_intent_pending,lease_token,lease_expires_at,next_reconcile_at,
			account_uri,order_url,finalize_url,authorization_urls,certificate_url,
			certificate_spki_sha256,leaf_fingerprint_sha256,failure_code,occurred_at
		  FROM acme_issuance_operation_events WHERE tenant_scope_id=$1 AND operation_id=$2
		    AND $3::uuid IS NOT NULL
		  ORDER BY revision DESC LIMIT 1`,
		`INSERT INTO acme_issuance_operation_events (
			tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
			order_intent_pending,lease_token,lease_expires_at,next_reconcile_at,account_uri,
			order_url,finalize_url,authorization_urls,certificate_url,certificate_spki_sha256,
			leaf_fingerprint_sha256,failure_code,occurred_at
		) SELECT tenant_scope_id,operation_id,revision+1,'authorization_ready','ready',status,
			$3,order_intent_pending,$3,lease_expires_at,next_reconcile_at,account_uri,
			order_url,finalize_url,authorization_urls,certificate_url,certificate_spki_sha256,
			leaf_fingerprint_sha256,failure_code,occurred_at
		  FROM acme_issuance_operation_events WHERE tenant_scope_id=$1 AND operation_id=$2
		    AND $3::uuid IS NOT NULL
		  ORDER BY revision DESC LIMIT 1`,
		`INSERT INTO acme_issuance_operation_events (
			tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
			order_intent_pending,lease_token,lease_expires_at,next_reconcile_at,account_uri,
			order_url,finalize_url,authorization_urls,certificate_url,certificate_spki_sha256,
			leaf_fingerprint_sha256,failure_code,occurred_at
		) SELECT tenant_scope_id,operation_id,revision+1,'authorization_ready','ready',status,
			fence_token,order_intent_pending,lease_token,lease_expires_at,next_reconcile_at,
			account_uri,'https://ca.example/order/forged',finalize_url,authorization_urls,
			certificate_url,certificate_spki_sha256,leaf_fingerprint_sha256,failure_code,occurred_at
		  FROM acme_issuance_operation_events WHERE tenant_scope_id=$1 AND operation_id=$2
		    AND $3::uuid IS NOT NULL
		  ORDER BY revision DESC LIMIT 1`,
	} {
		_, err := fixture.pool.Exec(context.Background(), statement,
			tenantID, request.OperationID, uuid.New())
		assertPGGuard(t, err)
	}
	assertPGOrphanFactsRejected(t, fixture, tenantID, lease)
	// The facts above come from today's store at the release head, and the
	// migrator cannot roll that head back to 048 (369's down is a one-way gate
	// over domain event history, P3699). Run 048's down script itself at the
	// head: its fact guard must refuse.
	down, err := controlmigrations.FS.ReadFile("048_dns_acme_runtime.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(context.Background(), string(down))
		return execErr
	})
	postgresError := assertPGGuard(t, err)
	if !strings.Contains(postgresError.Message, "facts exist") {
		t.Fatalf("down error = %s", postgresError.Message)
	}
}

func TestPGEmptyDownUpRoundTrip(t *testing.T) {
	// Only 1..047 through the real migrator ledger: rolling the release head
	// back crosses migration 268's one-way down gate (P2682).
	fixture := newPGFixtureWith(t, func(ctx context.Context, pool *pgxpool.Pool) error {
		return databasetest.MigrateThrough(ctx, pool, "up", 47)
	})
	if version := pgMigrationVersion(t, fixture.pool); version != 47 {
		t.Fatalf("migration version=%d, want 47", version)
	}
	if err := database.Migrate(context.Background(), fixture.pool, "down"); err != nil {
		t.Fatalf("empty 047 down: %v", err)
	}
	var tableName *string
	if err := fixture.pool.QueryRow(context.Background(), "SELECT to_regclass('acme_issuance_operations')::text").Scan(&tableName); err != nil {
		t.Fatal(err)
	}
	if tableName != nil {
		t.Fatalf("table remained after down: %s", *tableName)
	}
	if err := databasetest.MigrateThrough(context.Background(), fixture.pool, "up", 47); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	if version := pgMigrationVersion(t, fixture.pool); version != 47 {
		t.Fatalf("migration version=%d, want 47", version)
	}
}

func TestPGMigration060RemoteHandleBoundsAndV2DownGuard(t *testing.T) {
	fixture := newPGFixtureAt60(t)
	if version := pgMigrationVersion(t, fixture.pool); version != 60 {
		t.Fatalf("migration version=%d, want 60", version)
	}
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, "remote-handle-060")
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(t.Context(), request, issueRequestDigest(request), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	authorizations := []string{
		"https://ca.example/authz/handle-1024",
		"https://ca.example/authz/handle-2048",
		"https://ca.example/authz/handle-2049",
	}
	lease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now, authorizations)
	prepare := func(index int) ChallengeIdentity {
		challenge, prepareErr := fixture.store.PrepareChallenge(t.Context(), lease, ownedChallenge(lease, ChallengeIdentity{
			ProviderRef: request.ProviderRef, AuthorizationURL: authorizations[index],
			ChallengeURL:  fmt.Sprintf("https://ca.example/challenge/handle-%d", index),
			ChallengeType: ChallengeDNS01, Identifier: "example.test",
			RecordName: "_acme-challenge.example.test.",
			Token:      fmt.Sprintf("handle-token-%d", index), ExactValue: fmt.Sprintf("handle-value-%d", index),
		}), now)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		return challenge
	}

	for index, recordRef := range []string{
		strings.Repeat("r", 1024),
		"v2." + strings.Repeat("a", 2045),
	} {
		challenge := prepare(index)
		challenge.TXTHandle = RemoteTXTHandle{ProviderRef: request.ProviderRef, RecordRef: recordRef}
		if err := fixture.store.MarkChallenge(t.Context(), lease, challenge, "published", now); err != nil {
			t.Fatalf("MarkChallenge(%d bytes): %v", len(recordRef), err)
		}
	}

	tooLong := prepare(2)
	tooLong.TXTHandle = RemoteTXTHandle{
		ProviderRef: request.ProviderRef, RecordRef: strings.Repeat("x", 2049),
	}
	if err := fixture.store.MarkChallenge(t.Context(), lease, tooLong, "published", now); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("2049-byte MarkChallenge error = %v", err)
	}
	_, err = fixture.pool.Exec(t.Context(), `
		INSERT INTO acme_issuance_challenge_events(
			tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,
			provider_ref,remote_record_ref,exact_value_sha256,occurred_at
		) VALUES($1,$2,$3,2,'published',$4,$5,$6,
			sha256(convert_to($7,'UTF8')),$8)`,
		tooLong.TenantID, tooLong.OperationID, tooLong.AttemptID, lease.Token,
		request.ProviderRef, strings.Repeat("x", 2049), tooLong.ExactValue, now)
	postgresError := assertPGGuard(t, err)
	if !strings.Contains(postgresError.Message, "remote record reference") {
		t.Fatalf("2049-byte database error = %q", postgresError.Message)
	}

	err = database.Migrate(t.Context(), fixture.pool, "down")
	postgresError = assertPGGuard(t, err)
	if !strings.Contains(postgresError.Message, "v2 remote TXT handle") {
		t.Fatalf("060 down guard error = %q", postgresError.Message)
	}
	if version := pgMigrationVersion(t, fixture.pool); version != 60 {
		t.Fatalf("failed down changed migration version to %d", version)
	}
}

func TestPGMigration060EmptyDownUpRoundTrip(t *testing.T) {
	fixture := newPGFixtureAt60(t)
	if err := database.Migrate(t.Context(), fixture.pool, "down"); err != nil {
		t.Fatalf("060 down: %v", err)
	}
	if version := pgMigrationVersion(t, fixture.pool); version != 59 {
		t.Fatalf("migration version after down=%d", version)
	}
	var constraint string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conname='acme_issuance_challenge_publication_shape_048'
		  AND conrelid='acme_issuance_challenge_events'::regclass`).Scan(&constraint); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(constraint, "1024") {
		t.Fatalf("060 down constraint = %s", constraint)
	}
	applyPGMigration060Up(t, fixture.pool)
	if version := pgMigrationVersion(t, fixture.pool); version != 60 {
		t.Fatalf("migration version after up=%d", version)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conname='acme_issuance_challenge_publication_shape_048'
		  AND conrelid='acme_issuance_challenge_events'::regclass`).Scan(&constraint); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(constraint, "2048") {
		t.Fatalf("060 up constraint = %s", constraint)
	}
}

func applyPGMigration060Up(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	up, err := controlmigrations.FS.ReadFile("060_dns_remote_handle_v2.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("060_dns_remote_handle_v2.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, execErr := tx.Exec(t.Context(), string(up)); execErr != nil {
			return execErr
		}
		_, execErr := tx.Exec(t.Context(), `INSERT INTO schema_migrations(
			version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at
		) VALUES(60,'060_dns_remote_handle_v2',$1,$2,'verified',statement_timestamp())`,
			fmt.Sprintf("%x", sha256.Sum256(up)), fmt.Sprintf("%x", sha256.Sum256(down)))
		return execErr
	})
	if err != nil {
		t.Fatalf("060 exact up: %v", err)
	}
}

func TestPGMigration060DownRejectsLongLegacyReference(t *testing.T) {
	fixture := newPGFixtureAt60(t)
	_, _ = publishPGDNSHandle(t, fixture, "remote-handle-060-long", strings.Repeat("l", 1025))
	err := database.Migrate(t.Context(), fixture.pool, "down")
	postgresError := assertPGGuard(t, err)
	if !strings.Contains(postgresError.Message, "exceed 1024 bytes") {
		t.Fatalf("060 long-reference down guard error = %q", postgresError.Message)
	}
	if version := pgMigrationVersion(t, fixture.pool); version != 60 {
		t.Fatalf("failed down changed migration version to %d", version)
	}
}

func TestPGRestartRecoversPersistedV2HandleForExactCleanup(t *testing.T) {
	fixture := newPGFixtureAt60(t)
	lease, challenge := publishPGDNSHandle(t, fixture, "remote-handle-v2-restart",
		"v2.active.eyJzdGFibGUiOiJyZXN0YXJ0In0.c2lnbmF0dXJl")
	restartedStore, err := NewPGOperationStore(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	records := &challengeRecords{}
	worker := &Worker{
		config: Config{Clock: func() time.Time { return fixture.databaseNow(t) }, CleanupTimeout: time.Second},
		deps:   Dependencies{Operations: restartedStore, DNS01: records},
	}
	if err := worker.cleanupOutstanding(t.Context(), lease); err != nil {
		t.Fatalf("restart cleanup: %v", err)
	}
	wantDelete := challenge.TXTHandle.ProviderRef + "|" + challenge.TXTHandle.RecordRef + "|" + challenge.ExactValue
	if len(records.deleted) != 1 || records.deleted[0] != wantDelete {
		t.Fatalf("restart cleanup deletes=%v want=%s", records.deleted, wantDelete)
	}
	outstanding, err := restartedStore.OutstandingChallenges(t.Context(), lease, fixture.databaseNow(t))
	if err != nil || len(outstanding) != 0 {
		t.Fatalf("restart outstanding=%v error=%v", outstanding, err)
	}
}

func TestPGConcurrentV2CleanupHasOneFenceWinner(t *testing.T) {
	fixture := newPGFixtureAt60(t)
	lease, challenge := publishPGDNSHandle(t, fixture, "remote-handle-v2-concurrent",
		"v2.active.eyJzdGFibGUiOiJjb25jdXJyZW50In0.c2lnbmF0dXJl")
	records := &challengeRecords{}
	worker := &Worker{
		config: Config{Clock: func() time.Time { return fixture.databaseNow(t) }, CleanupTimeout: time.Second},
		deps:   Dependencies{Operations: fixture.store, DNS01: records},
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			errs <- worker.cleanupChallenge(t.Context(), lease, challenge)
		}()
	}
	close(start)
	first, second := <-errs, <-errs
	if (first == nil) == (second == nil) {
		t.Fatalf("cleanup results first=%v second=%v", first, second)
	}
	if len(records.deleted) != 1 {
		t.Fatalf("concurrent cleanup provider deletes=%v", records.deleted)
	}
}

func TestPGBlockedProviderCleanupDoesNotHoldOperationRowLock(t *testing.T) {
	fixture := newPGFixtureAt60(t)
	lease, challenge := publishPGDNSHandle(t, fixture, "provider-unlocked",
		"v2.active.eyJzdGFibGUiOiJ1bmxvY2tlZCJ9.c2lnbmF0dXJl")
	entered := make(chan struct{})
	release := make(chan struct{})
	records := &challengeRecords{onDeleteTXT: func(ChallengeIdentity) {
		close(entered)
		<-release
	}}
	worker := &Worker{
		config: Config{Clock: func() time.Time { return fixture.databaseNow(t) }, CleanupTimeout: time.Second},
		deps:   Dependencies{Operations: fixture.store, DNS01: records},
	}
	done := make(chan error, 1)
	go func() { done <- worker.cleanupChallenge(t.Context(), lease, challenge) }()
	<-entered

	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `
		SELECT 1 FROM acme_issuance_operations
		WHERE tenant_scope_id=$1 AND operation_id=$2
		FOR UPDATE NOWAIT`, lease.TenantID, lease.OperationID); err != nil {
		close(release)
		<-done
		t.Fatalf("provider cleanup retained operation row lock: %v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPGDNSZeroMatchCleanupPersistsEmptyHandleChain(t *testing.T) {
	fixture := newPGFixture(t)
	lease, challenge := preparePGDNSIntent(t, fixture, "zero-match-chain")
	records := &recoverableChallengeRecords{challengeRecords: &challengeRecords{}}
	worker := &Worker{
		config: Config{Clock: func() time.Time { return fixture.databaseNow(t) }, CleanupTimeout: time.Second},
		deps:   Dependencies{Operations: fixture.store, DNS01: records},
	}
	if err := worker.cleanupChallenge(t.Context(), lease, challenge); err != nil {
		t.Fatalf("zero-match cleanup: %v", err)
	}
	if len(records.recovered) != 1 || len(records.deleted) != 0 {
		t.Fatalf("provider recovered=%+v deleted=%v", records.recovered, records.deleted)
	}

	rows, err := fixture.pool.Query(t.Context(), `
		SELECT revision,state,provider_ref,remote_record_ref,exact_value_sha256
		FROM acme_issuance_challenge_events
		WHERE tenant_scope_id=$1 AND operation_id=$2 AND attempt_id=$3
		ORDER BY revision`, lease.TenantID, lease.OperationID, challenge.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	wantStates := []string{"intent", "cleanup_claimed", "cleaned"}
	expectedDigest := sha256.Sum256([]byte(challenge.ExactValue))
	index := 0
	for rows.Next() {
		var revision int
		var state string
		var providerRef, recordRef *string
		var digest []byte
		if err := rows.Scan(&revision, &state, &providerRef, &recordRef, &digest); err != nil {
			t.Fatal(err)
		}
		if index >= len(wantStates) || revision != index+1 || state != wantStates[index] ||
			providerRef != nil || recordRef != nil || !slices.Equal(digest, expectedDigest[:]) {
			t.Fatalf("event[%d]=revision:%d state:%q provider:%v record:%v digest:%x",
				index, revision, state, providerRef, recordRef, digest)
		}
		index++
	}
	if err := rows.Err(); err != nil || index != len(wantStates) {
		t.Fatalf("events=%d error=%v", index, err)
	}
}

func TestPGDNSZeroMatchCleanupCrashTakeoverAndIdentityFence(t *testing.T) {
	t.Run("crash takeover", func(t *testing.T) {
		fixture := newPGFixture(t)
		oldLease, challenge := preparePGDNSIntent(t, fixture, "zero-match-takeover")
		oldClaim, err := fixture.store.ClaimChallengeCleanup(t.Context(), oldLease, challenge, fixture.databaseNow(t))
		if err != nil {
			t.Fatal(err)
		}
		now := fixture.waitForDatabaseTimeAfter(t, oldLease.ExpiresAt)
		takeover, err := fixture.store.Claim(t.Context(), oldLease.Request, oldLease.Digest, now, now.Add(time.Minute))
		if err != nil || takeover.State != OperationClaimed {
			t.Fatalf("takeover=%+v error=%v", takeover, err)
		}
		if err := oldClaim.Complete(t.Context(), now); ErrorCodeOf(err) != CodeLeaseLost {
			t.Fatalf("stale complete error=%v", err)
		}
		outstanding, err := fixture.store.OutstandingChallenges(t.Context(), takeover.Lease, now)
		if err != nil || len(outstanding) != 1 || !outstanding[0].ZeroMatchCleanupClaimed {
			t.Fatalf("takeover outstanding=%+v error=%v", outstanding, err)
		}
		records := &recoverableChallengeRecords{
			challengeRecords: &challengeRecords{}, recoverError: errors.New("recovery must not repeat"),
		}
		worker := &Worker{
			config: Config{Clock: func() time.Time { return fixture.databaseNow(t) }, CleanupTimeout: time.Second},
			deps:   Dependencies{Operations: fixture.store, DNS01: records},
		}
		if err := worker.cleanupChallenge(t.Context(), takeover.Lease, outstanding[0]); err != nil {
			t.Fatal(err)
		}
		if len(records.recovered) != 0 || len(records.deleted) != 0 {
			t.Fatalf("takeover provider recovered=%+v deleted=%v", records.recovered, records.deleted)
		}
		outstanding, err = fixture.store.OutstandingChallenges(t.Context(), takeover.Lease, fixture.databaseNow(t))
		if err != nil || len(outstanding) != 0 {
			t.Fatalf("outstanding=%+v error=%v", outstanding, err)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*ChallengeIdentity)
	}{
		{name: "attempt", mutate: func(item *ChallengeIdentity) { item.AttemptID = uuid.New() }},
		{name: "owner", mutate: func(item *ChallengeIdentity) { item.RecordName = "_acme-challenge.other.test." }},
		{name: "digest", mutate: func(item *ChallengeIdentity) { item.ExactValue += "-drift" }},
		{name: "handle", mutate: func(item *ChallengeIdentity) {
			item.TXTHandle = RemoteTXTHandle{ProviderRef: item.ProviderRef, RecordRef: "record/forged"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPGFixture(t)
			lease, challenge := preparePGDNSIntent(t, fixture, "zero-match-fence-"+test.name)
			claim, err := fixture.store.ClaimChallengeCleanup(t.Context(), lease, challenge, fixture.databaseNow(t))
			if err != nil {
				t.Fatal(err)
			}
			concrete := claim.(*pgChallengeCleanupClaim)
			test.mutate(&concrete.challenge)
			if err := concrete.Complete(t.Context(), fixture.databaseNow(t)); ErrorCodeOf(err) != CodeOperationConflict {
				t.Fatalf("drift complete error=%v", err)
			}
			outstanding, err := fixture.store.OutstandingChallenges(t.Context(), lease, fixture.databaseNow(t))
			challenge.ZeroMatchCleanupClaimed = true
			if err != nil || len(outstanding) != 1 || outstanding[0] != challenge {
				t.Fatalf("outstanding=%+v error=%v", outstanding, err)
			}
		})
	}
}

func TestPGBlockedDNSRecoveryDoesNotHoldOperationRowLock(t *testing.T) {
	fixture := newPGFixture(t)
	lease, challenge := preparePGDNSIntent(t, fixture, "zero-match-unlocked")
	entered := make(chan struct{})
	release := make(chan struct{})
	provider := &blockingDNSRecoveryProvider{
		challengeRecords: &challengeRecords{}, entered: entered, release: release,
	}
	worker := &Worker{
		config: Config{Clock: func() time.Time { return fixture.databaseNow(t) }, CleanupTimeout: time.Second},
		deps:   Dependencies{Operations: fixture.store, DNS01: provider},
	}
	done := make(chan error, 1)
	go func() { done <- worker.cleanupChallenge(t.Context(), lease, challenge) }()
	<-entered

	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `
		SELECT 1 FROM acme_issuance_operations
		WHERE tenant_scope_id=$1 AND operation_id=$2
		FOR UPDATE NOWAIT`, lease.TenantID, lease.OperationID); err != nil {
		close(release)
		<-done
		t.Fatalf("provider recovery retained operation row lock: %v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type blockingDNSRecoveryProvider struct {
	*challengeRecords
	entered chan struct{}
	release chan struct{}
}

func (p *blockingDNSRecoveryProvider) RecoverTXT(ctx context.Context, _ ChallengeIdentity) (RemoteTXTHandle, bool, error) {
	close(p.entered)
	select {
	case <-p.release:
		return RemoteTXTHandle{}, false, nil
	case <-ctx.Done():
		return RemoteTXTHandle{}, false, ctx.Err()
	}
}

func TestPGCleanupCompletionRejectsIdentityDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ChallengeIdentity)
	}{
		{name: "provider", mutate: func(item *ChallengeIdentity) { item.ProviderRef = uuid.NewString() }},
		{name: "owner", mutate: func(item *ChallengeIdentity) { item.RecordName = "_acme-challenge.other.test." }},
		{name: "record", mutate: func(item *ChallengeIdentity) { item.TXTHandle.RecordRef += ".other" }},
		{name: "value", mutate: func(item *ChallengeIdentity) { item.ExactValue += "-other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPGFixtureAt60(t)
			lease, challenge := publishPGDNSHandle(t, fixture, "cleanup-identity-"+test.name,
				"v2.active.eyJzdGFibGUiOiJpZGVudGl0eSJ9.c2lnbmF0dXJl")
			claim, err := fixture.store.ClaimChallengeCleanup(t.Context(), lease, challenge, fixture.databaseNow(t))
			if err != nil {
				t.Fatal(err)
			}
			concrete := claim.(*pgChallengeCleanupClaim)
			test.mutate(&concrete.challenge)
			if err := concrete.Complete(t.Context(), fixture.databaseNow(t)); ErrorCodeOf(err) != CodeOperationConflict {
				t.Fatalf("Complete() error = %v", err)
			}
			outstanding, err := fixture.store.OutstandingChallenges(t.Context(), lease, fixture.databaseNow(t))
			if err != nil || len(outstanding) != 1 || outstanding[0] != challenge {
				t.Fatalf("outstanding=%+v error=%v", outstanding, err)
			}
		})
	}
}

func publishPGDNSHandle(
	t *testing.T,
	fixture *pgFixture,
	operationID, recordRef string,
) (OperationLease, ChallengeIdentity) {
	t.Helper()
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, operationID)
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(t.Context(), request, issueRequestDigest(request), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL := "https://ca.example/authz/" + operationID
	lease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now, []string{authorizationURL})
	challenge, err := fixture.store.PrepareChallenge(t.Context(), lease, ownedChallenge(lease, ChallengeIdentity{
		ProviderRef: request.ProviderRef, AuthorizationURL: authorizationURL,
		ChallengeURL:  "https://ca.example/challenge/" + operationID,
		ChallengeType: ChallengeDNS01, Identifier: "example.test",
		RecordName: "_acme-challenge.example.test.", Token: "token-" + operationID,
		ExactValue: "value-" + operationID,
	}), now)
	if err != nil {
		t.Fatal(err)
	}
	challenge.TXTHandle = RemoteTXTHandle{ProviderRef: request.ProviderRef, RecordRef: recordRef}
	if err := fixture.store.MarkChallenge(t.Context(), lease, challenge, "published", now); err != nil {
		t.Fatal(err)
	}
	return lease, challenge
}

func preparePGDNSIntent(t *testing.T, fixture *pgFixture, operationID string) (OperationLease, ChallengeIdentity) {
	t.Helper()
	tenantID := fixture.addTenant(t)
	request := pgIssueRequest(tenantID, operationID)
	fixture.bindIssueRequest(t, request)
	now := fixture.databaseNow(t)
	claim, err := fixture.store.Claim(t.Context(), request, issueRequestDigest(request), now, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL := "https://ca.example/authz/" + operationID
	lease := advancePGToAuthorizing(t, fixture.store, claim.Lease, now, []string{authorizationURL})
	challenge, err := fixture.store.PrepareChallenge(t.Context(), lease, ownedChallenge(lease, ChallengeIdentity{
		ProviderRef: request.ProviderRef, AuthorizationURL: authorizationURL,
		ChallengeURL:  "https://ca.example/challenge/" + operationID,
		ChallengeType: ChallengeDNS01, Identifier: "example.test",
		RecordName: "_acme-challenge.example.test.", Token: "token-" + operationID,
		ExactValue: "value-" + operationID,
	}), now)
	if err != nil {
		t.Fatal(err)
	}
	return lease, challenge
}

type pgFixture struct {
	pool   *pgxpool.Pool
	store  *PGOperationStore
	schema string
	admin  *pgxpool.Pool
}

func newPGFixture(t *testing.T) *pgFixture {
	return newPGFixtureAt(t, 0)
}

func newPGFixtureAt(t *testing.T, through int) *pgFixture {
	t.Helper()
	return newPGFixtureWith(t, func(ctx context.Context, pool *pgxpool.Pool) error {
		if through == 0 {
			if err := database.Migrate(ctx, pool, "up"); err != nil {
				return fmt.Errorf("migrate ACME test schema: %w", err)
			}
		} else if err := databasetest.MigrateThrough(ctx, pool, "up", int64(through)); err != nil {
			// The real migrator over 1..through: its verified ledger is what a
			// later down of that version is checked against (a hand-made
			// version-only ledger reads as legacy_unverified and is refused).
			return fmt.Errorf("migrate ACME test schema through %03d: %w", through, err)
		}
		return nil
	})
}

func newPGFixtureWith(t *testing.T, migrate func(context.Context, *pgxpool.Pool) error) *pgFixture {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "acme_worker_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store, err := NewPGOperationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	return &pgFixture{pool: pool, store: store, schema: schema, admin: admin}
}

func newPGFixtureAt47(t *testing.T) *pgFixture {
	t.Helper()
	fixture := newPGFixtureAt(t, 47)
	if version := pgMigrationVersion(t, fixture.pool); version != 47 {
		t.Fatalf("migration version=%d", version)
	}
	return fixture
}

func newPGFixtureAt60(t *testing.T) *pgFixture {
	t.Helper()
	fixture := newPGFixtureAt(t, 60)
	if version := pgMigrationVersion(t, fixture.pool); version != 60 {
		t.Fatalf("migration version=%d, want 60", version)
	}
	return fixture
}

func pgMigrationVersion(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var version int
	if err := pool.QueryRow(context.Background(), `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func (f *pgFixture) databaseNow(t *testing.T) time.Time {
	t.Helper()
	var now time.Time
	if err := f.pool.QueryRow(context.Background(), "SELECT statement_timestamp()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now.UTC()
}

func (f *pgFixture) waitForDatabaseTimeAfter(t *testing.T, target time.Time) time.Time {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		now := f.databaseNow(t)
		if now.After(target) {
			return now
		}
		if time.Now().After(deadline) {
			t.Fatalf("database clock did not pass %s", target)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (f *pgFixture) operationLeaseExpiry(t *testing.T, request IssueRequest) time.Time {
	t.Helper()
	var expiresAt time.Time
	if err := f.pool.QueryRow(context.Background(), `
		SELECT lease_expires_at
		FROM acme_issuance_operation_events
		WHERE tenant_scope_id=$1 AND operation_id=$2
		ORDER BY revision DESC LIMIT 1`, request.TenantID, request.OperationID,
	).Scan(&expiresAt); err != nil {
		t.Fatal(err)
	}
	return expiresAt.UTC()
}

// addTenant creates a tenant whose scope has the same ID: pgIssueRequest uses
// one ID as both the request's TenantID and ScopeID, and migration 047 binds
// the snapshot's TenantID to the scope's tenant.
func (f *pgFixture) addTenant(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	tenantID := id
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `INSERT INTO tenants (id,display_name) VALUES ($1,$2)`,
		tenantID, "ACME test tenant "+tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(),
		`INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($1,'tenant',$2)`, id, tenantID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *pgFixture) bindIssueRequest(t *testing.T, request IssueRequest) {
	t.Helper()
	ctx := context.Background()
	username := "acme-" + strings.ReplaceAll(request.ActorUserID.String(), "-", "")[:16]
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'ACME worker actor','test-hash')
		ON CONFLICT (id) DO NOTHING`, request.ActorUserID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)
			ON CONFLICT DO NOTHING`, request.ScopeID, request.ActorUserID); err != nil {
		t.Fatal(err)
	}
	// Before 048 the request only has to name an active tenant member (047);
	// the key, provider and certificate order facts below are 048's.
	var bound048 bool
	if err := f.pool.QueryRow(ctx, `SELECT to_regclass(current_schema() || '.acme_tenant_key_facts') IS NOT NULL`).Scan(&bound048); err != nil {
		t.Fatal(err)
	}
	if !bound048 {
		return
	}
	var providerID *uuid.UUID
	if request.ChallengeType == ChallengeDNS01 {
		parsed := uuid.MustParse(request.ProviderRef)
		providerID = &parsed
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO dns_providers(
				id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
				created_by_user_id,updated_by_user_id
			) VALUES($1,$2,'ACME test DNS','cloudflare','credential-key',$3,'verified',$4,$4)
				ON CONFLICT (id) DO NOTHING`, parsed, request.ScopeID, make([]byte, 32), request.ActorUserID); err != nil {
			t.Fatal(err)
		}
	}
	for index, key := range []struct {
		ref     string
		purpose string
	}{
		{ref: request.AccountKeyRef, purpose: "account"},
		{ref: request.CertificateKeyRef, purpose: "certificate"},
	} {
		publicKeyDigest := make([]byte, 32)
		publicKeyDigest[0] = byte(index + 1)
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO acme_tenant_key_facts(
				tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
				external_key_reference,created_by_user_id
			) VALUES($1,$2,$3,$4,'ecdsa',$5,$6,$7)
				ON CONFLICT (tenant_scope_id,key_ref) DO NOTHING`,
			request.ScopeID, uuid.New(), key.ref, key.purpose, publicKeyDigest,
			"kms://test/"+key.ref, request.ActorUserID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO certificate_orders(
			id,scope_id,dns_provider_id,domains,challenge_type,auto_renew,
			created_by_user_id,updated_by_user_id
		) VALUES($1,$2,$3,$4,$5,true,$6,$6)
			ON CONFLICT (id) DO NOTHING`, request.CertificateOrderID, request.ScopeID,
		providerID, request.Domains, request.ChallengeType, request.ActorUserID); err != nil {
		t.Fatal(err)
	}
	if request.ChallengeType == ChallengeDNS01 {
		if _, err := f.pool.Exec(ctx, `INSERT INTO dns_zones(
				id,scope_id,provider_id,name,created_by_user_id,updated_by_user_id
			) VALUES($1,$2,$3,'example.test',$4,$4) ON CONFLICT (id) DO NOTHING`,
			request.ZoneID, request.ScopeID, providerID, request.ActorUserID); err != nil {
			t.Fatal(err)
		}
	}
}

func seedPGAccountRegistration(t *testing.T, store *PGOperationStore, request IssueRequest, accountURI string) {
	t.Helper()
	ctx := context.Background()
	var tableName *string
	if err := store.pool.QueryRow(ctx, "SELECT to_regclass('acme_account_registration_facts')::text").Scan(&tableName); err != nil {
		t.Fatal(err)
	}
	if tableName == nil {
		return
	}
	var keyID uuid.UUID
	if err := store.pool.QueryRow(ctx, `
		SELECT id FROM acme_tenant_key_facts
		WHERE tenant_scope_id=$1 AND key_ref=$2`, request.TenantID, request.AccountKeyRef,
	).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO acme_account_registration_facts(
			tenant_scope_id,id,account_key_id,directory_url,account_uri,contacts,
			terms_agreed_at,registered_at,created_by_user_id
		) VALUES($1,$2,$3,$4,$5,$6,statement_timestamp()-interval '1 second',
			statement_timestamp(),$7)
		ON CONFLICT (tenant_scope_id,directory_url,account_key_id) DO NOTHING`,
		request.ScopeID, uuid.New(), keyID, request.DirectoryURL, accountURI,
		request.Contacts, request.ActorUserID); err != nil {
		t.Fatal(err)
	}
}

func pgIssueRequest(tenantID uuid.UUID, operationID string) IssueRequest {
	orderID, err := uuid.Parse(operationID)
	if err != nil {
		orderID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(operationID))
	}
	providerID := uuid.NewSHA1(uuid.NameSpaceOID, append([]byte("provider/"), tenantID[:]...))
	zoneID := uuid.NewSHA1(uuid.NameSpaceOID, append([]byte("zone/"), tenantID[:]...))
	return IssueRequest{
		TenantID: tenantID, ScopeID: tenantID, OperationID: orderID.String(), CertificateOrderID: orderID,
		ActorUserID: uuid.NewSHA1(uuid.NameSpaceOID, append([]byte("actor/"), tenantID[:]...)),
		ProviderID:  providerID, ZoneID: zoneID, ProviderRef: providerID.String(), DirectoryURL: "https://ca.example/directory",
		AccountKeyRef: "kms/account", CertificateKeyRef: "kms/certificate",
		Contacts: []string{"mailto:ops@example.test"}, AcceptTerms: true,
		Domains: []string{"example.test"}, ChallengeType: ChallengeDNS01,
	}
}

func assertPGGuard(t *testing.T, err error) *pgconn.PgError {
	t.Helper()
	return assertPGSQLState(t, err, "P0001")
}

func assertPGSQLState(t *testing.T, err error, code string) *pgconn.PgError {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("guard error = %v", err)
	}
	return postgresError
}

func assertPGOrphanFactsRejected(t *testing.T, fixture *pgFixture, tenantID uuid.UUID, lease OperationLease) {
	t.Helper()
	now := fixture.databaseNow(t)
	request := pgIssueRequest(tenantID, "orphan-operation")
	fixture.bindIssueRequest(t, request)
	snapshot, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := decodeDigest(issueRequestDigest(request))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO acme_issuance_operations (
			tenant_scope_id,operation_id,request_digest,request_snapshot,directory_url,
			certificate_key_ref,certificate_order_id,actor_user_id,dns_provider_id,
			account_key_ref,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		tenantID, request.OperationID, digest, snapshot, request.DirectoryURL,
		request.CertificateKeyRef, request.CertificateOrderID, request.ActorUserID,
		uuid.MustParse(request.ProviderRef), request.AccountKeyRef, now); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	assertPGGuard(t, tx.Commit(context.Background()))

	tx, err = fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO acme_issuance_challenge_attempts (
			tenant_scope_id,operation_id,attempt_id,attempt_number,authorization_url,
			challenge_url,challenge_type,identifier,wildcard,record_name,token,exact_value,created_at
		) VALUES ($1,$2,$3,2,$4,$5,'http-01',$6,false,$6,$7,$8,$9)`,
		lease.TenantID, lease.OperationID, uuid.New(), lease.State.AuthorizationURLs[0],
		"https://ca.example/challenge/orphan", "immutable.example.test", "orphan-token",
		"orphan-key-authorization", now); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	assertPGGuard(t, tx.Commit(context.Background()))
}

func advancePGToAuthorizing(
	t *testing.T,
	store OperationStore,
	lease OperationLease,
	now time.Time,
	authorizationURLs []string,
) OperationLease {
	t.Helper()
	if pgStore, ok := store.(*PGOperationStore); ok {
		seedPGAccountRegistration(t, pgStore, lease.Request, "https://ca.example/account/1")
	}
	next := cloneOperationState(lease.State)
	next.AccountURI = "https://ca.example/account/1"
	lease = mustPGAdvance(t, store, lease, "account_registered", next, now)
	next = cloneOperationState(lease.State)
	next.OrderIntentPending = true
	lease = mustPGAdvance(t, store, lease, "order_intent", next, now)
	next = cloneOperationState(lease.State)
	next.Phase = PhaseOrdered
	next.OrderIntentPending = false
	next.OrderURL = "https://ca.example/order/1"
	next.FinalizeURL = "https://ca.example/finalize/1"
	next.AuthorizationURLs = slices.Clone(authorizationURLs)
	lease = mustPGAdvance(t, store, lease, "order_created", next, now)
	next = cloneOperationState(lease.State)
	next.Phase = PhaseAuthorizing
	return mustPGAdvance(t, store, lease, "authorizing", next, now)
}

func mustPGAdvance(
	t *testing.T,
	store OperationStore,
	lease OperationLease,
	eventType string,
	next OperationState,
	now time.Time,
) OperationLease {
	t.Helper()
	updated, err := store.Advance(context.Background(), lease, eventType, next, now)
	if err != nil {
		t.Fatalf("Advance(%s): %v", eventType, err)
	}
	return updated
}

// ownedChallenge stamps a test challenge with the owner identity of lease's
// request, as the worker does for every challenge it prepares (worker.go):
// PrepareChallenge refuses one whose owner fields do not match the request.
func ownedChallenge(lease OperationLease, challenge ChallengeIdentity) ChallengeIdentity {
	request := lease.Request
	challenge.TenantID, challenge.ScopeID, challenge.OperationID = request.TenantID, request.ScopeID, request.OperationID
	challenge.ProviderID, challenge.ZoneID = request.ProviderID, request.ZoneID
	if challenge.ProviderRef == "" {
		challenge.ProviderRef = request.ProviderRef
	}
	return challenge
}
