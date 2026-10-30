package challengepolicy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPruneCompletedIdempotencyRetentionReplayBoundaryAndLimit(t *testing.T) {
	fixture := newFixture(t, allowGate())
	store := fixture.service.store
	fixture.now = time.Now().UTC().Add(-9 * 24 * time.Hour).Truncate(time.Microsecond)
	firstSite := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "first.a.example.test")
	secondSite := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "second.a.example.test")
	first := createServicePolicy(t, fixture, firstSite, "first.a.example.test", "retention-first")
	fixture.now = fixture.now.Add(24 * time.Hour)
	second := createServicePolicy(t, fixture, secondSite, "second.a.example.test", "retention-second")

	replay, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: firstSite, Host: "first.a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("retention-first"),
	})
	if err != nil || !replay.Replayed || replay.Policy.ID != first.ID {
		t.Fatalf("retained replay=(%#v,%v) want original %s", replay, err, first.ID)
	}
	_, err = fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: firstSite, Host: "first.a.example.test", Enabled: false,
		Config: validConfig(ModeClick), WriteMetadata: metadata("retention-first"),
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("retained different digest error=%v", err)
	}

	var firstExpiry time.Time
	if err := fixture.pool.QueryRow(context.Background(), `SELECT retention_expires_at
		FROM challenge_policy_write_requests WHERE idempotency_key='retention-first'`).Scan(&firstExpiry); err != nil {
		t.Fatal(err)
	}
	if pruned, err := store.PruneCompletedIdempotency(context.Background(), firstExpiry.Add(-time.Microsecond), 1); err != nil || pruned != 0 {
		t.Fatalf("before-boundary prune=(%d,%v)", pruned, err)
	}
	if pruned, err := store.PruneCompletedIdempotency(context.Background(), firstExpiry, 1); err != nil || pruned != 1 {
		t.Fatalf("boundary prune=(%d,%v)", pruned, err)
	}
	var remaining int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM challenge_policy_write_requests
		WHERE idempotency_key IN ('retention-first','retention-second')`).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("strict limit remaining=%d error=%v second=%s", remaining, err, second.ID)
	}

	fixture.now = time.Now().UTC().Truncate(time.Microsecond)
	reusedSite := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "reused.a.example.test")
	reused := createServicePolicy(t, fixture, reusedSite, "reused.a.example.test", "retention-first")
	if reused.ID == first.ID {
		t.Fatal("pruned idempotency key replayed the old resource")
	}
	for _, test := range []struct {
		now   time.Time
		limit int
	}{
		{now: time.Time{}, limit: 1},
		{now: time.Now(), limit: 0},
		{now: time.Now(), limit: -1},
		{now: time.Now(), limit: maxIdempotencyPruneBatch + 1},
	} {
		if _, err := store.PruneCompletedIdempotency(context.Background(), test.now, test.limit); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid prune now=%s limit=%d error=%v", test.now, test.limit, err)
		}
	}
}

func TestPruneCompletedIdempotencyOrdersEqualExpiryByID(t *testing.T) {
	if !strings.Contains(pruneCompletedIdempotencySQL, "ORDER BY retention_expires_at, id") {
		t.Fatal("prune SQL must order equal expiry receipts by id")
	}
	fixture := newFixture(t, allowGate())
	store := fixture.service.store
	completedAt := time.Now().UTC().Add(-8 * 24 * time.Hour).Truncate(time.Microsecond)
	lower := "07200000-0000-4000-8000-000000000020"
	higher := "07200000-0000-4000-8000-000000000021"
	for _, item := range []struct {
		id  string
		key string
	}{{higher, "retention-tie-higher"}, {lower, "retention-tie-lower"}} {
		if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO challenge_policy_write_requests(
			id,actor_scope_id,actor_user_id,target_scope_id,operation,idempotency_key,
			request_digest,request_id,trace_id,created_at
		) VALUES($1,$2,$3,$2,'challenge_policy.create',$4,decode(repeat('00',32),'hex'),$5,$6,$7)`,
			item.id, fixture.ownerA.ScopeID, fixture.ownerA.UserID, item.key,
			item.key+"-request", item.key+"-trace", completedAt.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(context.Background(), `UPDATE challenge_policy_write_requests SET
			outcome='success',resource_id=gen_random_uuid(),response_status=201,response_body='{}',completed_at=$2
			WHERE id=$1`, item.id, completedAt); err != nil {
			t.Fatal(err)
		}
	}
	if pruned, err := store.PruneCompletedIdempotency(context.Background(), completedAt.Add(168*time.Hour), 1); err != nil || pruned != 1 {
		t.Fatalf("equal-expiry prune=(%d,%v)", pruned, err)
	}
	var lowerExists, higherExists bool
	if err := fixture.pool.QueryRow(context.Background(), `SELECT
		EXISTS(SELECT 1 FROM challenge_policy_write_requests WHERE id=$1),
		EXISTS(SELECT 1 FROM challenge_policy_write_requests WHERE id=$2)`, lower, higher).Scan(&lowerExists, &higherExists); err != nil {
		t.Fatal(err)
	}
	if lowerExists || !higherExists {
		t.Fatalf("equal-expiry survivors lower=%t higher=%t, want false/true", lowerExists, higherExists)
	}
}

func TestPruneCompletedIdempotencyCapsFutureCallerAtDatabaseTime(t *testing.T) {
	fixture := newFixture(t, allowGate())
	store := fixture.service.store
	oldCompletion := time.Now().UTC().Add(-8 * 24 * time.Hour).Truncate(time.Microsecond)
	futureCompletion := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	for _, item := range []struct {
		id          string
		key         string
		completedAt time.Time
	}{
		{"07200000-0000-4000-8000-000000000030", "retention-db-expired", oldCompletion},
		{"07200000-0000-4000-8000-000000000031", "retention-caller-only", futureCompletion},
	} {
		if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO challenge_policy_write_requests(
			id,actor_scope_id,actor_user_id,target_scope_id,operation,idempotency_key,
			request_digest,request_id,trace_id,created_at
		) VALUES($1,$2,$3,$2,'challenge_policy.create',$4,decode(repeat('00',32),'hex'),$5,$6,$7)`,
			item.id, fixture.ownerA.ScopeID, fixture.ownerA.UserID, item.key,
			item.key+"-request", item.key+"-trace", item.completedAt.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(context.Background(), `UPDATE challenge_policy_write_requests SET
			outcome='success',resource_id=gen_random_uuid(),response_status=201,response_body='{}',completed_at=$2
			WHERE id=$1`, item.id, item.completedAt); err != nil {
			t.Fatal(err)
		}
	}
	if pruned, err := store.PruneCompletedIdempotency(context.Background(), time.Now().Add(365*24*time.Hour), 10); err != nil || pruned != 1 {
		t.Fatalf("future caller mixed prune=(%d,%v), want one database-expired receipt", pruned, err)
	}
	var oldExists, futureExists bool
	if err := fixture.pool.QueryRow(context.Background(), `SELECT
		EXISTS(SELECT 1 FROM challenge_policy_write_requests WHERE id='07200000-0000-4000-8000-000000000030'),
		EXISTS(SELECT 1 FROM challenge_policy_write_requests WHERE id='07200000-0000-4000-8000-000000000031')`).Scan(
		&oldExists, &futureExists); err != nil {
		t.Fatal(err)
	}
	if oldExists || !futureExists {
		t.Fatalf("future caller survivors old=%t future=%t, want false/true", oldExists, futureExists)
	}
}

func TestPruneCompletedIdempotencySkipsLockedAndPending(t *testing.T) {
	fixture := newFixture(t, allowGate())
	store := fixture.service.store
	fixture.now = time.Now().UTC().Add(-8 * 24 * time.Hour).Truncate(time.Microsecond)
	lockedSite := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "locked.a.example.test")
	createServicePolicy(t, fixture, lockedSite, "locked.a.example.test", "retention-locked")

	tx, err := fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(context.Background(), `SELECT id FROM challenge_policy_write_requests
		WHERE idempotency_key='retention-locked' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	replayResult := make(chan error, 1)
	go func() {
		result, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
			TargetScopeID: fixture.tenantA, SiteID: lockedSite, Host: "locked.a.example.test", Enabled: true,
			Config: validConfig(ModeClick), WriteMetadata: metadata("retention-locked"),
		})
		if err == nil && !result.Replayed {
			err = errors.New("concurrent retained request did not replay")
		}
		replayResult <- err
	}()
	if pruned, err := store.PruneCompletedIdempotency(context.Background(), time.Now(), 10); err != nil || pruned != 0 {
		t.Fatalf("locked prune=(%d,%v)", pruned, err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-replayResult; err != nil {
		t.Fatalf("concurrent replay after locked prune: %v", err)
	}
	if pruned, err := store.PruneCompletedIdempotency(context.Background(), time.Now(), 10); err != nil || pruned != 1 {
		t.Fatalf("unlocked prune=(%d,%v)", pruned, err)
	}

	if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO challenge_policy_write_requests(
		id,actor_scope_id,actor_user_id,target_scope_id,operation,idempotency_key,
		request_digest,request_id,trace_id,created_at
	) VALUES(gen_random_uuid(),$1,$2,$1,'challenge_policy.create','retention-pending',
		decode(repeat('00',32),'hex'),'retention-pending-request','retention-pending-trace',now())`,
		fixture.ownerA.ScopeID, fixture.ownerA.UserID); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM challenge_policy_write_requests
		WHERE completed_at IS NULL AND retention_expires_at IS NULL`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending receipts=%d want=1", pending)
	}
	if pruned, err := store.PruneCompletedIdempotency(context.Background(), time.Now().Add(365*24*time.Hour), 10); err != nil || pruned != 0 {
		t.Fatalf("pending prune=(%d,%v) pending=%d", pruned, err, pending)
	}
}
