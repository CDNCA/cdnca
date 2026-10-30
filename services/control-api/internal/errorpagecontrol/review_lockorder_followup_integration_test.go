package errorpagecontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type lockOrderFactCounts struct {
	revisions    int
	publications int
	writes       int
	audits       int
}

func readLockOrderFactCounts(t *testing.T, pool *pgxpool.Pool) lockOrderFactCounts {
	t.Helper()
	var counts lockOrderFactCounts
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM error_page_rule_revisions),
		(SELECT count(*) FROM error_page_publications),
		(SELECT count(*) FROM error_page_write_requests),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'error_page.rule.%')`).Scan(
		&counts.revisions, &counts.publications, &counts.writes, &counts.audits,
	); err != nil {
		t.Fatal(err)
	}
	return counts
}

func insertLockOrderRuleRevision(
	ctx context.Context,
	tx pgx.Tx,
	setup followupRuleSetup,
	revision int64,
	code int,
	enabled bool,
	deleted bool,
	key string,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO error_page_rule_revisions (
		rule_id,revision,category,match_kind,code_from,code_to,asset_id,enabled,deleted,
		created_by_user_id,created_by_scope_id,request_id,trace_id,created_at
	) VALUES($1,$2,$3,'exact',$4,$4,$5,$6,$7,$8,$9,$10,$10,$11)`,
		setup.rule.Value.ID, revision, CategoryOriginResponse, code, setup.asset.ID, enabled, deleted,
		setup.identities.tenantOwner.UserID, setup.identities.tenantOwner.ScopeID, key, storeTime(time.Now()))
	return err
}

func insertLockOrderPublication(
	ctx context.Context,
	tx pgx.Tx,
	identities seededIdentities,
	revision int64,
	previous []byte,
	canonical []byte,
) error {
	digest := sha256.Sum256(canonical)
	_, err := tx.Exec(ctx, `INSERT INTO error_page_publications (
		revision,platform_scope_id,schema,version,canonical_snapshot,snapshot_sha256,previous_sha256,
		created_by_user_id,created_by_scope_id,request_id,trace_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$11)`, revision, identities.platformScope,
		SchemaV1, fmt.Sprintf("control-%d", revision), canonical, digest[:], previous,
		identities.platform.UserID, identities.platform.ScopeID,
		fmt.Sprintf("lock-order-publication-%d", revision), storeTime(time.Now()))
	return err
}

func latestLockOrderPublication(ctx context.Context, tx pgx.Tx) (int64, []byte, error) {
	var revision int64
	var digest []byte
	err := tx.QueryRow(ctx, `SELECT revision,snapshot_sha256 FROM error_page_publications
		ORDER BY revision DESC LIMIT 1`).Scan(&revision, &digest)
	return revision, digest, err
}

func waitForBackendLockOrCompletion(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	pid int,
	done <-chan error,
) (bool, error) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return true, err
		default:
		}
		var waitEventType string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(wait_event_type,'')
			FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waitEventType); err != nil {
			t.Fatal(err)
		}
		if waitEventType == "Lock" {
			return false, nil
		}
		select {
		case <-ctx.Done():
			t.Fatalf("pid %d did not wait for a lock: %v", pid, ctx.Err())
		case <-ticker.C:
		}
	}
}

func receiveLockOrderError(t *testing.T, ctx context.Context, done <-chan error, label string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		t.Fatalf("%s did not finish: %v", label, ctx.Err())
		return ctx.Err()
	}
}

func assertLockOrderPublicationChain(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT revision,canonical_snapshot,snapshot_sha256,previous_sha256
		FROM error_page_publications ORDER BY revision`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var previous []byte
	expectedRevision := int64(1)
	for rows.Next() {
		var revision int64
		var canonical, digest, linkedPrevious []byte
		if err := rows.Scan(&revision, &canonical, &digest, &linkedPrevious); err != nil {
			t.Fatal(err)
		}
		calculated := sha256.Sum256(canonical)
		if revision != expectedRevision || !bytes.Equal(digest, calculated[:]) ||
			!bytes.Equal(linkedPrevious, previous) {
			t.Fatalf("publication chain revision=%d expected=%d digest_ok=%t previous_ok=%t",
				revision, expectedRevision, bytes.Equal(digest, calculated[:]), bytes.Equal(linkedPrevious, previous))
		}
		previous = append(previous[:0], digest...)
		expectedRevision++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestReviewLockOrderPublicationLocksReferencedSites(t *testing.T) {
	t.Run("site deletion commits first", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, false, "lock-order-publication-delete-first")
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		defer cancel()
		deletion, err := setup.fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer deletion.Rollback(context.Background())
		if _, err := deletion.Exec(ctx, `UPDATE sites SET deleted_at=$2,updated_at=$2 WHERE id=$1`,
			setup.identities.siteID, storeTime(time.Now())); err != nil {
			t.Fatal(err)
		}
		publication, err := setup.fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer publication.Rollback(context.Background())
		var pid int
		if err := publication.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		revision, previous, err := latestLockOrderPublication(ctx, publication)
		if err != nil {
			t.Fatal(err)
		}
		canonical := followupPublicationSnapshot(revision+1, []SnapshotSite{{
			SiteKey: setup.identities.siteID.String(), Rules: []SnapshotRule{},
		}}, 0)
		completed := make(chan error, 1)
		go func() {
			completed <- insertLockOrderPublication(ctx, publication, setup.identities,
				revision+1, previous, canonical)
		}()
		finished, insertErr := waitForBackendLockOrCompletion(t, ctx, setup.fixture.pool, pid, completed)
		if finished {
			t.Fatalf("publication validation completed before site deletion commit: %v", insertErr)
		}
		if err := deletion.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := receiveLockOrderError(t, ctx, completed, "publication after site deletion"); err == nil {
			t.Fatal("publication accepted a site deleted before validation acquired its row lock")
		}
	})

	t.Run("publication commits first", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, false, "lock-order-publication-first")
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		defer cancel()
		publication, err := setup.fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer publication.Rollback(context.Background())
		revision, previous, err := latestLockOrderPublication(ctx, publication)
		if err != nil {
			t.Fatal(err)
		}
		canonical := followupPublicationSnapshot(revision+1, []SnapshotSite{{
			SiteKey: setup.identities.siteID.String(), Rules: []SnapshotRule{},
		}}, 0)
		if err := insertLockOrderPublication(ctx, publication, setup.identities,
			revision+1, previous, canonical); err != nil {
			t.Fatal(err)
		}
		deletion, err := setup.fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer deletion.Rollback(context.Background())
		var pid int
		if err := deletion.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		completed := make(chan error, 1)
		go func() {
			_, err := deletion.Exec(ctx, `UPDATE sites SET deleted_at=$2,updated_at=$2 WHERE id=$1`,
				setup.identities.siteID, storeTime(time.Now()))
			completed <- err
		}()
		finished, updateErr := waitForBackendLockOrCompletion(t, ctx, setup.fixture.pool, pid, completed)
		if finished {
			t.Fatalf("site deletion completed before publication commit: %v", updateErr)
		}
		if err := publication.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := receiveLockOrderError(t, ctx, completed, "site deletion"); err != nil {
			t.Fatal(err)
		}
		if err := deletion.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(ctx, setup.fixture.pool, func(tx pgx.Tx) error {
			revision, previous, err := latestLockOrderPublication(ctx, tx)
			if err != nil {
				return err
			}
			return insertLockOrderPublication(ctx, tx, setup.identities, revision+1, previous,
				followupPublicationSnapshot(revision+1, []SnapshotSite{{
					SiteKey: setup.identities.siteID.String(), Rules: []SnapshotRule{},
				}}, 0))
		}); err == nil {
			t.Fatal("new publication accepted a site after its deletion committed")
		}
		assertLockOrderPublicationChain(t, setup.fixture.pool)
	})
}

func TestReviewLockOrderAllNonTombstoneSiteRevisionsRequireActiveSite(t *testing.T) {
	t.Run("disabled update", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, false, "lock-order-disabled-update")
		softDeleteFollowupSite(t, setup.fixture.pool, setup.identities.siteID)
		before := readLockOrderFactCounts(t, setup.fixture.pool)
		fields := setup.rule.Value.Fields
		fields.Match = StatusSelector{Kind: MatchExact, From: 519}
		_, err := setup.service.UpdateRule(t.Context(), setup.identities.tenantOwner, UpdateRuleRequest{
			RuleID: setup.rule.Value.ID, ExpectedRevision: setup.rule.Value.Revision,
			Fields: fields, WriteMetadata: writeMetadata("lock-order-disabled-update-write"),
		})
		if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
			t.Fatalf("disabled update error=%v", err)
		}
		if after := readLockOrderFactCounts(t, setup.fixture.pool); after != before {
			t.Fatalf("disabled update left facts: before=%+v after=%+v", before, after)
		}
	})

	t.Run("completed disabled replay", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, false, "lock-order-disabled-replay")
		fields := setup.rule.Value.Fields
		fields.Match = StatusSelector{Kind: MatchExact, From: 519}
		request := UpdateRuleRequest{
			RuleID: setup.rule.Value.ID, ExpectedRevision: setup.rule.Value.Revision,
			Fields: fields, WriteMetadata: writeMetadata("lock-order-disabled-replay-write"),
		}
		if _, err := setup.service.UpdateRule(t.Context(), setup.identities.tenantOwner, request); err != nil {
			t.Fatal(err)
		}
		softDeleteFollowupSite(t, setup.fixture.pool, setup.identities.siteID)
		before := readLockOrderFactCounts(t, setup.fixture.pool)
		_, err := setup.service.UpdateRule(t.Context(), setup.identities.tenantOwner, request)
		if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
			t.Fatalf("completed disabled replay error=%v", err)
		}
		if after := readLockOrderFactCounts(t, setup.fixture.pool); after != before {
			t.Fatalf("disabled replay left facts: before=%+v after=%+v", before, after)
		}
	})

	t.Run("direct disabled revision", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, false, "lock-order-disabled-direct")
		softDeleteFollowupSite(t, setup.fixture.pool, setup.identities.siteID)
		before := readLockOrderFactCounts(t, setup.fixture.pool)
		err := pgx.BeginFunc(t.Context(), setup.fixture.pool, func(tx pgx.Tx) error {
			return insertLockOrderRuleRevision(t.Context(), tx, setup, 2, 519, false, false,
				"lock-order-disabled-direct-write")
		})
		if err == nil {
			t.Fatal("direct disabled non-tombstone revision succeeded for deleted site")
		}
		if after := readLockOrderFactCounts(t, setup.fixture.pool); after != before {
			t.Fatalf("direct disabled revision left facts: before=%+v after=%+v", before, after)
		}
	})

	t.Run("direct tombstone cleanup", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, false, "lock-order-tombstone-direct")
		softDeleteFollowupSite(t, setup.fixture.pool, setup.identities.siteID)
		if err := pgx.BeginFunc(t.Context(), setup.fixture.pool, func(tx pgx.Tx) error {
			return insertLockOrderRuleRevision(t.Context(), tx, setup, 2, 518, false, true,
				"lock-order-tombstone-direct-write")
		}); err != nil {
			t.Fatalf("direct tombstone cleanup failed: %v", err)
		}
		var revision int64
		var deleted bool
		if err := setup.fixture.pool.QueryRow(t.Context(), `SELECT revision,deleted
			FROM error_page_rule_revisions WHERE rule_id=$1 ORDER BY revision DESC LIMIT 1`,
			setup.rule.Value.ID).Scan(&revision, &deleted); err != nil || revision != 2 || !deleted {
			t.Fatalf("tombstone revision=%d deleted=%t err=%v", revision, deleted, err)
		}
	})
}

func lockOrderUpdateService(
	t *testing.T,
	setup followupRuleSetup,
	pid chan<- int,
	key string,
) (*Service, UpdateRuleRequest) {
	t.Helper()
	limits := staticLimits{quota: AssetQuota{
		MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20,
	}}
	service := newReviewService(t, setup.fixture.pool, newMemoryContentStore(), limits,
		pidReviewAuthorizer{delegate: testTxAuthorizer{}, pid: pid})
	fields := setup.rule.Value.Fields
	fields.Match = StatusSelector{Kind: MatchExact, From: 519}
	return service, UpdateRuleRequest{
		RuleID: setup.rule.Value.ID, ExpectedRevision: setup.rule.Value.Revision,
		Fields: fields, WriteMetadata: writeMetadata(key),
	}
}

func receiveLockOrderPID(t *testing.T, ctx context.Context, pid <-chan int) int {
	t.Helper()
	select {
	case value := <-pid:
		return value
	case <-ctx.Done():
		t.Fatalf("service authorizer did not report backend pid: %v", ctx.Err())
		return 0
	}
}

func TestReviewLockOrderDirectRevisionAndServicePublication(t *testing.T) {
	t.Run("direct revision first", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, false, "lock-order-direct-first")
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		direct, err := setup.fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer direct.Rollback(context.Background())
		if err := insertLockOrderRuleRevision(ctx, direct, setup, 2, 518, false, false,
			"lock-order-direct-first-revision"); err != nil {
			t.Fatal(err)
		}
		pid := make(chan int, 1)
		service, request := lockOrderUpdateService(t, setup, pid, "lock-order-direct-first-service")
		serviceDone := make(chan error, 1)
		go func() {
			_, err := service.UpdateRule(ctx, setup.identities.tenantOwner, request)
			serviceDone <- err
		}()
		servicePID := receiveLockOrderPID(t, ctx, pid)
		finished, serviceErr := waitForBackendLockOrCompletion(t, ctx, setup.fixture.pool, servicePID, serviceDone)
		if finished {
			t.Fatalf("service completed before direct transaction released its locks: %v", serviceErr)
		}
		revision, previous, err := latestLockOrderPublication(ctx, direct)
		if err != nil {
			t.Fatal(err)
		}
		directErr := insertLockOrderPublication(ctx, direct, setup.identities, revision+1, previous,
			followupPublicationSnapshot(revision+1, []SnapshotSite{}, 0))
		if directErr == nil {
			directErr = direct.Commit(ctx)
		} else {
			_ = direct.Rollback(ctx)
		}
		serviceErr = receiveLockOrderError(t, ctx, serviceDone, "service update after direct publication")
		if sqlState(directErr) == "40P01" || sqlState(serviceErr) == "40P01" {
			t.Fatalf("deadlock detected: direct=%v service=%v", directErr, serviceErr)
		}
		if directErr != nil || !errors.Is(serviceErr, ErrRevisionConflict) {
			t.Fatalf("direct=%v service=%v, want direct success and service revision conflict", directErr, serviceErr)
		}
		assertLockOrderPublicationChain(t, setup.fixture.pool)
	})

	t.Run("service publication first", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, false, "lock-order-service-first")
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		gate, err := setup.fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer gate.Rollback(context.Background())
		if _, err := gate.Exec(ctx, `SELECT id FROM error_page_rules WHERE id=$1 FOR UPDATE`,
			setup.rule.Value.ID); err != nil {
			t.Fatal(err)
		}
		pid := make(chan int, 1)
		service, request := lockOrderUpdateService(t, setup, pid, "lock-order-service-first-service")
		serviceDone := make(chan error, 1)
		go func() {
			_, err := service.UpdateRule(ctx, setup.identities.tenantOwner, request)
			serviceDone <- err
		}()
		servicePID := receiveLockOrderPID(t, ctx, pid)
		finished, serviceErr := waitForBackendLockOrCompletion(t, ctx, setup.fixture.pool, servicePID, serviceDone)
		if finished {
			t.Fatalf("service completed while its rule row was locked: %v", serviceErr)
		}
		direct, err := setup.fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer direct.Rollback(context.Background())
		var directPID int
		if err := direct.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&directPID); err != nil {
			t.Fatal(err)
		}
		directDone := make(chan error, 1)
		go func() {
			directDone <- insertLockOrderRuleRevision(ctx, direct, setup, 2, 518, false, false,
				"lock-order-service-first-revision")
		}()
		finished, directErr := waitForBackendLockOrCompletion(t, ctx, setup.fixture.pool, directPID, directDone)
		if finished {
			t.Fatalf("direct revision completed while upstream locks were held: %v", directErr)
		}
		if err := gate.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		serviceErr = receiveLockOrderError(t, ctx, serviceDone, "service-first update")
		directErr = receiveLockOrderError(t, ctx, directDone, "direct revision after service publication")
		_ = direct.Rollback(ctx)
		if sqlState(serviceErr) == "40P01" || sqlState(directErr) == "40P01" {
			t.Fatalf("deadlock detected: service=%v direct=%v", serviceErr, directErr)
		}
		if serviceErr != nil || sqlState(directErr) != "P0001" {
			t.Fatalf("service=%v direct=%v state=%s, want service success and direct conflict",
				serviceErr, directErr, sqlState(directErr))
		}
		assertLockOrderPublicationChain(t, setup.fixture.pool)
	})
}

func TestReviewLockOrderDirectRevisionPublicationStress(t *testing.T) {
	setup := newFollowupRuleSetup(t, false, "lock-order-stress-base")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for round := 0; round < 12; round++ {
		created, err := setup.service.CreateRule(ctx, setup.identities.tenantOwner, CreateRuleRequest{
			Target: RuleTarget{Kind: ScopeSite, ScopeID: setup.identities.tenantScope, SiteID: &setup.identities.siteID},
			Fields: RuleFields{Category: CategoryOriginResponse,
				Match: StatusSelector{Kind: MatchExact, From: 530 + round}, AssetID: setup.asset.ID},
			WriteMetadata: writeMetadata(fmt.Sprintf("lock-order-stress-create-%d", round)),
		})
		if err != nil {
			t.Fatal(err)
		}
		roundSetup := setup
		roundSetup.rule = created
		start := make(chan struct{})
		directDone := make(chan error, 1)
		serviceDone := make(chan error, 1)
		go func() {
			<-start
			directDone <- pgx.BeginFunc(ctx, setup.fixture.pool, func(tx pgx.Tx) error {
				if err := insertLockOrderRuleRevision(ctx, tx, roundSetup, 2, 530+round, false, false,
					fmt.Sprintf("lock-order-stress-direct-%d", round)); err != nil {
					return err
				}
				revision, previous, err := latestLockOrderPublication(ctx, tx)
				if err != nil {
					return err
				}
				return insertLockOrderPublication(ctx, tx, setup.identities, revision+1, previous,
					followupPublicationSnapshot(revision+1, []SnapshotSite{}, 0))
			})
		}()
		go func() {
			<-start
			fields := created.Value.Fields
			fields.Match = StatusSelector{Kind: MatchExact, From: 540 + round}
			_, err := setup.service.UpdateRule(ctx, setup.identities.tenantOwner, UpdateRuleRequest{
				RuleID: created.Value.ID, ExpectedRevision: created.Value.Revision, Fields: fields,
				WriteMetadata: writeMetadata(fmt.Sprintf("lock-order-stress-service-%d", round)),
			})
			serviceDone <- err
		}()
		close(start)
		directErr := receiveLockOrderError(t, ctx, directDone, "stress direct transaction")
		serviceErr := receiveLockOrderError(t, ctx, serviceDone, "stress service transaction")
		if sqlState(directErr) == "40P01" || sqlState(serviceErr) == "40P01" {
			t.Fatalf("round %d deadlock: direct=%v service=%v", round, directErr, serviceErr)
		}
		if !((directErr == nil && errors.Is(serviceErr, ErrRevisionConflict)) ||
			(serviceErr == nil && sqlState(directErr) == "P0001")) {
			t.Fatalf("round %d direct=%v service=%v", round, directErr, serviceErr)
		}
		var latest int64
		if err := setup.fixture.pool.QueryRow(ctx, `SELECT max(revision) FROM error_page_rule_revisions
			WHERE rule_id=$1`, created.Value.ID).Scan(&latest); err != nil || latest != 2 {
			t.Fatalf("round %d latest rule revision=%d err=%v", round, latest, err)
		}
	}
	assertLockOrderPublicationChain(t, setup.fixture.pool)
}
