//go:build integration

package nodescheduler

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestCreateTargetSnapshotBindsRealNodesAndReplaysConcurrently(t *testing.T) {
	fixture := newIntegrationFixture(t)
	l1NodeIDs := []uuid.UUID{uuid.New(), uuid.New()}
	l2NodeIDs := []uuid.UUID{uuid.New(), uuid.New()}
	sort.Slice(l1NodeIDs, func(left, right int) bool { return l1NodeIDs[left].String() < l1NodeIDs[right].String() })
	for index, nodeID := range append(slices.Clone(l1NodeIDs), l2NodeIDs...) {
		seedSchedulerActiveNode(t, fixture, nodeID, "snapshot-node-"+string(rune('a'+index)))
	}
	groupID := uuid.New()
	request := fixture.putRequest(groupID, 0, "snapshot-group", "snapshot-create")
	request.Endpoints[0].NodeID = l2NodeIDs[0]
	request.Endpoints[1].NodeID = l2NodeIDs[1]
	ownEndpointAddresses(t, fixture, request.Endpoints)
	if _, err := fixture.service.PutGroup(context.Background(), fixture.actor, request); err != nil {
		t.Fatal(err)
	}

	const writers = 8
	results := make(chan TargetSnapshot, writers)
	errorsByWriter := make(chan error, writers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range writers {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			result, err := fixture.service.CreateTargetSnapshotForNodes(context.Background(), fixture.actor, groupID, 1,
				l1NodeIDs, "snapshot-targets", "snapshot-targets-"+strconv.Itoa(index))
			results <- result
			errorsByWriter <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Fatalf("concurrent snapshot error = %v", err)
		}
	}
	var created TargetSnapshot
	createdCount, replayCount := 0, 0
	for result := range results {
		if result.Replayed {
			replayCount++
		} else {
			createdCount++
			created = result
		}
	}
	if createdCount != 1 || replayCount != writers-1 ||
		created.Reference.ID != uuid.NewSHA1(groupID, []byte(targetNodeSetSchema)) ||
		created.Reference.Revision != 1 || created.SourceRevision != 1 ||
		!slices.Equal(created.NodeIDs, l1NodeIDs) || created.Reference.SHA256 != CanonicalNodeSetDigest(l1NodeIDs) {
		t.Fatalf("concurrent snapshot created=%d replay=%d snapshot=%#v", createdCount, replayCount, created)
	}
	replayed, err := fixture.service.CreateTargetSnapshotForNodes(context.Background(), fixture.actor, groupID, 1,
		l1NodeIDs, "snapshot-targets", "snapshot-targets-different-request")
	if err != nil || !replayed.Replayed || replayed.Reference != created.Reference ||
		!slices.Equal(replayed.NodeIDs, created.NodeIDs) {
		t.Fatalf("operation replay with different request ID = %#v, %v", replayed, err)
	}
	if _, err := fixture.service.CreateTargetSnapshotForNodes(context.Background(), fixture.actor, groupID, 1,
		l1NodeIDs[:1], "snapshot-targets", "snapshot-targets-drift"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("snapshot payload drift error = %v", err)
	}
	if _, err := fixture.service.CreateTargetSnapshotForNodes(context.Background(), fixture.actor, groupID, 1,
		l1NodeIDs[:1], "snapshot-natural-conflict", "snapshot-natural-conflict-request"); !errors.Is(err, ErrTargetSnapshotConflict) {
		t.Fatalf("snapshot natural conflict error = %v", err)
	}
	var receiptOperation string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT operation FROM node_scheduling_write_requests
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND idempotency_key='snapshot-targets'`,
		fixture.actor.ScopeID, fixture.actor.UserID).Scan(&receiptOperation); err != nil {
		t.Fatal(err)
	}
	if receiptOperation != operationTargetSnapshotCreate {
		t.Fatalf("snapshot receipt operation=%q", receiptOperation)
	}
	loaded, err := fixture.service.GetTargetSnapshot(t.Context(), fixture.actor, groupID, 1)
	if err != nil || loaded.Reference != created.Reference || !slices.Equal(loaded.NodeIDs, created.NodeIDs) {
		t.Fatalf("loaded snapshot=%#v err=%v", loaded, err)
	}
	if _, err := fixture.service.GetTargetSnapshot(t.Context(), fixture.actor, groupID, 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing snapshot read error=%v", err)
	}

	for sourceRevision := int64(1); sourceRevision <= 2; sourceRevision++ {
		request := fixture.putRequest(groupID, sourceRevision, "snapshot-group-"+strconv.FormatInt(sourceRevision, 10),
			"snapshot-update-"+strconv.FormatInt(sourceRevision, 10))
		request.Endpoints[0].NodeID = l2NodeIDs[0]
		request.Endpoints[1].NodeID = l2NodeIDs[1]
		if _, err := fixture.service.PutGroup(context.Background(), fixture.actor, request); err != nil {
			t.Fatal(err)
		}
	}
	thirdSourceSnapshot, err := fixture.service.CreateTargetSnapshotForNodes(context.Background(), fixture.actor, groupID, 3,
		l1NodeIDs, "snapshot-revision-three", "snapshot-revision-three-request")
	if err != nil || thirdSourceSnapshot.Reference.Revision != 2 || thirdSourceSnapshot.SourceRevision != 3 {
		t.Fatalf("independent snapshot revision = %#v, %v", thirdSourceSnapshot, err)
	}
	firstAtThirdGroupID := uuid.New()
	for sourceRevision := int64(0); sourceRevision <= 2; sourceRevision++ {
		request := fixture.putRequest(firstAtThirdGroupID, sourceRevision,
			"snapshot-first-at-three-"+strconv.FormatInt(sourceRevision+1, 10),
			"snapshot-first-at-three-"+strconv.FormatInt(sourceRevision+1, 10))
		request.Endpoints[0].NodeID = l2NodeIDs[0]
		request.Endpoints[1].NodeID = l2NodeIDs[1]
		if _, err := fixture.service.PutGroup(context.Background(), fixture.actor, request); err != nil {
			t.Fatal(err)
		}
	}
	firstAtThird, err := fixture.service.CreateTargetSnapshotForNodes(
		context.Background(), fixture.actor, firstAtThirdGroupID, 3, l1NodeIDs,
		"snapshot-first-at-three", "snapshot-first-at-three-request")
	if err != nil || firstAtThird.Reference.Revision != 1 || firstAtThird.SourceRevision != 3 {
		t.Fatalf("first snapshot at source revision three = %#v, %v", firstAtThird, err)
	}
	viewer := seedTenantViewer(t, fixture.pool, fixture.actor.ScopeID, "snapshot-readonly")
	if _, err := fixture.service.CreateTargetSnapshotForNodes(context.Background(), viewer, groupID, 1,
		l1NodeIDs, "snapshot-viewer-denied", "snapshot-viewer-denied-request"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("snapshot viewer write error = %v", err)
	}

	rollbackGroupID := uuid.New()
	rollbackRequest := fixture.putRequest(rollbackGroupID, 0, "snapshot-audit-rollback", "snapshot-audit-rollback")
	rollbackRequest.Endpoints[0].NodeID = l2NodeIDs[0]
	rollbackRequest.Endpoints[1].NodeID = l2NodeIDs[1]
	if _, err := fixture.service.PutGroup(context.Background(), fixture.actor, rollbackRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `
		CREATE FUNCTION fail_target_snapshot_audit()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		    RAISE EXCEPTION 'forced target snapshot audit failure';
		END;
		$$;
		CREATE TRIGGER fail_target_snapshot_audit_insert
		BEFORE INSERT ON audit_events
		FOR EACH ROW WHEN (NEW.action = 'node_scheduling.target_snapshot.create')
		EXECUTE FUNCTION fail_target_snapshot_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.CreateTargetSnapshotForNodes(context.Background(), fixture.actor, rollbackGroupID, 1,
		l1NodeIDs, "snapshot-audit-failure", "snapshot-audit-failure-request"); err == nil ||
		!strings.Contains(err.Error(), "forced target snapshot audit failure") {
		t.Fatalf("target snapshot audit failure error = %v", err)
	}
	rollbackSnapshotID := uuid.NewSHA1(rollbackGroupID, []byte(targetNodeSetSchema))
	var parentCount, childCount, auditCount, receiptCount int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_target_snapshots WHERE source_line_group_id=$1`, rollbackGroupID).Scan(&parentCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_target_snapshot_nodes WHERE snapshot_id=$1`, rollbackSnapshotID).Scan(&childCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE resource_type='edge_target_snapshot' AND resource_id=$1`,
		rollbackSnapshotID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM node_scheduling_write_requests
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key='snapshot-audit-failure'`,
		fixture.actor.ScopeID, fixture.actor.UserID, operationTargetSnapshotCreate).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if parentCount != 0 || childCount != 0 || auditCount != 0 || receiptCount != 0 {
		t.Fatalf("target snapshot audit rollback counts parent=%d child=%d audit=%d receipt=%d",
			parentCount, childCount, auditCount, receiptCount)
	}
	if _, err := fixture.pool.Exec(t.Context(), `
		DROP TRIGGER fail_target_snapshot_audit_insert ON audit_events;
		DROP FUNCTION fail_target_snapshot_audit()`); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.pool.Exec(t.Context(), `UPDATE nodes SET admin_state='disabled' WHERE id=$1`, l1NodeIDs[0]); err != nil {
		t.Fatal(err)
	}
	disabledGroupID := uuid.New()
	disabledRequest := fixture.putRequest(disabledGroupID, 0, "snapshot-disabled", "snapshot-disabled-group")
	disabledRequest.Endpoints[0].NodeID, disabledRequest.Endpoints[1].NodeID = l2NodeIDs[0], l2NodeIDs[1]
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, disabledRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.CreateTargetSnapshotForNodes(context.Background(), fixture.actor, disabledGroupID, 1,
		l1NodeIDs[:1], "snapshot-disabled-target", "snapshot-disabled-target-request"); !errors.Is(err, ErrTargetSnapshotUnavailable) {
		t.Fatalf("disabled node snapshot error = %v", err)
	}
}
