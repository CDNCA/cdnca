//go:build integration

package nodeidentity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodemetrics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// After "重装此节点" the new host's Agent numbers
// its monitoring reports from 1 again (the sequence lives in
// /var/lib/cdnca-node-monitoring) and derives the same event IDs from them.
// Every report below the previous host's highest sequence (7713) was refused
// as stale (P1501), and node_metric_latest kept showing the previous host's
// expired sample. Migration 626 compares sequences only within the node's
// current host (host_epoch: enrollments so far, minus one).
func TestReinstalledHostMetricSequenceStartsOver(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	ctx := context.Background()
	store, err := nodemetrics.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	reinstalled := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	enrolledOnce := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	for index, fixture := range []identityFixture{reinstalled, enrolledOnce} {
		request := validAuthorizeRequest(t, testCSR(t, false))
		request.EnrollmentToken = fixture.token
		request.ArtifactEncryptionPublicKey = bytesOf(32, byte(40+index))
		enrollIdentity(t, service, request)
	}
	var puback uint64
	put := func(nodeID uuid.UUID, sequence uint64, host string) (nodemetrics.Sample, bool, error) {
		t.Helper()
		puback++
		sample := agentProbeSample(nodeID, sequence, puback, host)
		replayed, err := store.Put(ctx, sample)
		return sample, replayed, err
	}
	mustPut := func(nodeID uuid.UUID, sequence uint64, host string) nodemetrics.Sample {
		t.Helper()
		sample, replayed, err := put(nodeID, sequence, host)
		if err != nil || replayed {
			t.Fatalf("Put(%s seq %d %s) = replayed %v, %v", nodeID, sequence, host, replayed, err)
		}
		return sample
	}
	refused := func(nodeID uuid.UUID, sequence uint64, host string) {
		t.Helper()
		if _, _, err := put(nodeID, sequence, host); !errors.Is(err, nodemetrics.ErrConflict) {
			t.Fatalf("Put(%s seq %d %s) error = %v, want ErrConflict", nodeID, sequence, host, err)
		}
	}
	for sequence := uint64(1); sequence <= 3; sequence++ {
		mustPut(reinstalled.nodeID, sequence, "old")
		mustPut(enrolledOnce.nodeID, sequence, "only")
	}
	previousNewest := mustPut(reinstalled.nodeID, 7713, "old")
	refused(reinstalled.nodeID, 5, "old") // a step back within one host

	clock.set(now.Add(10 * time.Minute))
	reinstall := reenrollRequest(t, pool, reinstalled, clock)
	reinstall.EnrollmentToken = issueIdentityToken(t, pool, reinstalled, clock.now(), "re_enrollment")
	enrollIdentity(t, service, reinstall)

	// The new host starts at 1 with the previous host's event IDs: accepted.
	first := mustPut(reinstalled.nodeID, 1, "new")
	if got := latestMetricSequence(t, pool, reinstalled.nodeID); got != first.EventID+"/1/1" {
		t.Fatalf("node_metric_latest after the new host's first report = %s", got)
	}
	mustPut(reinstalled.nodeID, 2, "new")
	refused(reinstalled.nodeID, 1, "new-other") // a step back within the new host is still refused
	// The previous host's sample redelivered as is stays a replay, not a conflict.
	if replayed, err := store.Put(ctx, previousNewest); err != nil || !replayed {
		t.Fatalf("redelivered previous host sample = replayed %v, %v", replayed, err)
	}
	if got := latestMetricSequence(t, pool, reinstalled.nodeID); got != agentEventID(reinstalled.nodeID, 2)+"/1/2" {
		t.Fatalf("node_metric_latest = %s, want the new host's sequence 2", got)
	}
	var load int64
	if err := pool.QueryRow(ctx, `SELECT publication_sequence FROM node_load_latest WHERE node_id=$1`,
		reinstalled.nodeID).Scan(&load); err != nil || load != 2 {
		t.Fatalf("node_load_latest sequence = %d, %v", load, err)
	}
	// History is kept: the previous host's four samples and the new host's two.
	var epochs string
	if err := pool.QueryRow(ctx, `SELECT string_agg(host_epoch||':'||count,',' ORDER BY host_epoch) FROM
		(SELECT host_epoch,count(*) FROM node_metric_samples WHERE node_id=$1 GROUP BY host_epoch) counted`,
		reinstalled.nodeID).Scan(&epochs); err != nil || epochs != "0:4,1:2" {
		t.Fatalf("samples per host = %s, %v", epochs, err)
	}

	// A node enrolled once is unaffected: epoch 0, a step back still refused.
	refused(enrolledOnce.nodeID, 2, "only-other")
	mustPut(enrolledOnce.nodeID, 4, "only")
	if got := latestMetricSequence(t, pool, enrolledOnce.nodeID); got != agentEventID(enrolledOnce.nodeID, 4)+"/0/4" {
		t.Fatalf("node_metric_latest of the node enrolled once = %s", got)
	}
}

// agentEventID is the Agent's event ID of report sequence (gatewayclient
// NodeMonitoringBridge.enqueue): the same on every host of the node.
func agentEventID(nodeID uuid.UUID, sequence uint64) string {
	return uuid.NewSHA1(nodeID, []byte(fmt.Sprintf("node-monitoring-metric/%d", sequence))).String()
}

func agentProbeSample(nodeID uuid.UUID, sequence, puback uint64, host string) nodemetrics.Sample {
	eventID := agentEventID(nodeID, sequence)
	return nodemetrics.Sample{EventID: eventID, RequestID: uuid.NewSHA1(nodeID, []byte("node-monitoring-report/"+eventID)).String(),
		NodeID: nodeID.String(), SchemaVersion: 1, Kind: nodemetrics.RecordMetric, ConfigRevision: 1, ActiveConfigRevision: 1,
		ProbePort: 80, PublicationSequence: sequence, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), ProbesTotal: 1,
		PubAckStream: nodemetrics.NodeMonitoringStatusStream, PubAckSequence: puback,
		ConsumerDurable: nodemetrics.DefaultConsumerDurable, ConsumerSequence: puback, NumDelivered: 1,
		WireSHA256: sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d", host, nodeID, sequence)))}
}

// latestMetricSequence is node_metric_latest's row for the node as
// event_id/host_epoch/publication_sequence.
func latestMetricSequence(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID) string {
	t.Helper()
	var eventID uuid.UUID
	var sequence int64
	if err := pool.QueryRow(context.Background(), `SELECT event_id,publication_sequence FROM node_metric_latest
		WHERE node_id=$1`, nodeID).Scan(&eventID, &sequence); err != nil {
		t.Fatal(err)
	}
	var epoch int
	if err := pool.QueryRow(context.Background(), `SELECT host_epoch FROM node_metric_samples
		WHERE event_id=$1 AND node_id=$2 AND publication_sequence=$3 ORDER BY host_epoch DESC LIMIT 1`,
		eventID, nodeID, sequence).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s/%d/%d", eventID, epoch, sequence)
}
