package analytics

import (
	"errors"
	"testing"
)

// 复现 73：PG 单独从转储还原后 broker_stream_ack_floor 落后于 NATS 实际 ack 地板，
// 中间序号已被 NATS 确认、PG 却没有接收记录。下一个序号准备必须先失败，
// 经一次 broker 对账同步地板后才能成功（处理器在准备失败时排期这次对账）。
func TestPostgresIngestHistoryPrepareGapRecoversAfterBrokerReconcile(t *testing.T) {
	fixture := openPostgresIngestHistoryFixtureV1(t)
	start := fixture.generation.HistoryStartSequence
	gapped := postgresIngestReceiptV1(t, fixture.generation, start+3, "postgres-prepare-gap")
	if _, err := fixture.history.Receive(t.Context(), gapped); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.history.MarkPrepared(t.Context(), gapped); !errors.Is(err, ErrIngestPreparationNotContiguous) || errors.Is(err, ErrIngestReceiptConflict) {
		t.Fatalf("prepare across broker gap error = %v, want non-contiguous rejection", err)
	}

	if err := fixture.history.ScheduleRecovery(t.Context(), fixture.generation); err != nil {
		t.Fatal(err)
	}
	claim, ok, err := fixture.history.ClaimScheduledRecovery(t.Context(), fixture.generation)
	if err != nil || !ok {
		t.Fatalf("claim = (%#v, %t, %v)", claim, ok, err)
	}
	snapshot := IngestBrokerHistorySnapshotV1{Generation: fixture.generation, ConsumerAckFloor: 3, StreamAckFloor: start + 2}
	if _, err := fixture.history.ReconcileBroker(t.Context(), claim, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := fixture.history.CompleteScheduledRecovery(t.Context(), claim); err != nil {
		t.Fatal(err)
	}

	progress, err := fixture.history.MarkPrepared(t.Context(), gapped)
	if err != nil || progress.PreparedStreamFloor != start+3 {
		t.Fatalf("prepare after reconcile = (%#v, %v)", progress, err)
	}
}
