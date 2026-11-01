package analytics

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 73 现场：PG 从较早的转储还原后，PG 的 broker_stream_ack_floor(4) 落后于
// NATS 消费者实际 ack 地板(6)，后续序号 7 起 MarkPrepared 永远“不连号”，
// 每批全部 nak。修复要求：准备失败时排期一次 broker 对账，让下一轮
// RunScheduledHistoryRecovery 把 NATS 地板同步回 PG。
func TestIngestProcessorPrepareFailureSchedulesBrokerReconcile(t *testing.T) {
	now := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	generation := authorityGenerationV1()
	history := newRecordingIngestHistoryAuthorityV1(t, generation)
	history.prepareErr = ErrIngestReceiptConflict
	delivery := newFakeDelivery(t, "prepare-gap", now, []AccessEvent{
		eventAt(validAccessEvent("prepare-gap-event"), now.Add(-time.Minute)),
	})
	delivery.installationID = generation.InstallationID
	delivery.streamSequence = generation.HistoryStartSequence + 2
	processor := authorityProcessorV1(t, now, &fakeIngestWriter{}, history, generation, &memoryIsolationSink{})

	result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
	if !errors.Is(err, ErrIngestReceiptConflict) {
		t.Fatalf("process error = %v, want prepare failure surfaced", err)
	}
	if result.Naked != 1 || result.Acknowledged != 0 || delivery.nakCount != 1 || delivery.ackCount != 0 {
		t.Fatalf("result=%#v nak=%d ack=%d", result, delivery.nakCount, delivery.ackCount)
	}
	if history.recoveryCount != 1 || !history.recoveryScheduled {
		t.Fatalf("recovery scheduled count = %d, want 1 so broker floor can be reconciled", history.recoveryCount)
	}
}
