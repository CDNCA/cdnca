package analytics

import (
	"context"
	"testing"
	"time"
)

// contiguousIngestHistoryV1 与 PG analytics_ingest_mark_prepared_098 一样要求严格连号准备。
type contiguousIngestHistoryV1 struct {
	*recordingIngestHistoryAuthorityV1
}

func (history contiguousIngestHistoryV1) MarkPrepared(ctx context.Context, receipt IngestReceiptV1) (IngestHistoryProgressV1, error) {
	history.mu.Lock()
	floor := max(history.progress.PreparedStreamFloor, history.progress.BrokerStreamAckFloor)
	history.mu.Unlock()
	if receipt.Key.StreamSequence <= floor {
		return history.progress, nil
	}
	if receipt.Key.StreamSequence != floor+1 {
		return history.progress, ErrIngestReceiptConflict
	}
	return history.recordingIngestHistoryAuthorityV1.MarkPrepared(ctx, receipt)
}

// 73 现场：重投消息各自 nak 延迟不同，一批里序号乱序到达（如 43、41、42）。
// 按到达顺序准备时只有排在前面的连号能成功，其余全部 nak 并退避，入库每分钟只推进一条。
// 修复要求批内按 stream 序号处理，连号的一批可一次全部确认。
func TestIngestProcessorPreparesBatchInStreamSequenceOrder(t *testing.T) {
	now := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	generation := authorityGenerationV1()
	history := contiguousIngestHistoryV1{newRecordingIngestHistoryAuthorityV1(t, generation)}
	start := generation.HistoryStartSequence
	var deliveries []IngestDelivery
	for _, offset := range []uint64{2, 0, 1} {
		delivery := newFakeDelivery(t, "order-"+string(rune('a'+offset)), now, []AccessEvent{
			eventAt(validAccessEvent("order-event-"+string(rune('a'+offset))), now.Add(-time.Minute)),
		})
		delivery.installationID = generation.InstallationID
		delivery.streamSequence = start + offset
		delivery.attempts = 5
		deliveries = append(deliveries, delivery)
	}
	processor := authorityProcessorV1(t, now, &fakeIngestWriter{}, history, generation, &memoryIsolationSink{})

	result, err := processor.Process(context.Background(), deliveries)
	if err != nil {
		t.Fatalf("process error = %v", err)
	}
	if result.Acknowledged != 3 || result.Naked != 0 {
		t.Fatalf("result = %#v, want all three contiguous sequences acknowledged", result)
	}
}
