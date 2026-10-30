package analytics

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestIngestProcessorCoalescingIsScopedToReceiptSequence(t *testing.T) {
	now := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	generation := authorityGenerationV1()
	newDelivery := func(t *testing.T, eventID string, sequence uint64) *fakeIngestDelivery {
		t.Helper()
		delivery := newFakeDelivery(t, "shared-message-id", now, []AccessEvent{
			eventAt(validAccessEvent(eventID), now.Add(-time.Minute)),
		})
		delivery.installationID = generation.InstallationID
		delivery.streamSequence = sequence
		return delivery
	}

	t.Run("consecutive sequences have independent receipts", func(t *testing.T) {
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		writer := &fakeIngestWriter{}
		first := newDelivery(t, "sequence-event", generation.HistoryStartSequence)
		second := newDelivery(t, "sequence-event", generation.HistoryStartSequence+1)
		if string(first.payload) != string(second.payload) {
			t.Fatal("consecutive deliveries are not byte-identical")
		}
		processor := authorityProcessorV1(t, now, writer, history, generation, &memoryIsolationSink{})

		result, err := processor.Process(context.Background(), []IngestDelivery{first, second})
		if err != nil {
			t.Fatal(err)
		}
		if result.Acknowledged != 2 || result.Naked != 0 || result.Terminated != 0 || result.WriteBatches != 2 {
			t.Fatalf("result = %#v", result)
		}
		if len(history.receipts) != 2 ||
			history.receipts[0].Key.StreamSequence != generation.HistoryStartSequence ||
			history.receipts[1].Key.StreamSequence != generation.HistoryStartSequence+1 {
			t.Fatalf("receipts = %#v", history.receipts)
		}
		firstToken, secondToken := history.receipts[0].ClickHouseToken, history.receipts[1].ClickHouseToken
		if firstToken == "" || secondToken == "" || firstToken == secondToken {
			t.Fatalf("receipt tokens = %q, %q", firstToken, secondToken)
		}
		if writer.accessCalls != 2 || len(writer.accessTokens) != 2 ||
			writer.accessTokens[0] != firstToken || writer.accessTokens[1] != secondToken {
			t.Fatalf("writer calls=%d tokens=%v", writer.accessCalls, writer.accessTokens)
		}
		if strings.Count(authorityOperationsV1(history), "pg-prepared") != 2 || history.brokerAckCount != 2 ||
			first.ackCount != 1 || second.ackCount != 1 {
			t.Fatalf("operations=%q broker observations=%d ACKs=%d,%d",
				authorityOperationsV1(history), history.brokerAckCount, first.ackCount, second.ackCount)
		}
	})

	t.Run("same sequence byte-identical replay still coalesces", func(t *testing.T) {
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		writer := &fakeIngestWriter{}
		first := newDelivery(t, "replay-event", generation.HistoryStartSequence)
		replay := *first
		processor := authorityProcessorV1(t, now, writer, history, generation, &memoryIsolationSink{})

		result, err := processor.Process(context.Background(), []IngestDelivery{first, &replay})
		if err != nil {
			t.Fatal(err)
		}
		if result.Acknowledged != 2 || result.Naked != 0 || result.Terminated != 0 || result.WriteBatches != 1 ||
			len(history.receipts) != 1 || writer.accessCalls != 1 || len(writer.accessTokens) != 1 ||
			writer.accessTokens[0] == "" || strings.Count(authorityOperationsV1(history), "pg-prepared") != 1 ||
			history.brokerAckCount != 1 || first.ackCount != 1 || replay.ackCount != 1 {
			t.Fatalf("result=%#v receipts=%#v writer=%#v operations=%q observations=%d ACKs=%d,%d",
				result, history.receipts, writer, authorityOperationsV1(history), history.brokerAckCount,
				first.ackCount, replay.ackCount)
		}
	})

	t.Run("same message identity rejects payload conflict across sequences", func(t *testing.T) {
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		writer := &fakeIngestWriter{}
		sink := &memoryIsolationSink{}
		first := newDelivery(t, "first-payload", generation.HistoryStartSequence)
		conflict := newDelivery(t, "different-payload", generation.HistoryStartSequence+1)
		processor := authorityProcessorV1(t, now, writer, history, generation, sink)

		result, err := processor.Process(context.Background(), []IngestDelivery{first, conflict})
		if err != nil {
			t.Fatal(err)
		}
		if result.Acknowledged != 1 || result.Terminated != 1 || len(history.receipts) != 1 ||
			writer.accessCalls != 1 || history.brokerAckCount != 1 || first.ackCount != 1 || conflict.termCount != 1 ||
			len(sink.records) != 1 || sink.records[0].ReasonCode != RejectIdentityMismatch {
			t.Fatalf("result=%#v receipts=%#v writer=%#v observations=%d deliveries=%#v/%#v records=%#v",
				result, history.receipts, writer, history.brokerAckCount, first, conflict, sink.records)
		}
	})

	t.Run("same message identity rejects installation conflict across sequences", func(t *testing.T) {
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		writer := &fakeIngestWriter{}
		sink := &memoryIsolationSink{}
		first := newDelivery(t, "installation-event", generation.HistoryStartSequence)
		conflict := newDelivery(t, "installation-event", generation.HistoryStartSequence+1)
		conflict.installationID = "22222222-2222-4222-8222-222222222222"
		processor := authorityProcessorV1(t, now, writer, history, generation, sink)

		result, err := processor.Process(context.Background(), []IngestDelivery{first, conflict})
		if err != nil {
			t.Fatal(err)
		}
		if result.Acknowledged != 1 || result.Terminated != 1 || len(history.receipts) != 1 ||
			writer.accessCalls != 1 || history.brokerAckCount != 1 || first.ackCount != 1 || conflict.termCount != 1 ||
			len(sink.records) != 1 || sink.records[0].ReasonCode != RejectIdentityMismatch {
			t.Fatalf("result=%#v receipts=%#v writer=%#v observations=%d deliveries=%#v/%#v records=%#v",
				result, history.receipts, writer, history.brokerAckCount, first, conflict, sink.records)
		}
	})
}
