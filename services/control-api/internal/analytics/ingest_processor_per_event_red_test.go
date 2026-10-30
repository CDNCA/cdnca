package analytics

import (
	"context"
	"errors"
	"testing"
	"time"
)

type ingestWatermarkStateProviderStubV1 struct {
	dependency AnalyticsWatermarkDependencyStateV1
	state      AnalyticsWatermarkStateV1
	err        error
	calls      int
}

func (stub *ingestWatermarkStateProviderStubV1) WatermarkState(_ context.Context, _ AnalyticsWatermarkKeyV1) (AnalyticsWatermarkDependencyStateV1, AnalyticsWatermarkStateV1, error) {
	stub.calls++
	return stub.dependency, stub.state, stub.err
}

type ingestWatermarkBatchAuthorityStubV1 struct {
	decision func(AnalyticsWatermarkBatchRequestV1) (AnalyticsWatermarkBatchDecisionV1, error)
	calls    int
	request  AnalyticsWatermarkBatchRequestV1
}

func (stub *ingestWatermarkBatchAuthorityStubV1) DecideAndCommitBatch(_ context.Context, request AnalyticsWatermarkBatchRequestV1) (AnalyticsWatermarkBatchDecisionV1, error) {
	stub.calls++
	stub.request = request
	return stub.decision(request)
}

func TestIngestProcessorPerEventWatermarkRejectsBeforeClickHouseAndPrepared(t *testing.T) {
	now := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	generation := processorFixtureGenerationV1()
	history := newRecordingIngestHistoryAuthorityV1(t, generation)
	writer := &fakeIngestWriter{}
	state := &ingestWatermarkStateProviderStubV1{dependency: AnalyticsWatermarkDependencyReady}
	authority := &ingestWatermarkBatchAuthorityStubV1{decision: func(request AnalyticsWatermarkBatchRequestV1) (AnalyticsWatermarkBatchDecisionV1, error) {
		return AnalyticsWatermarkBatchDecisionV1{}, ErrAnalyticsWatermarkFinalized
	}}
	processor := mustProcessor(t, now, writer, &memoryIsolationSink{}, IngestProcessorConfig{
		History: history, HistoryGeneration: generation,
		WatermarkPolicy:        AnalyticsWatermarkPolicyV1{Enabled: true, MaxLateRevision: time.Hour},
		WatermarkStateProvider: state, WatermarkAuthority: authority,
	})
	delivery := newFakeDelivery(t, "watermark-finalized", now, []AccessEvent{eventAt(validAccessEvent("watermark-finalized-event"), now.Add(-time.Minute))})
	result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
	if err == nil || writer.accessCalls != 0 || history.prepared || authority.calls != 1 || state.calls != 1 || result.Acknowledged != 0 {
		t.Fatalf("result=%#v err=%v writer=%#v history=%#v authority=%#v state=%#v", result, err, writer, history, authority, state)
	}
}

func TestIngestProcessorPerEventWatermarkRetryAfterClickHouseUnknownOutcome(t *testing.T) {
	now := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	generation := processorFixtureGenerationV1()
	history := newRecordingIngestHistoryAuthorityV1(t, generation)
	state := &ingestWatermarkStateProviderStubV1{dependency: AnalyticsWatermarkDependencyReady}
	authority := &ingestWatermarkBatchAuthorityStubV1{decision: func(request AnalyticsWatermarkBatchRequestV1) (AnalyticsWatermarkBatchDecisionV1, error) {
		return EvaluateAnalyticsWatermarkBatchV1(request.LastKnownGood, request)
	}}
	firstWriter := &fakeIngestWriter{accessErrors: []error{ErrIngestWriteOutcomeUnknown}}
	processor := mustProcessor(t, now, firstWriter, &memoryIsolationSink{}, IngestProcessorConfig{
		History: history, HistoryGeneration: generation,
		WatermarkPolicy:        AnalyticsWatermarkPolicyV1{Enabled: true, MaxLateRevision: time.Hour},
		WatermarkStateProvider: state, WatermarkAuthority: authority,
	})
	first := newFakeDelivery(t, "watermark-retry", now, []AccessEvent{eventAt(validAccessEvent("watermark-retry-event"), now.Add(-time.Minute))})
	if result, err := processor.Process(context.Background(), []IngestDelivery{first}); err != nil || result.Naked != 1 || history.prepared || len(history.receipts) != 1 {
		t.Fatalf("first result=%#v err=%v writer=%#v history=%#v", result, err, firstWriter, history)
	}

	restartedWriter := &fakeIngestWriter{}
	restarted := mustProcessor(t, now, restartedWriter, &memoryIsolationSink{}, IngestProcessorConfig{
		History: history, HistoryGeneration: generation,
		WatermarkPolicy:        AnalyticsWatermarkPolicyV1{Enabled: true, MaxLateRevision: time.Hour},
		WatermarkStateProvider: state, WatermarkAuthority: authority,
	})
	redelivery := newFakeDelivery(t, "watermark-retry", now, []AccessEvent{eventAt(validAccessEvent("watermark-retry-event"), now.Add(-time.Minute))})
	if result, err := restarted.Process(context.Background(), []IngestDelivery{redelivery}); err != nil || result.Acknowledged != 1 || restartedWriter.accessCalls != 1 || !history.prepared || len(history.receipts) != 1 {
		t.Fatalf("replay result=%#v err=%v writer=%#v history=%#v", result, err, restartedWriter, history)
	}
}

var _ = errors.Is
