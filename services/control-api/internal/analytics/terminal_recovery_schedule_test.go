package analytics

import (
	"errors"
	"testing"
	"time"
)

func TestTerminalIsolationSchedulesRecoveryBeforeBrokerSettlement(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "scheduled", true: "schedule-failure"}[fail], func(t *testing.T) {
			now := time.Now().UTC()
			generation := processorFixtureGenerationV1()
			history := &ackRecoveryContextAuthority{recordingIngestHistoryAuthorityV1: newRecordingIngestHistoryAuthorityV1(t, generation)}
			if fail {
				history.scheduleErr = errors.New("recovery unavailable")
			}
			processor := mustProcessor(t, now, &fakeIngestWriter{}, &memoryIsolationSink{}, IngestProcessorConfig{History: history, HistoryGeneration: generation})
			delivery := &fakeIngestDelivery{payload: []byte("invalid"), subject: IngestSubjectPrefix + "." + testNodeID, messageID: "terminal-test", attempts: 1, streamSequence: 1}
			result, err := processor.Process(t.Context(), []IngestDelivery{delivery})
			if history.scheduleCalls != 1 {
				t.Fatalf("recovery schedule calls=%d", history.scheduleCalls)
			}
			if fail {
				if err == nil || delivery.termCount != 0 || result.Naked != 1 {
					t.Fatalf("unsafe terminal settlement: %+v err=%v", result, err)
				}
			} else if err != nil || delivery.termCount != 1 || result.Terminated != 1 {
				t.Fatalf("terminal settlement failed: %+v err=%v", result, err)
			}
		})
	}
}
