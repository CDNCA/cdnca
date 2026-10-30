package analytics

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBuildIngestRuntimeStartupHistorySnapshotUsesCallerContext(t *testing.T) {
	generation := authorityGenerationV1()
	history := newRecordingIngestHistoryAuthorityV1(t, generation)
	config := JetStreamConfig{
		Stream: generation.StreamName, Durable: generation.DurableName,
		OperationTimeout: time.Second,
	}

	t.Run("legacy and unbounded forms fail closed", func(t *testing.T) {
		if runtime, err := BuildIngestRuntime(nil, nil, config, IngestDecoderConfig{}, nil, history, generation); runtime != nil || !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("legacy build = (%#v, %v), want fail closed", runtime, err)
		}
		if runtime, err := BuildIngestRuntime(nil, nil, config, IngestDecoderConfig{}, nil,
			context.Background(), history, generation); runtime != nil || !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("unbounded build = (%#v, %v), want fail closed", runtime, err)
		}
	})

	t.Run("cancellation before consumer creation wins", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		cancel()
		runtime, err := BuildIngestRuntime(nil, nil, config, IngestDecoderConfig{}, nil,
			ctx, history, generation)
		if runtime != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-cancelled build = (%#v, %v), want caller cancellation", runtime, err)
		}
	})

	t.Run("deadline during snapshot wins before later setup", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		err := snapshotIngestHistoryAtStartup(ctx, func(snapshotCtx context.Context) error {
			if _, ok := snapshotCtx.Deadline(); !ok {
				t.Fatal("snapshot context has no deadline")
			}
			<-snapshotCtx.Done()
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("snapshot error = %v, want caller deadline", err)
		}
	})
}
