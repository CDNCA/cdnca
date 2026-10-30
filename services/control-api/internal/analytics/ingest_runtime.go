package analytics

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

var ErrIngestDegraded = errors.New("analytics ingest dependency is degraded")

type IngestRuntime struct {
	consumer                     *NATSIngestConsumer
	processor                    *IngestProcessor
	logger                       *slog.Logger
	healthMu                     sync.RWMutex
	onHealthy                    func()
	requiresAcknowledgedRecovery bool
	historyRecoveryReady         bool
	emptyHealthyNotified         bool
	history                      IngestHistoryAuthorityV1
	historyGeneration            IngestHistoryGenerationV1
	operationTimeout             time.Duration
	brokerHistorySnapshot        func(context.Context) (IngestBrokerHistorySnapshotV1, error)
}

func BuildIngestRuntime(
	connection *nats.Conn,
	writer IngestWriter,
	jetstreamConfig JetStreamConfig,
	decoderConfig IngestDecoderConfig,
	logger *slog.Logger,
	historyArguments ...any,
) (*IngestRuntime, error) {
	if len(historyArguments) != 3 {
		return nil, ErrInvalidConfiguration
	}
	startupCtx, ok := historyArguments[0].(context.Context)
	if !ok {
		return nil, ErrInvalidConfiguration
	}
	if err := validateIngestRuntimeStartupContext(startupCtx); err != nil {
		return nil, err
	}
	history, ok := historyArguments[1].(IngestHistoryAuthorityV1)
	if !ok || history == nil {
		return nil, ErrInvalidConfiguration
	}
	historyGeneration, ok := historyArguments[2].(IngestHistoryGenerationV1)
	if !ok || ValidateIngestHistoryGenerationV1(historyGeneration) != nil ||
		historyGeneration.StreamName != jetstreamConfig.Stream || historyGeneration.DurableName != jetstreamConfig.Durable {
		return nil, ErrInvalidConfiguration
	}
	consumer, err := NewNATSIngestConsumer(connection, jetstreamConfig)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = consumer.Close()
		}
	}()
	if err := snapshotIngestHistoryAtStartup(startupCtx, func(snapshotCtx context.Context) error {
		_, snapshotErr := consumer.HistorySnapshot(snapshotCtx, historyGeneration)
		return snapshotErr
	}); err != nil {
		return nil, err
	}
	isolation, err := NewNATSIsolationSink(connection, jetstreamConfig)
	if err != nil {
		return nil, err
	}
	decoder, err := NewIngestDecoder(decoderConfig)
	if err != nil {
		return nil, err
	}
	processor, err := NewIngestProcessor(decoder, writer, isolation, IngestProcessorConfig{
		OperationTimeout: jetstreamConfig.OperationTimeout,
		NakBaseDelay:     jetstreamConfig.NakBaseDelay, NakMaxDelay: jetstreamConfig.NakMaxDelay,
		MaxDeliver: jetstreamConfig.MaxDeliver, MaxBatchEvents: DefaultMaxEventsPerEnvelope,
		Now: decoderConfig.Now, Logger: logger, History: history, HistoryGeneration: historyGeneration,
	})
	if err != nil {
		return nil, err
	}
	runtime, err := NewIngestRuntime(consumer, processor, logger)
	if err != nil {
		return nil, err
	}
	runtime.brokerHistorySnapshot = func(ctx context.Context) (IngestBrokerHistorySnapshotV1, error) {
		return consumer.HistorySnapshot(ctx, historyGeneration)
	}
	failed = false
	return runtime, nil
}

func validateIngestRuntimeStartupContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfiguration
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrInvalidConfiguration
	}
	return ctx.Err()
}

func snapshotIngestHistoryAtStartup(ctx context.Context, snapshot func(context.Context) error) error {
	if err := validateIngestRuntimeStartupContext(ctx); err != nil {
		return err
	}
	if snapshot == nil {
		return ErrInvalidConfiguration
	}
	err := snapshot(ctx)
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func NewIngestRuntime(
	consumer *NATSIngestConsumer,
	processor *IngestProcessor,
	logger *slog.Logger,
) (*IngestRuntime, error) {
	if consumer == nil || processor == nil || processor.operationTimeout <= 0 || processor.history == nil ||
		ValidateIngestHistoryGenerationV1(processor.historyGeneration) != nil {
		return nil, ErrInvalidConfiguration
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &IngestRuntime{
		consumer: consumer, processor: processor, logger: logger,
		history: processor.history, historyGeneration: processor.historyGeneration,
		operationTimeout: processor.operationTimeout,
	}, nil
}

func (runtime *IngestRuntime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	for {
		result, err := runtime.RunOnce(ctx)
		runtime.reportHealthy(result, err)
		if err == nil {
			if result.Naked > 0 {
				return ErrIngestDegraded
			}
			continue
		}
		if errors.Is(err, ErrNoIngestMessages) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
}

func (runtime *IngestRuntime) SetHealthyHandler(handler func()) {
	if runtime == nil {
		return
	}
	runtime.healthMu.Lock()
	runtime.onHealthy = handler
	runtime.healthMu.Unlock()
}

func (runtime *IngestRuntime) reportHealthy(result IngestBatchResult, err error) {
	if runtime == nil {
		return
	}
	runtime.healthMu.Lock()
	if result.Naked > 0 || (result.Fetched > 0 && err != nil) {
		runtime.requiresAcknowledgedRecovery = true
		runtime.historyRecoveryReady = false
		runtime.emptyHealthyNotified = false
		runtime.healthMu.Unlock()
		return
	}
	if err == nil && result.Acknowledged > 0 {
		runtime.requiresAcknowledgedRecovery = false
		runtime.historyRecoveryReady = false
		runtime.emptyHealthyNotified = false
		handler := runtime.onHealthy
		runtime.healthMu.Unlock()
		if handler != nil {
			handler()
		}
		return
	}
	if !errors.Is(err, ErrNoIngestMessages) {
		runtime.historyRecoveryReady = false
		runtime.healthMu.Unlock()
		return
	}
	if runtime.requiresAcknowledgedRecovery && !runtime.historyRecoveryReady {
		runtime.healthMu.Unlock()
		return
	}
	runtime.requiresAcknowledgedRecovery = false
	runtime.historyRecoveryReady = false
	if runtime.emptyHealthyNotified {
		runtime.healthMu.Unlock()
		return
	}
	runtime.emptyHealthyNotified = true
	handler := runtime.onHealthy
	runtime.healthMu.Unlock()
	if handler != nil {
		handler()
	}
}

func (runtime *IngestRuntime) RunOnce(ctx context.Context) (IngestBatchResult, error) {
	if runtime == nil || ctx == nil {
		return IngestBatchResult{}, ErrInvalidConfiguration
	}
	if _, err := runtime.RunScheduledHistoryRecovery(ctx); err != nil {
		return IngestBatchResult{}, err
	}
	deliveries, err := runtime.consumer.Fetch(ctx)
	if err != nil {
		return IngestBatchResult{}, err
	}
	result, processErr := runtime.processor.Process(ctx, deliveries)
	if processErr != nil {
		runtime.logger.Error("analytics ingest batch settlement failed",
			"fetched", result.Fetched, "acknowledged", result.Acknowledged,
			"naked", result.Naked, "terminated", result.Terminated)
	}
	return result, processErr
}

func (runtime *IngestRuntime) RunScheduledHistoryRecovery(ctx context.Context) (bool, error) {
	if runtime == nil || ctx == nil || runtime.history == nil || runtime.brokerHistorySnapshot == nil ||
		ValidateIngestHistoryGenerationV1(runtime.historyGeneration) != nil {
		return false, ErrInvalidConfiguration
	}
	runtime.healthMu.Lock()
	runtime.historyRecoveryReady = false
	runtime.healthMu.Unlock()
	recoveryCtx := ctx
	cancel := func() {}
	if runtime.operationTimeout > 0 {
		recoveryCtx, cancel = context.WithTimeout(ctx, runtime.operationTimeout)
	}
	defer cancel()
	if err := recoveryCtx.Err(); err != nil {
		return false, err
	}
	claim, ok, err := runtime.history.ClaimScheduledRecovery(recoveryCtx, runtime.historyGeneration)
	if contextErr := recoveryCtx.Err(); contextErr != nil {
		return false, contextErr
	}
	if err != nil || !ok {
		return false, err
	}
	snapshot, err := runtime.brokerHistorySnapshot(recoveryCtx)
	if contextErr := recoveryCtx.Err(); contextErr != nil {
		return false, contextErr
	}
	if err != nil {
		return false, err
	}
	_, err = runtime.history.ReconcileBroker(recoveryCtx, claim, snapshot)
	if contextErr := recoveryCtx.Err(); contextErr != nil {
		return false, contextErr
	}
	if err != nil {
		return false, err
	}
	err = runtime.history.CompleteScheduledRecovery(recoveryCtx, claim)
	if contextErr := recoveryCtx.Err(); contextErr != nil {
		return false, contextErr
	}
	if err != nil {
		return false, err
	}
	runtime.healthMu.Lock()
	runtime.historyRecoveryReady = true
	runtime.emptyHealthyNotified = false
	runtime.healthMu.Unlock()
	return true, nil
}

func (runtime *IngestRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	return runtime.consumer.Close()
}
