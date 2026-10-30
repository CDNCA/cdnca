package pluginwebhook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

type SendResult struct {
	Success         bool
	Retryable       bool
	Code            string
	StatusCode      int
	RetryAfter      time.Duration
	RequestSHA256   string
	RequestBytes    int
	ResponseSHA256  string
	ResponseBytes   int
	ResponsePreview string
	ResponseHeaders map[string]string
}

type Deliverer interface {
	Deliver(context.Context, QueueItem, uint64) SendResult
}

type AttemptRecord struct {
	DeliveryID      uuid.UUID
	TenantID        string
	InstallationID  string
	EventID         string
	Attempt         uint64
	Code            string
	StatusCode      int
	Retryable       bool
	RequestSHA256   string
	RequestBytes    int
	ResponseSHA256  string
	ResponseBytes   int
	ResponsePreview string
	ResponseHeaders map[string]string
	RecordedAt      time.Time
}

type AttemptLogger interface {
	// Record must be idempotent for a delivery ID and attempt number.
	Record(context.Context, AttemptRecord) error
}

type WorkerConfig struct {
	MaxAttempts      uint64
	OperationTimeout time.Duration
	Retry            RetryPolicy
	Now              func() time.Time
	RandomInt63n     func(int64) int64
}

func DefaultWorkerConfig() WorkerConfig {
	return WorkerConfig{
		MaxAttempts: 5, OperationTimeout: 10 * time.Second,
		Retry: RetryPolicy{BaseDelay: time.Second, MaxDelay: 15 * time.Minute, RetryAfterMax: 5 * time.Minute},
		Now:   func() time.Time { return time.Now().UTC() }, RandomInt63n: rand.Int64N,
	}
}

type ProcessOutcome string

const (
	OutcomeDelivered      ProcessOutcome = "delivered"
	OutcomeRetryScheduled ProcessOutcome = "retry_scheduled"
	OutcomeDeadLettered   ProcessOutcome = "dead_lettered"
)

type ProcessResult struct {
	Outcome    ProcessOutcome
	DeliveryID uuid.UUID
	Attempt    uint64
	RetryDelay time.Duration
	ReasonCode string
}

type Worker struct {
	consumer    queueConsumer
	deliverer   Deliverer
	deadLetters deadLetterSink
	config      WorkerConfig
	logger      AttemptLogger
}

func NewWorker(
	connection *nats.Conn,
	jetstreamConfig JetStreamConfig,
	deliverer Deliverer,
	workerConfig WorkerConfig,
	logger AttemptLogger,
) (*Worker, error) {
	consumer, err := newNATSConsumer(connection, jetstreamConfig)
	if err != nil {
		return nil, err
	}
	if int(workerConfig.MaxAttempts) >= jetstreamConfig.ConsumerMaxDeliver {
		_ = consumer.Close()
		return nil, ErrInvalidConfig
	}
	deadLetters, err := NewDeadLetterStore(connection, jetstreamConfig)
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	worker, err := newWorker(consumer, deliverer, deadLetters, workerConfig, logger)
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	return worker, nil
}

func newWorker(consumer queueConsumer, deliverer Deliverer, deadLetters deadLetterSink, config WorkerConfig, logger AttemptLogger) (*Worker, error) {
	if consumer == nil || deliverer == nil || deadLetters == nil || logger == nil || !validWorkerConfig(config) {
		return nil, ErrInvalidConfig
	}
	return &Worker{consumer: consumer, deliverer: deliverer, deadLetters: deadLetters, config: config, logger: logger}, nil
}

func (worker *Worker) ProcessOne(ctx context.Context) (ProcessResult, error) {
	if worker == nil || ctx == nil {
		return ProcessResult{}, ErrInvalidConfig
	}
	delivery, err := worker.consumer.Next(ctx)
	if err != nil {
		return ProcessResult{}, err
	}
	var item QueueItem
	if json.Unmarshal(delivery.Data(), &item) != nil || validateQueueItem(item) != nil {
		digest := sha256.Sum256(delivery.Data())
		record := DeadLetterRecord{
			Schema:       DeadLetterSchemaV1,
			DeadLetterID: uuid.NewHash(sha256.New(), deliveryNamespace, []byte(fmt.Sprintf("invalid\x00%d\x00%x", delivery.StreamSequence(), digest)), 5),
			RawSHA256:    hex.EncodeToString(digest[:]), RawBytes: len(delivery.Data()), Attempts: delivery.Attempts(),
			SourceSequence: delivery.StreamSequence(), ReasonCode: "invalid_message", FailedAt: worker.config.Now().UTC(),
		}
		return worker.deadLetterAndAck(ctx, delivery, record)
	}
	if delivery.Attempts() > worker.config.MaxAttempts {
		record := DeadLetterRecord{
			Schema: DeadLetterSchemaV1, DeadLetterID: item.DeliveryID, Item: &item,
			Attempts: delivery.Attempts(), SourceSequence: delivery.StreamSequence(),
			ReasonCode: "attempts_exhausted_after_recovery", FailedAt: worker.config.Now().UTC(),
		}
		return worker.deadLetterAndAck(ctx, delivery, record)
	}
	result := worker.deliverer.Deliver(ctx, item, delivery.Attempts())
	result = sanitizeSendResult(result)
	if !validSendResult(result) {
		result = SendResult{Code: "sender_contract_invalid"}
	}
	processResult := ProcessResult{DeliveryID: item.DeliveryID, Attempt: delivery.Attempts(), ReasonCode: result.Code}
	if err := worker.recordAttempt(ctx, item, delivery.Attempts(), result); err != nil {
		return processResult, err
	}
	if result.Success {
		if err := worker.ack(ctx, delivery); err != nil {
			return processResult, err
		}
		processResult.Outcome = OutcomeDelivered
		return processResult, nil
	}
	if result.Retryable && delivery.Attempts() < worker.config.MaxAttempts {
		delay := worker.config.Retry.delay(delivery.Attempts(), result.RetryAfter, worker.config.RandomInt63n)
		if delay <= 0 {
			return processResult, ErrInvalidConfig
		}
		operationCtx, cancel := context.WithTimeout(ctx, worker.config.OperationTimeout)
		err := delivery.Nak(operationCtx, delay)
		cancel()
		if err != nil {
			return processResult, err
		}
		processResult.Outcome = OutcomeRetryScheduled
		processResult.RetryDelay = delay
		return processResult, nil
	}
	record := DeadLetterRecord{
		Schema: DeadLetterSchemaV1, DeadLetterID: item.DeliveryID, Item: &item,
		Attempts: delivery.Attempts(), SourceSequence: delivery.StreamSequence(), ReasonCode: result.Code,
		StatusCode: result.StatusCode, RequestSHA256: result.RequestSHA256, RequestBytes: result.RequestBytes,
		ResponseSHA256: result.ResponseSHA256, ResponseBytes: result.ResponseBytes,
		ResponsePreview: result.ResponsePreview, ResponseHeaders: result.ResponseHeaders, FailedAt: worker.config.Now().UTC(),
	}
	return worker.deadLetterAndAck(ctx, delivery, record)
}

func (worker *Worker) Run(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrInvalidConfig
	}
	for {
		_, err := worker.ProcessOne(ctx)
		if err == nil || errors.Is(err, ErrNoDelivery) {
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

func (worker *Worker) Close() error {
	if worker == nil || worker.consumer == nil {
		return nil
	}
	return worker.consumer.Close()
}

func (worker *Worker) deadLetterAndAck(ctx context.Context, delivery queueDelivery, record DeadLetterRecord) (ProcessResult, error) {
	result := ProcessResult{Outcome: OutcomeDeadLettered, Attempt: delivery.Attempts(), ReasonCode: record.ReasonCode}
	if record.Item != nil {
		result.DeliveryID = record.Item.DeliveryID
	}
	operationCtx, cancel := context.WithTimeout(ctx, worker.config.OperationTimeout)
	err := worker.deadLetters.put(operationCtx, record)
	cancel()
	if err != nil {
		operationCtx, cancel = context.WithTimeout(ctx, worker.config.OperationTimeout)
		_ = delivery.Nak(operationCtx, worker.config.Retry.BaseDelay)
		cancel()
		return result, fmt.Errorf("persist plugin webhook dead letter: %w", err)
	}
	if err := worker.ack(ctx, delivery); err != nil {
		return result, err
	}
	return result, nil
}

func (worker *Worker) ack(ctx context.Context, delivery queueDelivery) error {
	operationCtx, cancel := context.WithTimeout(ctx, worker.config.OperationTimeout)
	defer cancel()
	return delivery.Ack(operationCtx)
}

func (worker *Worker) recordAttempt(ctx context.Context, item QueueItem, attempt uint64, result SendResult) error {
	operationCtx, cancel := context.WithTimeout(ctx, worker.config.OperationTimeout)
	defer cancel()
	err := worker.logger.Record(operationCtx, AttemptRecord{
		DeliveryID: item.DeliveryID, TenantID: item.Event.TenantID, InstallationID: item.Event.InstallationID,
		EventID: item.Event.ID, Attempt: attempt, Code: result.Code, StatusCode: result.StatusCode,
		Retryable: result.Retryable, RequestSHA256: result.RequestSHA256, RequestBytes: result.RequestBytes,
		ResponseSHA256: result.ResponseSHA256, ResponseBytes: result.ResponseBytes,
		ResponsePreview: truncateUTF8(result.ResponsePreview, 2048), ResponseHeaders: result.ResponseHeaders,
		RecordedAt: worker.config.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("persist plugin webhook delivery attempt: %w", err)
	}
	return nil
}

func validSendResult(result SendResult) bool {
	if !eventIDPattern.MatchString(result.Code) || result.StatusCode < 0 || result.StatusCode > 599 ||
		result.RequestBytes < 0 || result.ResponseBytes < 0 || !validOptionalSHA256(result.RequestSHA256) ||
		!validOptionalSHA256(result.ResponseSHA256) ||
		len(result.ResponsePreview) > 2048 || result.RetryAfter < 0 {
		return false
	}
	if result.Success {
		return !result.Retryable && result.StatusCode >= 200 && result.StatusCode <= 299
	}
	return true
}

func sanitizeSendResult(result SendResult) SendResult {
	result.ResponsePreview = sanitizePreview([]byte(result.ResponsePreview), "application/json", 2048)
	headers := make(http.Header, len(result.ResponseHeaders))
	for name, value := range result.ResponseHeaders {
		headers.Set(name, value)
	}
	result.ResponseHeaders = sanitizeHeaders(headers)
	return result
}

func validOptionalSHA256(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validWorkerConfig(config WorkerConfig) bool {
	return config.MaxAttempts > 0 && config.MaxAttempts <= 100 && config.OperationTimeout > 0 &&
		config.OperationTimeout <= time.Minute && config.Retry.BaseDelay > 0 &&
		config.Retry.MaxDelay >= config.Retry.BaseDelay && config.Retry.MaxDelay <= 24*time.Hour &&
		config.Retry.RetryAfterMax > 0 && config.Retry.RetryAfterMax <= config.Retry.MaxDelay &&
		config.Now != nil && config.RandomInt63n != nil
}
