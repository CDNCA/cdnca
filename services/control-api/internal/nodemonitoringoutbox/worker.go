package nodemonitoringoutbox

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type publishAck struct {
	stream    string
	sequence  uint64
	duplicate bool
}

type messagePublisher interface {
	Publish(context.Context, Command) (publishAck, error)
}

type commandStore interface {
	ClaimCommands(context.Context, uuid.UUID, int, time.Duration) ([]Command, error)
	MarkPublished(context.Context, Command, string, uint64) error
	ReleaseCommand(context.Context, Command, time.Time, string) error
	FailCommand(context.Context, Command, string) error
}

type Publisher struct {
	store    commandStore
	messages messagePublisher
	config   Config
}

func NewPublisher(pool *pgxpool.Pool, connection *nats.Conn, config Config) (*Publisher, error) {
	if pool == nil || connection == nil || connection.IsClosed() {
		return nil, ErrInvalidInput
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.WorkerID == uuid.Nil {
		config.WorkerID = uuid.New()
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create node monitoring JetStream context: %w", err)
	}
	return newPublisher(&Store{pool: pool, now: config.Clock}, &natsMessagePublisher{
		jetstream: js, operationTimeout: config.OperationTimeout, maxPayloadBytes: config.MaxPayloadBytes,
	}, config)
}

func newPublisher(store commandStore, messages messagePublisher, config Config) (*Publisher, error) {
	if store == nil || messages == nil {
		return nil, ErrInvalidInput
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Publisher{store: store, messages: messages, config: config}, nil
}

type BatchResult struct {
	Claimed           int
	Published         int
	Duplicates        int
	RetryableFailures int
	PermanentFailures int
}

func (publisher *Publisher) PublishBatch(ctx context.Context) (BatchResult, error) {
	if publisher == nil || ctx == nil {
		return BatchResult{}, ErrInvalidInput
	}
	claimContext, cancel := context.WithTimeout(ctx, publisher.config.OperationTimeout)
	commands, err := publisher.store.ClaimCommands(claimContext, publisher.config.WorkerID,
		publisher.config.BatchSize, publisher.config.ClaimLease)
	cancel()
	if err != nil {
		return BatchResult{}, err
	}
	result := BatchResult{Claimed: len(commands)}
	for _, command := range commands {
		if err := ctx.Err(); err != nil {
			permanent, settleErr := publisher.retryOrFail(command, "context_canceled")
			if settleErr != nil {
				return result, settleErr
			}
			if permanent {
				result.PermanentFailures++
			} else {
				result.RetryableFailures++
			}
			continue
		}
		if err := validateCommand(command, publisher.config.MaxPayloadBytes); err != nil {
			if settleErr := publisher.store.FailCommand(context.Background(), command, "invalid_payload"); settleErr != nil {
				return result, settleErr
			}
			result.PermanentFailures++
			continue
		}
		publishContext, publishCancel := context.WithTimeout(ctx, publisher.config.OperationTimeout)
		ack, publishErr := publisher.messages.Publish(publishContext, command)
		publishCancel()
		if publishErr != nil {
			permanent, settleErr := publisher.retryOrFail(command, classifyPublishError(publishErr, ctx))
			if settleErr != nil {
				return result, settleErr
			}
			if permanent {
				result.PermanentFailures++
			} else {
				result.RetryableFailures++
			}
			continue
		}
		if ack.stream != CommandStream || ack.sequence == 0 {
			if settleErr := publisher.store.FailCommand(context.Background(), command, "invalid_puback"); settleErr != nil {
				return result, settleErr
			}
			result.PermanentFailures++
			continue
		}
		finalizeContext, finalizeCancel := context.WithTimeout(context.Background(), publisher.config.OperationTimeout)
		markErr := publisher.store.MarkPublished(finalizeContext, command, ack.stream, ack.sequence)
		finalizeCancel()
		if markErr != nil {
			return result, markErr
		}
		result.Published++
		if ack.duplicate {
			result.Duplicates++
		}
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func (publisher *Publisher) Run(ctx context.Context) error {
	if publisher == nil || ctx == nil {
		return ErrInvalidInput
	}
	for {
		result, err := publisher.PublishBatch(ctx)
		if err != nil {
			return err
		}
		if result.Claimed > 0 {
			continue
		}
		timer := time.NewTimer(publisher.config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (publisher *Publisher) retryOrFail(command Command, errorCode string) (bool, error) {
	if command.AttemptCount >= publisher.config.MaxAttempts {
		return true, publisher.store.FailCommand(context.Background(), command, errorCode)
	}
	return false, publisher.store.ReleaseCommand(context.Background(), command,
		publisher.config.Clock().UTC().Add(retryDelay(publisher.config.RetryDelay, command.AttemptCount)), errorCode)
}

func retryDelay(base time.Duration, attempt int) time.Duration {
	if attempt < 1 {
		return base
	}
	shift := attempt - 1
	if shift > 6 {
		shift = 6
	}
	delay := base * time.Duration(1<<shift)
	if delay < base || delay > time.Minute {
		return time.Minute
	}
	return delay
}

func classifyPublishError(err error, parent context.Context) string {
	if parent != nil && parent.Err() != nil || errors.Is(err, context.Canceled) {
		return "context_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
		return "publish_timeout"
	}
	return "publish_unavailable"
}

func validateCommand(command Command, maxPayload int) error {
	if command.ID == uuid.Nil || command.NodeID == uuid.Nil || command.ConfigRevision == 0 ||
		command.Subject != CommandSubjectBase+"."+command.NodeID.String() ||
		command.MessageID != CommandMessagePrefix+command.ID.String() || len(command.Payload) == 0 ||
		len(command.Payload) > maxPayload || len(command.PayloadSHA256) != sha256.Size {
		return ErrInvalidInput
	}
	digest := sha256.Sum256(command.Payload)
	if !equalBytes(digest[:], command.PayloadSHA256) {
		return ErrInvalidInput
	}
	artifact := &agentv1.NodeMonitoringArtifact{}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(command.Payload, artifact); err != nil ||
		artifact.Event == nil || !canonicalUUID(artifact.Event.EventId) || !canonicalUUID(artifact.Event.RequestId) ||
		artifact.Event.OccurredTime == nil || artifact.Event.OccurredTime.CheckValid() != nil ||
		artifact.NodeId != command.NodeID.String() ||
		artifact.ConfigRevision != command.ConfigRevision || artifact.PublicationSequence != command.ConfigRevision ||
		artifact.Schema != agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1 || len(artifact.CanonicalConfigJson) == 0 ||
		len(artifact.CanonicalConfigJson) > maxPayload || len(artifact.ConfigSha256) != sha256.Size ||
		artifact.Event.EventId != command.ID.String() || proto.Size(artifact) > maxPayload {
		return ErrInvalidInput
	}
	var identity struct {
		SchemaVersion  string `json:"schema_version"`
		ConfigRevision uint64 `json:"config_revision"`
	}
	if json.Unmarshal(artifact.CanonicalConfigJson, &identity) != nil ||
		identity.SchemaVersion != "cdnca.node-monitoring/v1" || identity.ConfigRevision != artifact.ConfigRevision {
		return ErrInvalidInput
	}
	configDigest := sha256.Sum256(artifact.CanonicalConfigJson)
	if !equalBytes(configDigest[:], artifact.ConfigSha256) {
		return ErrInvalidInput
	}
	return nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var value byte
	for index := range left {
		value |= left[index] ^ right[index]
	}
	return value == 0
}

type natsMessagePublisher struct {
	jetstream        nats.JetStreamContext
	operationTimeout time.Duration
	maxPayloadBytes  int
}

func (publisher *natsMessagePublisher) Publish(ctx context.Context, command Command) (publishAck, error) {
	if publisher == nil || publisher.jetstream == nil || ctx == nil || len(command.Payload) > publisher.maxPayloadBytes {
		return publishAck{}, ErrInvalidInput
	}
	message := nats.NewMsg(command.Subject)
	message.Data = command.Payload
	message.Header.Set(nats.MsgIdHdr, command.MessageID)
	op, cancel := context.WithTimeout(ctx, publisher.operationTimeout)
	ack, err := publisher.jetstream.PublishMsg(message, nats.Context(op), nats.ExpectStream(CommandStream))
	cancel()
	if err != nil || ack == nil {
		if err == nil {
			err = errors.New("JetStream returned no publish acknowledgement")
		}
		return publishAck{}, err
	}
	return publishAck{stream: ack.Stream, sequence: ack.Sequence, duplicate: ack.Duplicate}, nil
}

var _ commandStore = (*Store)(nil)
var _ messagePublisher = (*natsMessagePublisher)(nil)
