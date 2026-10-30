package securityanalytics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	"github.com/nats-io/nats.go"
)

// ReportConsumer is the durable control-api consumer of the report stream
// (agent-gateway owns the stream, contract section 1).
const ReportConsumer = "control_api_autodefense_reports"

type reportIngest interface {
	Ingest(ctx context.Context, subjectNode string, encoded []byte) (string, error)
}

// NATSConsumer pulls reports and ingests them one batch at a time.
type NATSConsumer struct {
	subscription *nats.Subscription
	ingest       reportIngest
	logger       *slog.Logger
	batch        int
	fetchTimeout time.Duration
	opTimeout    time.Duration
}

// NewNATSConsumer binds (creating when absent) the durable consumer. The
// stream must already exist (agent-gateway creates it).
func NewNATSConsumer(connection *nats.Conn, ingest reportIngest, logger *slog.Logger) (*NATSConsumer, error) {
	if connection == nil || connection.IsClosed() || ingest == nil {
		return nil, ErrInvalidConfig
	}
	if logger == nil {
		logger = slog.Default()
	}
	js, err := connection.JetStream(nats.MaxWait(5 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("autodefense report JetStream: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config := &nats.ConsumerConfig{Durable: ReportConsumer, FilterSubject: contract.ReportSubjectPrefix + ".*",
		DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy, AckWait: time.Minute, MaxDeliver: -1,
		ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: 256}
	if _, err := js.AddConsumer(contract.ReportStream, config, nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrConsumerNameAlreadyInUse) {
		info, infoErr := js.ConsumerInfo(contract.ReportStream, ReportConsumer, nats.Context(ctx))
		if infoErr != nil || info.Config.FilterSubject != config.FilterSubject || info.Config.AckPolicy != nats.AckExplicitPolicy {
			return nil, fmt.Errorf("autodefense report consumer: %w", err)
		}
	}
	subscription, err := js.PullSubscribe(config.FilterSubject, ReportConsumer, nats.Bind(contract.ReportStream, ReportConsumer))
	if err != nil {
		return nil, fmt.Errorf("bind autodefense report consumer: %w", err)
	}
	return &NATSConsumer{subscription: subscription, ingest: ingest, logger: logger, batch: 64,
		fetchTimeout: 5 * time.Second, opTimeout: 10 * time.Second}, nil
}

// RunOnce ingests one batch and returns how many messages it settled.
// Invalid or foreign reports are terminated; storage errors are redelivered.
func (consumer *NATSConsumer) RunOnce(ctx context.Context) (int, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, consumer.fetchTimeout)
	messages, err := consumer.subscription.Fetch(consumer.batch, nats.Context(fetchCtx))
	cancel()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
			return 0, nil
		}
		return 0, err
	}
	for _, message := range messages {
		node := strings.TrimPrefix(message.Subject, contract.ReportSubjectPrefix+".")
		opCtx, cancel := context.WithTimeout(ctx, consumer.opTimeout)
		_, err := consumer.ingest.Ingest(opCtx, node, message.Data)
		cancel()
		switch {
		case errors.Is(err, ErrInvalidReport):
			consumer.logger.Warn("autodefense report rejected", "node_id", node)
			_ = message.Term()
		case err != nil:
			consumer.logger.Warn("autodefense report ingest failed", "node_id", node, "error", err)
			_ = message.NakWithDelay(5 * time.Second)
		default:
			_ = message.Ack()
		}
	}
	return len(messages), nil
}

// Run ingests until ctx ends and prunes receipts hourly when prune is set.
func (consumer *NATSConsumer) Run(ctx context.Context, prune func(context.Context) (int64, error)) error {
	pruneAt := time.Now()
	for ctx.Err() == nil {
		if _, err := consumer.RunOnce(ctx); err != nil && ctx.Err() == nil {
			consumer.logger.Warn("autodefense report fetch failed", "error", err)
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
		if prune != nil && time.Since(pruneAt) >= time.Hour {
			pruneAt = time.Now()
			if _, err := prune(ctx); err != nil {
				consumer.logger.Warn("autodefense receipt prune failed", "error", err)
			}
		}
	}
	return ctx.Err()
}

func (consumer *NATSConsumer) Close() error {
	if consumer == nil || consumer.subscription == nil {
		return nil
	}
	return consumer.subscription.Unsubscribe()
}
