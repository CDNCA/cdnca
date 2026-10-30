package edgeoutbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

type Publisher struct {
	store    outboxStore
	messages messagePublisher
	config   Config
}

func New(pool *pgxpool.Pool, connection *nats.Conn, config Config) (*Publisher, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: PostgreSQL pool is required", ErrInvalidConfig)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	messages, err := newNATSPublisher(connection, config.OperationTimeout)
	if err != nil {
		return nil, err
	}
	return newPublisher(&postgresStore{pool: pool}, messages, config)
}

func newPublisher(store outboxStore, messages messagePublisher, config Config) (*Publisher, error) {
	if store == nil || messages == nil {
		return nil, fmt.Errorf("%w: store and message publisher are required", ErrInvalidConfig)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Publisher{store: store, messages: messages, config: config}, nil
}

func (p *Publisher) PublishBatch(ctx context.Context) (BatchResult, error) {
	if ctx == nil {
		return BatchResult{}, fmt.Errorf("publish context is required")
	}
	claimContext, cancel := context.WithTimeout(ctx, p.config.OperationTimeout)
	commands, err := p.store.claim(claimContext, p.config.BatchSize, p.config.LeaseTimeout)
	cancel()
	if err != nil {
		return BatchResult{}, err
	}
	result := BatchResult{Claimed: len(commands)}
	for _, command := range commands {
		if ctx.Err() != nil {
			failed := failure{class: "publish", code: "context_canceled", retryable: true}
			if err := p.failClaim(command, failed); err != nil {
				return result, err
			}
			result.RetryableFailures++
			continue
		}
		if command.superseded {
			finalizeContext, finalizeCancel := context.WithTimeout(context.Background(), p.config.OperationTimeout)
			err := p.store.markSuperseded(finalizeContext, command.outboxID, command.claimToken)
			finalizeCancel()
			if err != nil {
				return result, err
			}
			result.Superseded++
			continue
		}
		messageID, failed := validateClaim(command, p.config.MaxPayloadBytes)
		if failed.code != "" {
			if err := p.failClaim(command, failed); err != nil {
				return result, err
			}
			result.PermanentFailures++
			continue
		}
		publishContext, cancel := context.WithTimeout(ctx, p.config.OperationTimeout)
		acknowledgement, publishErr := p.messages.publish(
			publishContext, command.subject, command.payload, messageID, p.config.Stream,
		)
		cancel()
		if publishErr != nil {
			failed = classifyPublishError(publishErr, ctx)
			if err := p.failClaim(command, failed); err != nil {
				return result, err
			}
			if failed.retryable {
				result.RetryableFailures++
			} else {
				result.PermanentFailures++
			}
			continue
		}
		if acknowledgement.stream != p.config.Stream {
			failed = failure{class: "configuration", code: "puback_stream_mismatch", retryable: false}
			if err := p.failClaim(command, failed); err != nil {
				return result, err
			}
			result.PermanentFailures++
			continue
		}
		finalizeContext, finalizeCancel := context.WithTimeout(context.Background(), p.config.OperationTimeout)
		err = p.store.markPublished(finalizeContext, command.outboxID, command.claimToken)
		finalizeCancel()
		if err != nil {
			return result, err
		}
		result.Published++
		if acknowledgement.duplicate {
			result.Duplicates++
		}
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}

func (p *Publisher) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("publisher context is required")
	}
	backoff := p.config.BaseBackoff
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		result, err := p.PublishBatch(ctx)
		delay := p.config.PollInterval
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !retryableStoreError(err) {
				return err
			}
			// Keep durable claims for lease recovery; never manufacture a new message ID.
			delay = backoff
			backoff = retryDelay(backoff, p.config.MaxBackoff, 2)
		} else {
			backoff = p.config.BaseBackoff
			if result.Claimed > 0 {
				continue
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func retryableStoreError(err error) bool {
	switch cause := err.(type) {
	case *pgconn.PgError:
		switch cause.Code {
		case "57P01", "57P02", "57P03", "08003", "08006":
			return true
		}
		return false
	case *pgconn.ParseConfigError:
		return false
	case interface{ Unwrap() []error }:
		// pgx joins connection attempts: a transient address must not hide bad credentials.
		causes := cause.Unwrap()
		for _, joined := range causes {
			if !retryableStoreError(joined) {
				return false
			}
		}
		return len(causes) > 0
	case interface{ Unwrap() error }:
		return retryableStoreError(cause.Unwrap())
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func (p *Publisher) failClaim(command claimedCommand, failed failure) error {
	backoff := retryDelay(p.config.BaseBackoff, p.config.MaxBackoff, command.publishAttempts)
	finalizeContext, cancel := context.WithTimeout(context.Background(), p.config.OperationTimeout)
	defer cancel()
	return p.store.markFailed(
		finalizeContext, command.outboxID, command.claimToken,
		failed, backoff, p.config.MaxErrorBytes,
	)
}

func classifyPublishError(err error, parent context.Context) failure {
	if parent.Err() != nil || errors.Is(err, context.Canceled) {
		return failure{class: "publish", code: "context_canceled", retryable: true}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
		return failure{class: "publish", code: "timeout", retryable: true}
	}
	var apiError *nats.APIError
	if errors.As(err, &apiError) && apiError.Code >= 400 && apiError.Code < 500 {
		return failure{class: "configuration", code: "publish_rejected", retryable: false}
	}
	return failure{class: "publish", code: "unavailable", retryable: true}
}
