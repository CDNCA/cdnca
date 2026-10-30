package edgestatus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

type Runtime struct {
	consumer  *NATSConsumer
	processor *Processor
	logger    *slog.Logger
}

func NewRuntime(pool *pgxpool.Pool, connection *nats.Conn, consumerConfig NATSConsumerConfig,
	validatorConfig ValidatorConfig, logger *slog.Logger,
) (*Runtime, error) {
	if pool == nil {
		return nil, fmt.Errorf("deployment status runtime requires a PostgreSQL pool")
	}
	if logger == nil {
		logger = slog.Default()
	}
	consumer, err := NewNATSConsumer(connection, consumerConfig)
	if err != nil {
		return nil, err
	}
	validator, err := NewValidator(validatorConfig)
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	store, err := NewStore(pool)
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	processor, err := NewProcessor(validator, store, consumerConfig.NakDelay, consumerConfig.OperationTimeout)
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	processor.SetLogger(logger)
	return &Runtime{consumer: consumer, processor: processor, logger: logger}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	for {
		delivery, err := r.consumer.Next(ctx)
		if errors.Is(err, ErrNoMessage) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		disposition, err := r.processor.Process(ctx, delivery)
		if err != nil && ctx.Err() == nil {
			r.logger.Error("deployment status disposition failed", "disposition", disposition, "error", err)
		}
	}
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	return r.consumer.Close()
}
