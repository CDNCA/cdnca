package nodepresence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

type RuntimeConfig struct {
	NATSURL              string
	RedisURL             string
	Stream               string
	SubjectPrefix        string
	Durable              string
	RedisKeyPrefix       string
	AckWait              time.Duration
	FetchTimeout         time.Duration
	OperationTimeout     time.Duration
	NakDelay             time.Duration
	LeaseTTL             time.Duration
	OfflineAfter         time.Duration
	OfflineInterval      time.Duration
	ConnectionTimeout    time.Duration
	MaxFutureSkew        time.Duration
	MaxHeartbeatBytes    int
	MaxActiveDeployments int
	MaxAckPending        int
	MaxWaiting           int
	OfflineBatchSize     int
}

type Runtime struct {
	connection *nats.Conn
	redis      *redis.Client
	leases     *RedisLeaseStore
	consumer   *NATSConsumer
	processor  *Processor
	offline    *OfflineWorker
	logger     *slog.Logger
	closeOnce  sync.Once
}

func OpenRuntime(ctx context.Context, pool *pgxpool.Pool, config RuntimeConfig, logger *slog.Logger) (*Runtime, error) {
	if pool == nil || config.NATSURL == "" || config.RedisURL == "" || config.LeaseTTL <= 0 ||
		config.OfflineAfter <= 0 || config.LeaseTTL > config.OfflineAfter || config.OfflineInterval <= 0 ||
		config.ConnectionTimeout <= 0 || config.AckWait <= 3*config.OperationTimeout {
		return nil, fmt.Errorf("invalid node presence runtime configuration")
	}
	if logger == nil {
		logger = slog.Default()
	}
	connection, err := nats.Connect(config.NATSURL,
		nats.Name("cdnca-control-api-node-presence"),
		nats.Timeout(config.ConnectionTimeout),
		nats.ReconnectWait(time.Second),
		nats.MaxReconnects(-1),
	)
	if err != nil {
		return nil, fmt.Errorf("connect node presence NATS: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			connection.Close()
		}
	}()
	redisOptions, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parse node presence Redis URL: %w", err)
	}
	redisOptions.DialTimeout = config.ConnectionTimeout
	redisOptions.ReadTimeout = config.OperationTimeout
	redisOptions.WriteTimeout = config.OperationTimeout
	redisOptions.ContextTimeoutEnabled = true
	redisClient := redis.NewClient(redisOptions)
	defer func() {
		if failed {
			_ = redisClient.Close()
		}
	}()
	operationCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	err = redisClient.Ping(operationCtx).Err()
	cancel()
	if err != nil {
		return nil, fmt.Errorf("ping node presence Redis: %w", err)
	}
	consumer, err := NewNATSConsumer(connection, NATSConsumerConfig{
		Stream: config.Stream, SubjectPrefix: config.SubjectPrefix, Durable: config.Durable,
		AckWait: config.AckWait, FetchTimeout: config.FetchTimeout,
		OperationTimeout: config.OperationTimeout, NakDelay: config.NakDelay,
		MaxAckPending: config.MaxAckPending, MaxWaiting: config.MaxWaiting,
	})
	if err != nil {
		return nil, err
	}
	validator, err := NewValidator(ValidatorConfig{
		SubjectPrefix: config.SubjectPrefix, MaxHeartbeatBytes: config.MaxHeartbeatBytes,
		MaxActiveDeployments: config.MaxActiveDeployments, MaxFutureSkew: config.MaxFutureSkew,
		MaxPastAge: config.OfflineAfter,
	})
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	store, err := NewStore(pool, config.LeaseTTL)
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	leases, err := NewRedisLeaseStore(redisClient, config.RedisKeyPrefix, config.OperationTimeout)
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	processor, err := NewProcessor(validator, store, leases, config.NakDelay, config.OperationTimeout)
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	offline, err := NewOfflineWorker(store, leases, config.OfflineAfter, config.OfflineInterval,
		config.OperationTimeout, config.OfflineBatchSize)
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	failed = false
	return &Runtime{
		connection: connection, redis: redisClient, consumer: consumer,
		leases: leases, processor: processor, offline: offline, logger: logger,
	}, nil
}

func (r *Runtime) LeaseReader() LeaseReader {
	if r == nil {
		return nil
	}
	return r.leases
}

func (r *Runtime) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- r.consume(runCtx) }()
	go func() {
		errorsChannel <- r.offline.Run(runCtx, func(err error) {
			r.logger.Error("node presence offline scan failed", "error", err)
		})
	}()
	first := <-errorsChannel
	cancel()
	second := <-errorsChannel
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if first != nil && !errors.Is(first, context.Canceled) {
		return first
	}
	if second != nil && !errors.Is(second, context.Canceled) {
		return second
	}
	return nil
}

func (r *Runtime) Close() error {
	var closeErr error
	r.closeOnce.Do(func() {
		if err := r.consumer.Close(); err != nil {
			closeErr = err
		}
		r.connection.Close()
		if err := r.redis.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

func (r *Runtime) consume(ctx context.Context) error {
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
			r.logger.Error("node presence heartbeat disposition failed", "disposition", disposition, "error", err)
		}
	}
}
