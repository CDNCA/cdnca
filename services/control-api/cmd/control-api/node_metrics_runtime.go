package main

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/ccautoswitch"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemetrics"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

type nodeMetricsRuntime struct {
	connection *nats.Conn
	consumer   *nodemetrics.NATSConsumer
	processor  *nodemetrics.Processor
	reader     *nodemetrics.PostgresReader
}

func openNodeMetricsRuntime(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
	connect natsConnector,
) (_ *nodeMetricsRuntime, returnedErr error) {
	if ctx == nil || ctx.Err() != nil || pool == nil || connect == nil {
		return nil, errors.New("node metrics runtime dependencies are required")
	}
	options := []nats.Option{
		nats.Name("cdnca-control-api-node-metrics"),
		nats.Timeout(cfg.EdgeDeploymentConnectTimeout),
		nats.ReconnectWait(time.Second),
		nats.DrainTimeout(cfg.ShutdownPeriod),
	}
	if cfg.EdgeDeploymentNATSCredsFile != "" {
		options = append(options,
			nats.UserCredentials(cfg.EdgeDeploymentNATSCredsFile),
			nats.RootCAs(cfg.EdgeDeploymentNATSCAFile),
		)
	}
	connection, err := connect(cfg.EdgeDeploymentNATSURL, options...)
	if err != nil {
		return nil, runtimeStageError{stage: "connect node metrics NATS", err: err}
	}
	failed := true
	defer func() {
		if failed {
			connection.Close()
		}
	}()
	consumerConfig := nodemetrics.DefaultNATSConsumerConfig()
	consumer, err := nodemetrics.NewNATSConsumer(connection, consumerConfig)
	if err != nil {
		return nil, runtimeStageError{stage: "bind node metrics consumer", err: err}
	}
	store, err := nodemetrics.NewPostgresStore(pool)
	if err != nil {
		return nil, runtimeStageError{stage: "configure node metrics store", err: err}
	}
	processor, err := nodemetrics.NewProcessor(
		nodemetrics.NewDecoder(nodemetrics.DefaultDecoderConfig()),
		store,
		consumerConfig.NakDelay,
		consumerConfig.OperationTimeout,
	)
	if err != nil {
		return nil, runtimeStageError{stage: "configure node metrics processor", err: err}
	}
	notifications, err := notification.NewStore(pool)
	if err != nil {
		return nil, runtimeStageError{stage: "configure CC auto switch notifications", err: err}
	}
	ccAutoSwitch, err := ccautoswitch.NewRecorder(pool, notifications)
	if err != nil {
		return nil, runtimeStageError{stage: "configure CC auto switch recorder", err: err}
	}
	processor.WithCCAutoSwitchRecorder(ccAutoSwitch)
	reader, err := nodemetrics.NewPostgresReader(pool)
	if err != nil {
		return nil, runtimeStageError{stage: "configure node metrics reader", err: err}
	}
	failed = false
	return &nodeMetricsRuntime{
		connection: connection,
		consumer:   consumer,
		processor:  processor,
		reader:     reader,
	}, nil
}

func (runtime *nodeMetricsRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.consumer == nil || runtime.processor == nil || ctx == nil {
		return errors.New("node metrics runtime is not configured")
	}
	for {
		delivery, err := runtime.consumer.Next(ctx)
		switch {
		case errors.Is(err, nodemetrics.ErrNoMessage):
			continue
		case err != nil:
			return err
		}
		if _, err := runtime.processor.Process(ctx, delivery); err != nil {
			return err
		}
	}
}

func (runtime *nodeMetricsRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	var result error
	if runtime.consumer != nil {
		result = runtime.consumer.Close()
	}
	if runtime.connection != nil {
		if err := runtime.connection.Drain(); err != nil {
			result = errors.Join(result, err)
		}
		runtime.connection.Close()
	}
	return result
}

func runRequiredNodeMetricsRuntime(ctx context.Context, runtime *nodeMetricsRuntime, failures chan<- error) {
	if runtime == nil {
		select {
		case failures <- errors.New("node metrics runtime stopped: required runtime is missing"):
		default:
		}
		return
	}
	err := runtime.Run(ctx)
	if ctx.Err() != nil {
		return
	}
	if err == nil || errors.Is(err, context.Canceled) {
		err = errors.New("required runtime stopped unexpectedly")
	}
	select {
	case failures <- runtimeStageError{stage: "node metrics runtime stopped", err: err}:
	default:
	}
}
