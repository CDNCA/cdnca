package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/nats-io/nats.go"
)

type analyticsConnectionsProcessRuntime struct {
	core       *analyticsconnections.Runtime
	connection *nats.Conn
}

const (
	analyticsConnectionsDeadLetterStream  = "CONNECTIONS_DEAD_V1"
	analyticsConnectionsDeadLetterSubject = "cdnca.connections.dead.v1"
)

type analyticsConnectionsJetStream interface {
	StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error)
	AddStream(*nats.StreamConfig, ...nats.JSOpt) (*nats.StreamInfo, error)
	ConsumerInfo(string, string, ...nats.JSOpt) (*nats.ConsumerInfo, error)
	AddConsumer(string, *nats.ConsumerConfig, ...nats.JSOpt) (*nats.ConsumerInfo, error)
}

func openAnalyticsConnectionsRuntime(
	ctx context.Context,
	cfg config.Config,
	connect natsConnector,
) (*analyticsConnectionsProcessRuntime, error) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("ANALYTICS_CONNECTIONS_RUNTIME_ENABLED")), "true") {
		return nil, nil
	}
	if ctx == nil || connect == nil {
		return nil, errors.New("analytics connections runtime dependencies are required")
	}
	if !cfg.AnalyticsIngest.Enabled || cfg.AnalyticsIngest.ClickHouseURL == "" || cfg.AnalyticsIngest.ClickHouseDatabase == "" ||
		cfg.AnalyticsIngest.ClickHouseUsername == "" || cfg.AnalyticsIngest.ClickHousePassword == "" {
		return nil, errors.New("analytics connections ingest writer configuration is required")
	}
	runtimeConfig := analyticsConnectionsRuntimeConfig(cfg)
	if err := analyticsconnections.ValidateRuntimeConfig(runtimeConfig); err != nil {
		return nil, err
	}
	options, err := analyticsConnectionsNATSOptions(runtimeConfig)
	if err != nil {
		return nil, err
	}
	connection, err := connect(runtimeConfig.NATSURL, options...)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			connection.Close()
		}
	}()
	if err := ensureAnalyticsConnectionsJetStream(ctx, connection, runtimeConfig); err != nil {
		return nil, err
	}
	subscriber, err := analyticsconnections.NewNATSSubscriber(connection, runtimeConfig)
	if err != nil {
		return nil, err
	}
	writer, err := analyticsconnections.NewClickHouseWriter(analyticsconnections.ClickHouseConfig{
		Endpoint: runtimeConfig.Endpoint, Database: runtimeConfig.Database,
		Username: runtimeConfig.Username, Password: runtimeConfig.Password,
		ConnectTimeout: runtimeConfig.ConnectTimeout, OperationTimeout: runtimeConfig.OperationTimeout,
		MaxResponseBytes: runtimeConfig.MaxResponseBytes,
	}, nil)
	if err != nil {
		_ = subscriber.Close()
		return nil, err
	}
	core, err := analyticsconnections.NewRuntime(runtimeConfig, subscriber, writer)
	if err != nil {
		_ = subscriber.Close()
		return nil, err
	}
	failed = false
	return &analyticsConnectionsProcessRuntime{core: core, connection: connection}, nil
}

func analyticsConnectionsNATSOptions(config analyticsconnections.RuntimeConfig) ([]nats.Option, error) {
	username := strings.TrimSpace(os.Getenv("ANALYTICS_CONNECTIONS_NATS_USER"))
	password := strings.TrimSpace(os.Getenv("ANALYTICS_CONNECTIONS_NATS_PASSWORD"))
	if (username == "") != (password == "") {
		return nil, errors.New("analytics connections NATS credentials must be configured together")
	}

	options := []nats.Option{
		nats.Name("cdnca-control-api-analytics-connections"),
		nats.Timeout(config.ConnectTimeout), nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second), nats.NoCallbacksAfterClientClose(),
	}
	if strings.HasPrefix(strings.ToLower(config.NATSURL), "tls://") {
		options = append(options, nats.TLSHandshakeFirst())
		if caFile := strings.TrimSpace(os.Getenv("SSL_CERT_FILE")); caFile != "" {
			if _, err := os.Stat(caFile); err != nil {
				return nil, errors.New("analytics connections NATS root CA is unavailable")
			}
			options = append(options, nats.RootCAs(caFile))
		}
	}
	if username != "" {
		options = append(options, nats.UserInfo(username, password))
	}
	return options, nil
}

func ensureAnalyticsConnectionsJetStream(ctx context.Context, connection *nats.Conn, config analyticsconnections.RuntimeConfig) error {
	if ctx == nil || connection == nil || connection.IsClosed() || config.OperationTimeout <= 0 {
		return errors.New("analytics connections JetStream unavailable")
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return errors.New("analytics connections JetStream unavailable")
	}
	return ensureAnalyticsConnectionsJetStreamObjects(ctx, jetstream, config)
}

func ensureAnalyticsConnectionsJetStreamObjects(
	ctx context.Context,
	jetstream analyticsConnectionsJetStream,
	config analyticsconnections.RuntimeConfig,
) error {
	if ctx == nil || jetstream == nil || config.OperationTimeout <= 0 || config.Stream == "" || config.Durable == "" ||
		config.Subject != analyticsconnections.ConnectionsSubject {
		return errors.New("analytics connections JetStream unavailable")
	}
	for _, expected := range []nats.StreamConfig{
		analyticsConnectionsSourceStreamConfig(config), analyticsConnectionsDeadLetterStreamConfig(),
	} {
		operationCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
		info, err := jetstream.StreamInfo(expected.Name, nats.Context(operationCtx))
		if errors.Is(err, nats.ErrStreamNotFound) {
			info, err = jetstream.AddStream(&expected, nats.Context(operationCtx))
		}
		cancel()
		if err != nil || validateAnalyticsConnectionsStream(info, expected) != nil {
			return errors.New("analytics connections JetStream unavailable")
		}
	}

	expected := analyticsConnectionsConsumerConfig(config)
	operationCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	info, err := jetstream.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	if errors.Is(err, nats.ErrConsumerNotFound) {
		info, err = jetstream.AddConsumer(config.Stream, &expected, nats.Context(operationCtx))
	}
	cancel()
	if err != nil || validateAnalyticsConnectionsConsumer(info, config.Stream, expected) != nil {
		return errors.New("analytics connections JetStream unavailable")
	}
	return nil
}

func analyticsConnectionsSourceStreamConfig(config analyticsconnections.RuntimeConfig) nats.StreamConfig {
	return nats.StreamConfig{
		Name: config.Stream, Subjects: []string{config.Subject}, Retention: nats.WorkQueuePolicy,
		MaxConsumers: 1, MaxMsgs: 1_000_000, MaxBytes: 2 << 30, Discard: nats.DiscardNew,
		DiscardNewPerSubject: true, MaxAge: 0, MaxMsgsPerSubject: 1, MaxMsgSize: 64 << 10,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}
}

func analyticsConnectionsDeadLetterStreamConfig() nats.StreamConfig {
	return nats.StreamConfig{
		Name: analyticsConnectionsDeadLetterStream, Subjects: []string{analyticsConnectionsDeadLetterSubject},
		Retention: nats.LimitsPolicy, MaxConsumers: -1, MaxMsgs: 1_000_000, MaxBytes: 1 << 30,
		Discard: nats.DiscardNew, MaxAge: 30 * 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: 8 << 10,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 24 * time.Hour,
	}
}

func analyticsConnectionsConsumerConfig(config analyticsconnections.RuntimeConfig) nats.ConsumerConfig {
	return nats.ConsumerConfig{
		Durable: config.Durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: 30 * time.Second, MaxDeliver: 8,
		BackOff: []time.Duration{
			30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute,
			10 * time.Minute, 15 * time.Minute, 30 * time.Minute,
		},
		FilterSubject: config.Subject, ReplayPolicy: nats.ReplayInstantPolicy,
		MaxWaiting: 16, MaxAckPending: 256, MaxRequestBatch: 1,
		MaxRequestExpires: config.OperationTimeout, MaxRequestMaxBytes: 64 << 10,
	}
}

func validateAnalyticsConnectionsStream(info *nats.StreamInfo, expected nats.StreamConfig) error {
	if info == nil {
		return errors.New("invalid analytics connections stream")
	}
	actual := info.Config
	actual.Description, expected.Description = "", ""
	actual.Metadata, expected.Metadata = nil, nil
	actual.Template, expected.Template = "", ""
	if !reflect.DeepEqual(actual, expected) {
		return errors.New("invalid analytics connections stream")
	}
	return nil
}

func validateAnalyticsConnectionsConsumer(info *nats.ConsumerInfo, stream string, expected nats.ConsumerConfig) error {
	if info == nil || info.Stream != stream || info.Name != expected.Durable {
		return errors.New("invalid analytics connections consumer")
	}
	actual := info.Config
	actual.Name, expected.Name = "", ""
	actual.Description, expected.Description = "", ""
	actual.Metadata, expected.Metadata = nil, nil
	if !reflect.DeepEqual(actual, expected) {
		return errors.New("invalid analytics connections consumer")
	}
	return nil
}

func analyticsConnectionsRuntimeConfig(cfg config.Config) analyticsconnections.RuntimeConfig {
	operationTimeout := durationFromEnv("ANALYTICS_CONNECTIONS_OPERATION_TIMEOUT", 5*time.Second)
	connectTimeout := durationFromEnv("ANALYTICS_CONNECTIONS_CONNECT_TIMEOUT", 3*time.Second)
	return analyticsconnections.RuntimeConfig{
		Enabled:  true,
		NATSURL:  strings.TrimSpace(os.Getenv("ANALYTICS_CONNECTIONS_NATS_URL")),
		Stream:   analyticsConnectionsEnvOr("ANALYTICS_CONNECTIONS_STREAM", "CONNECTIONS_INGEST_V1"),
		Durable:  analyticsConnectionsEnvOr("ANALYTICS_CONNECTIONS_DURABLE", "control_api_connections"),
		Subject:  analyticsConnectionsEnvOr("ANALYTICS_CONNECTIONS_SUBJECT", analyticsconnections.ConnectionsSubject),
		Endpoint: cfg.AnalyticsIngest.ClickHouseURL, Database: cfg.AnalyticsIngest.ClickHouseDatabase,
		Username: cfg.AnalyticsIngest.ClickHouseUsername, Password: cfg.AnalyticsIngest.ClickHousePassword,
		ConnectTimeout: connectTimeout, OperationTimeout: operationTimeout,
		MaxResponseBytes: 1 << 20,
	}
}

func (runtime *analyticsConnectionsProcessRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.core == nil {
		return errors.New("analytics connections runtime is not configured")
	}
	return runtime.core.Run(ctx)
}

func (runtime *analyticsConnectionsProcessRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	if runtime.core != nil {
		_ = runtime.core.Close()
	}
	if runtime.connection != nil {
		runtime.connection.Drain()
		runtime.connection.Close()
	}
	return nil
}

func durationFromEnv(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return parsed
}

func analyticsConnectionsEnvOr(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}
