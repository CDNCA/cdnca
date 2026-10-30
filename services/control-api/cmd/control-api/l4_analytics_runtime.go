package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/l4analytics"
	"github.com/nats-io/nats.go"
)

// l4AnalyticsRuntime consumes the dedicated L4 stream and writes only finalized
// facts to ClickHouse. It deliberately does not share the ordinary analytics
// consumer because the two streams have different protobuf contracts.
type l4AnalyticsRuntime struct {
	connection *nats.Conn
	ingestor   *l4analytics.NATSIngestor
	closeOnce  bool
}

func openL4AnalyticsRuntime(
	ctx context.Context,
	cfg config.Config,
	connect natsConnector,
	httpClient l4analytics.HTTPDoer,
) (*l4AnalyticsRuntime, error) {
	if !cfg.AnalyticsIngest.Enabled {
		return nil, nil
	}
	if ctx == nil || ctx.Err() != nil || connect == nil || cfg.AnalyticsIngest.NATSURL == "" {
		return nil, errors.New("L4 analytics runtime dependencies are required")
	}
	drainTimeout := cfg.AnalyticsIngest.JetStream.OperationTimeout
	if drainTimeout <= 0 {
		drainTimeout = 5 * time.Second
	}
	if cfg.ShutdownPeriod > 0 && cfg.ShutdownPeriod/2 < drainTimeout {
		drainTimeout = cfg.ShutdownPeriod / 2
	}
	connection, err := connect(cfg.AnalyticsIngest.NATSURL, l4AnalyticsNATSOptions(cfg, drainTimeout)...)
	if err != nil || connection == nil || connection.IsClosed() {
		if connection != nil {
			connection.Close()
		}
		return nil, runtimeStageError{stage: "connect L4 analytics NATS", err: err}
	}
	failed := true
	defer func() {
		if failed {
			connection.Close()
		}
	}()
	timeout := cfg.AnalyticsIngest.ConnectTimeout
	if timeout <= 0 || (cfg.AnalyticsQueryTimeout > 0 && cfg.AnalyticsQueryTimeout < timeout) {
		timeout = cfg.AnalyticsQueryTimeout
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	source, err := l4analytics.NewClickHouseSource(l4analytics.ClickHouseConfig{
		Endpoint: cfg.AnalyticsIngest.ClickHouseURL, Database: cfg.AnalyticsIngest.ClickHouseDatabase,
		Username: cfg.AnalyticsIngest.ClickHouseUsername, Password: cfg.AnalyticsIngest.ClickHousePassword,
		QueryTimeout: timeout, HTTPClient: httpClient,
	})
	if err != nil {
		return nil, runtimeStageError{stage: "configure L4 analytics ClickHouse writer", err: err}
	}
	config := l4analytics.DefaultNATSIngestConfig()
	setupCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	if err := l4analytics.EnsureL4JetStream(setupCtx, connection, config); err != nil {
		cancel()
		return nil, runtimeStageError{stage: "verify L4 analytics JetStream resources", err: err}
	}
	cancel()
	// Session logs are written when l4_session_logs_v1 exists (ClickHouse
	// migration 017); facts are written either way.
	writerCtx, cancelWriter := context.WithTimeout(ctx, config.OperationTimeout)
	writer, err := l4analytics.NewClickHouseFactWriterWithSessionLogs(writerCtx, source)
	cancelWriter()
	if err != nil {
		return nil, runtimeStageError{stage: "configure L4 analytics fact writer", err: err}
	}
	ingestor, err := l4analytics.NewNATSIngestor(connection, writer, config)
	if err != nil {
		return nil, runtimeStageError{stage: "build L4 analytics ingest runtime", err: err}
	}
	runtime := &l4AnalyticsRuntime{connection: connection, ingestor: ingestor}
	failed = false
	return runtime, nil
}

func l4AnalyticsNATSOptions(cfg config.Config, drainTimeout time.Duration) []nats.Option {
	options := []nats.Option{
		nats.Name("cdnca-control-api-l4-analytics"),
		nats.Timeout(cfg.AnalyticsIngest.ConnectTimeout),
		nats.ReconnectWait(cfg.AnalyticsIngest.SupervisorBackoffMin),
		nats.MaxReconnects(-1),
		nats.DrainTimeout(drainTimeout),
		nats.NoCallbacksAfterClientClose(),
	}
	if strings.HasPrefix(cfg.AnalyticsIngest.NATSURL, "tls://") {
		options = append(options, nats.TLSHandshakeFirst())
		if caFile := strings.TrimSpace(os.Getenv("SSL_CERT_FILE")); caFile != "" {
			if _, err := os.Stat(caFile); err == nil {
				options = append(options, nats.RootCAs(caFile))
			}
		}
	}
	if cfg.AnalyticsIngest.NATSUsername != "" {
		options = append(options, nats.UserInfo(cfg.AnalyticsIngest.NATSUsername, cfg.AnalyticsIngest.NATSPassword))
	}
	return options
}

func (runtime *l4AnalyticsRuntime) Ready() error {
	if runtime == nil || runtime.connection == nil || runtime.ingestor == nil || runtime.connection.IsClosed() {
		return errors.New("L4 analytics runtime is unavailable")
	}
	return nil
}

func (runtime *l4AnalyticsRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.ingestor == nil || ctx == nil {
		return errors.New("L4 analytics runtime is not configured")
	}
	for {
		err := runtime.ingestor.Run(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			return errors.New("L4 analytics ingest stopped unexpectedly")
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (runtime *l4AnalyticsRuntime) Close() error {
	if runtime == nil || runtime.closeOnce {
		return nil
	}
	runtime.closeOnce = true
	var closeErr error
	if runtime.ingestor != nil {
		closeErr = runtime.ingestor.Close()
	}
	if runtime.connection != nil && !runtime.connection.IsClosed() {
		if err := runtime.connection.Drain(); err != nil {
			closeErr = errors.Join(closeErr, err)
			runtime.connection.Close()
		}
	}
	return closeErr
}

var _ readinessProbe = (*l4AnalyticsRuntime)(nil)
var _ runtimeWorker = (*l4AnalyticsRuntime)(nil)
