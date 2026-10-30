package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	analyticsIngestStateDisabled int32 = iota
	analyticsIngestStateStarting
	analyticsIngestStateRunning
	analyticsIngestStateDegraded
	analyticsIngestStateStopping
	analyticsIngestStateStopped
)

const (
	analyticsIngestDegradedNATS uint32 = 1 << iota
	analyticsIngestDegradedWorker
)

type analyticsIngestWorker interface {
	Run(context.Context) error
	Close() error
}

type analyticsIngestConnection interface {
	Drain() error
	Close()
	IsClosed() bool
	StatusChanged(...nats.Status) chan nats.Status
	RemoveStatusListener(chan nats.Status)
}

type analyticsIngestHealth struct {
	enabled  bool
	state    atomic.Int32
	degraded atomic.Uint32
	failures atomic.Uint64
}

type analyticsIngestHealthSnapshot struct {
	Enabled      bool   `json:"enabled"`
	State        string `json:"state"`
	RestartCount uint64 `json:"restart_count"`
}

type analyticsIngestProcessRuntime struct {
	worker          analyticsIngestWorker
	connection      analyticsIngestConnection
	closeHTTP       func()
	logger          *slog.Logger
	health          *analyticsIngestHealth
	backoffMin      time.Duration
	backoffMax      time.Duration
	shutdownTimeout time.Duration
	closeOnce       sync.Once
	closeErr        error
}

func openAnalyticsIngestRuntime(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
	logger *slog.Logger,
	connect natsConnector,
	httpClient analytics.HTTPClient,
) (_ *analyticsIngestProcessRuntime, returnedErr error) {
	if !cfg.AnalyticsIngest.Enabled {
		return nil, nil
	}
	if ctx == nil || pool == nil || connect == nil {
		return nil, errors.New("analytics ingest runtime dependencies are required")
	}
	if cfg.ControlInstallationID == "" {
		return nil, errors.New("analytics ingest control installation is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	jetstreamConfig := cfg.AnalyticsIngest.JetStream
	historyCtx, cancelHistory := context.WithTimeout(ctx, jetstreamConfig.OperationTimeout)
	history, generation, err := analytics.OpenPostgresIngestHistoryV1(historyCtx, pool, analytics.PostgresIngestHistoryConfig{
		InstallationID: cfg.ControlInstallationID,
		StreamName:     jetstreamConfig.Stream,
		DurableName:    jetstreamConfig.Durable,
		ClaimedBy:      "control-api-analytics-ingest-" + uuid.NewString(),
		RecoveryLease:  jetstreamConfig.OperationTimeout,
		Now:            time.Now,
	})
	cancelHistory()
	if err != nil {
		return nil, runtimeStageError{stage: "open analytics ingest history authority", err: err}
	}
	health := newAnalyticsIngestHealth(true)
	drainTimeout := min(jetstreamConfig.OperationTimeout, cfg.ShutdownPeriod/2)
	options := []nats.Option{
		nats.Name("cdnca-control-api-analytics-ingest"),
		nats.Timeout(cfg.AnalyticsIngest.ConnectTimeout),
		nats.ReconnectWait(cfg.AnalyticsIngest.SupervisorBackoffMin),
		nats.MaxReconnects(-1),
		nats.DrainTimeout(drainTimeout),
		nats.NoCallbacksAfterClientClose(),
		nats.DisconnectErrHandler(func(*nats.Conn, error) {
			if health.markDegraded(analyticsIngestDegradedNATS) {
				logger.Warn("analytics ingest NATS disconnected", "class", "dependency")
			}
		}),
		nats.ReconnectHandler(func(*nats.Conn) {
			if health.markRecovered(analyticsIngestDegradedNATS) {
				logger.Info("analytics ingest NATS reconnected")
			}
		}),
	}
	if strings.HasPrefix(cfg.AnalyticsIngest.NATSURL, "tls://") {
		// The local TLS proxy performs the handshake before NATS INFO; retain the
		// same ordering for any TLS endpoint that uses a directly terminated cert.
		options = append(options, nats.TLSHandshakeFirst())
		if caFile := strings.TrimSpace(os.Getenv("SSL_CERT_FILE")); caFile != "" {
			if _, statErr := os.Stat(caFile); statErr == nil {
				options = append(options, nats.RootCAs(caFile))
			}
		}
	}
	if cfg.AnalyticsIngest.NATSUsername != "" {
		options = append(options, nats.UserInfo(cfg.AnalyticsIngest.NATSUsername, cfg.AnalyticsIngest.NATSPassword))
	}
	connection, err := connect(cfg.AnalyticsIngest.NATSURL, options...)
	if err != nil {
		return nil, runtimeStageError{stage: "connect analytics ingest NATS", err: err}
	}
	failed := true
	defer func() {
		if failed {
			connection.Close()
		}
	}()

	if httpClient == nil {
		httpClient = newAnalyticsHTTPClient(cfg.AnalyticsIngest.ConnectTimeout, max(cfg.AnalyticsIngest.ConnectTimeout, cfg.AnalyticsIngest.WriteTimeout))
	}
	var closeHTTP func()
	if closer, ok := httpClient.(interface{ CloseIdleConnections() }); ok {
		closeHTTP = closer.CloseIdleConnections
		defer func() {
			if failed {
				closeHTTP()
			}
		}()
	}
	client, err := analytics.NewClient(analytics.Config{
		Endpoint: cfg.AnalyticsIngest.ClickHouseURL, Database: cfg.AnalyticsIngest.ClickHouseDatabase,
		Username: cfg.AnalyticsIngest.ClickHouseUsername, Password: cfg.AnalyticsIngest.ClickHousePassword,
		QueryTimeout: cfg.AnalyticsIngest.ConnectTimeout, WriteTimeout: cfg.AnalyticsIngest.WriteTimeout,
		MaxResponseBytes: 64 << 10,
	}, httpClient)
	if err != nil {
		return nil, runtimeStageError{stage: "configure analytics ingest ClickHouse client", err: err}
	}
	checkTimeout := 2 * (cfg.AnalyticsIngest.ConnectTimeout + cfg.AnalyticsIngest.WriteTimeout)
	checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)
	err = client.CheckIngest(checkCtx)
	cancel()
	if err != nil {
		return nil, runtimeStageError{stage: "verify analytics ingest ClickHouse", err: err}
	}
	setupTimeout := 3 * jetstreamConfig.OperationTimeout
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	err = analytics.EnsureIngestJetStream(setupCtx, connection, jetstreamConfig)
	cancel()
	if err != nil {
		return nil, runtimeStageError{stage: "verify analytics ingest JetStream resources", err: err}
	}
	buildCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	// Country/province/carrier come from the control plane's IP library at
	// ingest (nodes do not send them), for the region/province/carrier reports.
	// Optional access log fields the platform does not record
	// (system configuration access_log_fields) are not stored.
	writer := analytics.GeoEnrichingWriter{Writer: client, Lookup: ingestClientGeo{analyticslog.NewPostgresIPIntelLookup(pool, logger)},
		Fields: systemconfig.NewAccessLogFieldReader(pool, logger)}
	worker, err := analytics.BuildIngestRuntime(connection, writer, jetstreamConfig, analytics.IngestDecoderConfig{}, logger,
		buildCtx, history, generation)
	cancel()
	if err != nil {
		return nil, runtimeStageError{stage: "build analytics ingest runtime", err: err}
	}
	recoveryCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	_, err = worker.RunScheduledHistoryRecovery(recoveryCtx)
	cancel()
	if err != nil {
		return nil, runtimeStageError{stage: "recover analytics ingest history", err: err}
	}
	worker.SetHealthyHandler(func() {
		if health.markRecovered(analyticsIngestDegradedWorker) {
			logger.Info("analytics ingest worker recovered")
		}
	})
	runtime := &analyticsIngestProcessRuntime{
		worker: worker, connection: connection, logger: logger, health: health,
		backoffMin: cfg.AnalyticsIngest.SupervisorBackoffMin, backoffMax: cfg.AnalyticsIngest.SupervisorBackoffMax,
		shutdownTimeout: cfg.ShutdownPeriod, closeHTTP: closeHTTP,
	}
	failed = false
	return runtime, nil
}

func newAnalyticsIngestHealth(enabled bool) *analyticsIngestHealth {
	health := &analyticsIngestHealth{enabled: enabled}
	if enabled {
		health.state.Store(analyticsIngestStateStarting)
	}
	return health
}

func (runtime *analyticsIngestProcessRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.worker == nil || runtime.health == nil || ctx == nil ||
		runtime.backoffMin <= 0 || runtime.backoffMax < runtime.backoffMin {
		return errors.New("analytics ingest process runtime is not configured")
	}
	delay := runtime.backoffMin
	runtime.health.markStarted()
	for {
		started := time.Now()
		err := runtime.worker.Run(ctx)
		if ctx.Err() != nil {
			runtime.health.markStopping()
			return ctx.Err()
		}
		if time.Since(started) >= runtime.backoffMax {
			delay = runtime.backoffMin
		}
		failures := runtime.health.failures.Add(1)
		runtime.health.markDegraded(analyticsIngestDegradedWorker)
		runtime.logger.Warn("analytics ingest worker degraded",
			"class", analyticsIngestFailureClass(err),
			"restart_count", failures,
			"retry_delay_ms", delay.Milliseconds())
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			runtime.health.markStopping()
			return ctx.Err()
		case <-timer.C:
		}
		if delay < runtime.backoffMax {
			delay = min(delay*2, runtime.backoffMax)
		}
	}
}

func (runtime *analyticsIngestProcessRuntime) Health() analyticsIngestHealthSnapshot {
	if runtime == nil || runtime.health == nil {
		return analyticsIngestHealthSnapshot{State: "disabled"}
	}
	return runtime.health.snapshot()
}

func (runtime *analyticsIngestProcessRuntime) Close() error {
	return runtime.CloseContext(context.Background())
}

func (runtime *analyticsIngestProcessRuntime) CloseContext(ctx context.Context) error {
	if runtime == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("analytics ingest shutdown context is required")
	}
	runtime.closeOnce.Do(func() {
		closeCtx, cancel := context.WithTimeout(ctx, runtime.shutdownTimeout)
		defer cancel()
		runtime.health.markStopping()
		if runtime.worker != nil && runtime.worker.Close() != nil {
			runtime.closeErr = errors.New("close analytics ingest consumer")
		}
		connectionClosed := runtime.connection == nil
		if runtime.connection != nil {
			closedStatuses := runtime.connection.StatusChanged(nats.CLOSED)
			defer runtime.connection.RemoveStatusListener(closedStatuses)
			connectionClosed = runtime.connection.IsClosed()
			if !connectionClosed {
				if err := runtime.connection.Drain(); err != nil {
					if runtime.closeErr == nil {
						runtime.closeErr = errors.New("drain analytics ingest NATS connection")
					}
					runtime.connection.Close()
					connectionClosed = runtime.connection.IsClosed()
				}
			}
			if !connectionClosed {
				poll := time.NewTicker(10 * time.Millisecond)
				defer poll.Stop()
			waitForClose:
				for !connectionClosed {
					select {
					case status := <-closedStatuses:
						connectionClosed = status == nats.CLOSED
					case <-poll.C:
						connectionClosed = runtime.connection.IsClosed()
					case <-closeCtx.Done():
						runtime.connection.Close()
						connectionClosed = runtime.connection.IsClosed()
						if runtime.closeErr == nil {
							runtime.closeErr = errors.New("analytics ingest NATS drain timed out")
						}
						break waitForClose
					}
				}
			}
			if !connectionClosed && runtime.closeErr == nil {
				runtime.closeErr = errors.New("close analytics ingest NATS connection")
			}
		}
		if runtime.closeHTTP != nil {
			runtime.closeHTTP()
		}
		if connectionClosed {
			runtime.health.markStopped()
		}
	})
	return runtime.closeErr
}

func (health *analyticsIngestHealth) snapshot() analyticsIngestHealthSnapshot {
	if health == nil || !health.enabled {
		return analyticsIngestHealthSnapshot{State: "disabled"}
	}
	var state string
	switch health.state.Load() {
	case analyticsIngestStateStarting:
		state = "starting"
	case analyticsIngestStateRunning:
		state = "running"
		if health.degraded.Load() != 0 {
			state = "degraded"
		}
	case analyticsIngestStateDegraded:
		state = "degraded"
	case analyticsIngestStateStopping:
		state = "stopping"
	case analyticsIngestStateStopped:
		state = "stopped"
	default:
		state = "degraded"
	}
	return analyticsIngestHealthSnapshot{
		Enabled: true, State: state, RestartCount: health.failures.Load(),
	}
}

func (health *analyticsIngestHealth) markStarted() {
	if health == nil || !health.enabled {
		return
	}
	health.state.CompareAndSwap(analyticsIngestStateStarting, analyticsIngestStateRunning)
}

func (health *analyticsIngestHealth) markDegraded(cause uint32) bool {
	if health == nil || !health.enabled || cause == 0 || !health.running() {
		return false
	}
	return health.degraded.Or(cause)&cause == 0
}

func (health *analyticsIngestHealth) markRecovered(cause uint32) bool {
	if health == nil || !health.enabled || cause == 0 || !health.running() {
		return false
	}
	return health.degraded.And(^cause)&cause != 0
}

func (health *analyticsIngestHealth) markStopping() {
	if health == nil || !health.enabled {
		return
	}
	for {
		state := health.state.Load()
		if state != analyticsIngestStateStarting && state != analyticsIngestStateRunning &&
			state != analyticsIngestStateDegraded {
			return
		}
		if health.state.CompareAndSwap(state, analyticsIngestStateStopping) {
			return
		}
	}
}

func (health *analyticsIngestHealth) markStopped() {
	if health != nil && health.enabled {
		health.state.Store(analyticsIngestStateStopped)
	}
}

func (health *analyticsIngestHealth) running() bool {
	if health == nil {
		return false
	}
	state := health.state.Load()
	return state == analyticsIngestStateStarting || state == analyticsIngestStateRunning || state == analyticsIngestStateDegraded
}

func analyticsIngestFailureClass(err error) string {
	if errors.Is(err, analytics.ErrIngestDegraded) {
		return "dependency"
	}
	if err == nil {
		return "unexpected_stop"
	}
	return "worker"
}

func withAnalyticsIngestHealth(next http.Handler, runtime *analyticsIngestProcessRuntime) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/health/detail" {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(writer).Encode(struct {
				AnalyticsIngest analyticsIngestHealthSnapshot `json:"analytics_ingest"`
			}{AnalyticsIngest: runtime.Health()})
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// ingestClientGeo answers the analytics ingest geo enrichment (country,
// province code, carrier tag) from the library the log pages use.
type ingestClientGeo struct {
	lookup *analyticslog.PostgresIPIntelLookup
}

func (geo ingestClientGeo) LookupClientGeo(ctx context.Context, addresses []string) map[string]analytics.ClientGeo {
	answers := geo.lookup.Lookup(ctx, addresses)
	result := make(map[string]analytics.ClientGeo, len(answers))
	for address, info := range answers {
		if info != nil {
			result[address] = analytics.ClientGeo{Country: info.Country, Province: info.Province, Carrier: info.Carrier}
		}
	}
	return result
}
