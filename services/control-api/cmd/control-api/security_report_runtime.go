package main

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// securityReportBindRetry: the report stream is the agent gateway's; until it
// exists Run retries the consumer binding.
const securityReportBindRetry = 10 * time.Second

// securityReportRuntime consumes the node report stream (durable
// control_api_autodefense_reports) in the community edition: platform node
// security events (F4) go to ClickHouse and the notification center, CC
// rule statistics (cc_stats) to their ClickHouse table. The automatic
// defense reports are acknowledged and dropped (no module here).
type securityReportRuntime struct {
	nats     *nats.Conn
	ingestor *securityanalytics.Ingestor
	router   *securityReportRouter
	logger   *slog.Logger

	mu       sync.Mutex
	consumer *securityanalytics.NATSConsumer
}

type securityReportRouter struct {
	ingestor *securityanalytics.Ingestor
}

func (router *securityReportRouter) Ingest(ctx context.Context, subjectNode string, encoded []byte) (string, error) {
	report, err := contract.DecodeReport(encoded)
	if err != nil || report.NodeID != subjectNode {
		return "", securityanalytics.ErrInvalidReport
	}
	if report.Kind == contract.ReportCCStats {
		return router.ingestor.IngestCCStats(ctx, report)
	}
	return router.ingestor.Ingest(ctx, subjectNode, encoded)
}

// openSecurityReportRuntime returns nil without the analytics ingest side
// (its ClickHouse and NATS), like the commercial auto defense ingest.
func openSecurityReportRuntime(cfg config.Config, pool *pgxpool.Pool, ingest *analyticsIngestProcessRuntime) (*securityReportRuntime, error) {
	if !configuredRuntimePool(pool) || ingest == nil {
		return nil, nil
	}
	connection, ok := ingest.connection.(*nats.Conn)
	if !ok || connection == nil {
		return nil, nil
	}
	writer, err := securityanalytics.NewClickHouse(cfg.AnalyticsIngest.ClickHouseURL, cfg.AnalyticsIngest.ClickHouseDatabase,
		cfg.AnalyticsIngest.ClickHouseUsername, cfg.AnalyticsIngest.ClickHousePassword, 10*time.Second)
	if err != nil {
		return nil, err
	}
	ingestor, err := securityanalytics.NewIngestor(pool, writer, time.Now)
	if err != nil {
		return nil, err
	}
	// Node kernel bans go to the notification center even when the
	// notification runtime is off, like node availability alerts.
	alerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	ingestor.EnableNodeEventAlerts(alerts)
	if os.Getenv("MARKET_RUNTIME_ENABLED") == "true" && os.Getenv("MARKET_PROBE_ENABLED") == "true" {
		ingestor.EnableMarketNodeActions()
	}
	return &securityReportRuntime{nats: connection, ingestor: ingestor, router: &securityReportRouter{ingestor: ingestor},
		logger: slog.Default().With("component", "security_reports")}, nil
}

// Run binds the durable consumer (retrying until the gateway created the
// stream) and ingests reports until ctx ends.
func (runtime *securityReportRuntime) Run(ctx context.Context) error {
	for {
		consumer, err := securityanalytics.NewNATSConsumer(runtime.nats, runtime.router, runtime.logger)
		if err == nil {
			runtime.mu.Lock()
			runtime.consumer = consumer
			runtime.mu.Unlock()
			return consumer.Run(ctx, runtime.ingestor.PruneReceipts)
		}
		runtime.logger.Warn("security report consumer not bound yet", "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(securityReportBindRetry):
		}
	}
}

func (runtime *securityReportRuntime) Close() error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.consumer != nil {
		return runtime.consumer.Close()
	}
	return nil
}

// clickHouseEndpoint is one ClickHouse identity of the security tables.
type clickHouseEndpoint struct {
	URL, Database, Username, Password string
}

func (endpoint clickHouseEndpoint) configured() bool { return endpoint.URL != "" }

func newAutoDefenseClickHouse(endpoint clickHouseEndpoint) (*securityanalytics.ClickHouse, error) {
	return securityanalytics.NewClickHouse(endpoint.URL, endpoint.Database, endpoint.Username, endpoint.Password, 10*time.Second)
}
