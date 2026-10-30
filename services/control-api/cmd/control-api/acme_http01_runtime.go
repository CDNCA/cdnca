package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmehttp01"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// acmeHTTP01PublishTimeout bounds one HTTP-01 Publish: every target node must
// receive, activate and health check the token generation (several delivery
// attempts) before the CA is asked to validate.
const acmeHTTP01PublishTimeout = 3 * time.Minute

// acmeHTTP01NodeRuntime is the production HTTP-01 path (FX05①, ADR-0003):
// tokens reach every serving node of the site's line groups as node-global
// overlay generations, signed with the edge publication key the agents trust.
type acmeHTTP01NodeRuntime struct {
	provider  *acmehttp01.NodeProvider
	artifacts *acmehttp01.NodeArtifactStore
	runtime   *acmehttp01.NodeRuntime
	signer    *edgePublishArtifactSigner
}

// openACMEHTTP01NodeRuntime returns nil (HTTP-01 stays refused) when the
// ACME runtime or edge publication is disabled: without the edge signing key
// no agent would accept the overlay.
func openACMEHTTP01NodeRuntime(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
	environment []string,
	connect natsConnector,
) (_ *acmeHTTP01NodeRuntime, returnedErr error) {
	if !cfg.ACMERuntimeEnabled {
		return nil, nil
	}
	configured := false
	for _, entry := range environment {
		configured = configured || strings.HasPrefix(entry, "EDGE_PUBLISH_RUNTIME_ENABLED=")
	}
	if !configured {
		slog.Warn("ACME HTTP-01 is unavailable: edge publication is not configured")
		return nil, nil
	}
	edgePublish, err := loadEdgePublishRuntimeConfigFromEnvEntries(environment)
	enabled := edgePublish.Enabled
	edgePublish.clearSecrets()
	if err != nil {
		return nil, runtimeStageError{stage: "read edge publication configuration for ACME HTTP-01", err: err}
	}
	if !enabled {
		slog.Warn("ACME HTTP-01 is unavailable: edge publication is disabled")
		return nil, nil
	}
	if ctx == nil || pool == nil || connect == nil {
		return nil, errors.New("ACME HTTP-01 node runtime dependencies are required")
	}
	signer, err := loadEdgePublishArtifactSigner(true)
	if err != nil {
		return nil, runtimeStageError{stage: "load ACME HTTP-01 overlay signer", err: err}
	}
	failed := true
	defer func() {
		if failed {
			signer.Close()
		}
	}()
	storeConfig := acmehttp01.DefaultNodeStoreConfig()
	storeConfig.AttemptTimeout = 45 * time.Second
	store, err := acmehttp01.NewNodeStore(pool, storeConfig)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME HTTP-01 node store", err: err}
	}
	// Drift alerts are queued even when the notification runtime is off, like
	// node availability alerts (repeats are guarded).
	alerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME HTTP-01 drift alerts", err: err}
	}
	store.EnableDriftAlerts(alerts)
	artifacts, err := acmehttp01.NewNodeArtifactStore(store, signer, acmehttp01.DefaultNodeArtifactConfig())
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME HTTP-01 node artifacts", err: err}
	}
	provider, err := acmehttp01.NewNodeProvider(store, 500*time.Millisecond, 10*time.Second, slog.Default())
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME HTTP-01 node provider", err: err}
	}
	options := []nats.Option{
		nats.Name("cdnca-control-api-acme-http01"),
		nats.Timeout(cfg.EdgeDeploymentConnectTimeout),
		nats.ReconnectWait(time.Second),
		nats.MaxReconnects(-1),
		nats.DrainTimeout(cfg.ShutdownPeriod),
	}
	if cfg.EdgeDeploymentNATSCredsFile != "" {
		options = append(options,
			nats.UserCredentials(cfg.EdgeDeploymentNATSCredsFile),
			nats.RootCAs(cfg.EdgeDeploymentNATSCAFile),
		)
	}
	connection, err := connect(cfg.EdgeDeploymentNATSURL, options...)
	if err != nil || connection == nil {
		return nil, runtimeStageError{stage: "connect ACME HTTP-01 NATS", err: err}
	}
	defer func() {
		if failed {
			connection.Close()
		}
	}()
	dispatchConfig := acmehttp01.DefaultDispatcherConfig()
	dispatchConfig.Stream = cfg.EdgeCommandStream
	dispatchConfig.BatchSize = 32
	dispatcher, err := acmehttp01.NewNodeDispatcher(store, artifacts, connection, dispatchConfig, slog.Default())
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME HTTP-01 node dispatcher", err: err}
	}
	statusConfig := acmehttp01.DefaultStatusConfig()
	statusConfig.Stream = cfg.EdgeStatusStream
	status, err := acmehttp01.NewNodeStatusConsumer(store, connection, statusConfig, slog.Default())
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME HTTP-01 node status consumer", err: err}
	}
	runtime, err := acmehttp01.NewNodeRuntime(dispatcher, status, connection)
	if err != nil {
		_ = status.Close()
		return nil, runtimeStageError{stage: "configure ACME HTTP-01 node runtime", err: err}
	}
	failed = false
	slog.Info("ACME HTTP-01 node overlay runtime configured")
	return &acmeHTTP01NodeRuntime{provider: provider, artifacts: artifacts, runtime: runtime, signer: signer}, nil
}

func (r *acmeHTTP01NodeRuntime) Close() error {
	if r == nil {
		return nil
	}
	err := r.runtime.Close()
	r.signer.Close()
	return err
}
