package main

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeporttransition"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const nodePortTransitionReadinessTimeout = 2 * time.Second

type nodePortTransitionProductionRuntime struct {
	runtime    *nodeporttransition.NATSRuntime
	connection *nats.Conn
	pool       *pgxpool.Pool
}

func openNodePortTransitionProductionRuntime(
	enabled bool,
	cfg config.Config,
	pool *pgxpool.Pool,
	connect natsConnector,
) (_ *nodePortTransitionProductionRuntime, returnedErr error) {
	if !enabled {
		return nil, nil
	}
	if pool == nil || connect == nil {
		return nil, errors.New("node port transition runtime dependencies are required")
	}
	options := []nats.Option{
		nats.Name("cdnca-control-api-node-port-transition"),
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
	if err != nil {
		return nil, runtimeStageError{stage: "connect node port transition NATS", err: err}
	}
	if connection == nil {
		return nil, errors.New("connect node port transition NATS returned no connection")
	}
	failed := true
	defer func() {
		if failed {
			connection.Close()
		}
	}()
	store := nodeporttransition.NewPostgresStore(pool, time.Now)
	service := nodeporttransition.NewService(store, time.Now, uuid.New)
	runtime, err := nodeporttransition.NewNATSRuntime(
		store, service, connection, nodeporttransition.DefaultNATSRuntimeConfig(), time.Now,
	)
	if err != nil {
		return nil, err
	}
	failed = false
	return &nodePortTransitionProductionRuntime{runtime: runtime, connection: connection, pool: pool}, nil
}

func (runtime *nodePortTransitionProductionRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.runtime == nil || ctx == nil {
		return errors.New("node port transition runtime is not configured")
	}
	return runtime.runtime.Run(ctx)
}

func (runtime *nodePortTransitionProductionRuntime) Ready() error {
	if runtime == nil || runtime.runtime == nil || runtime.connection == nil || runtime.pool == nil ||
		runtime.connection.IsClosed() || !runtime.connection.IsConnected() {
		return errors.New("node port transition runtime is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), nodePortTransitionReadinessTimeout)
	defer cancel()
	return runtime.pool.Ping(ctx)
}

func (runtime *nodePortTransitionProductionRuntime) Close() error {
	if runtime == nil || runtime.runtime == nil {
		return nil
	}
	return runtime.runtime.Close()
}
