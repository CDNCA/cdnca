package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// securityBanRuntime is the ban list library: the API store
// (always), the sync of the nodes' automatic bans from ClickHouse (when the
// analytics log client is configured) and the signed per-node distribution
// (when the edge publication signer and edge NATS are).
type securityBanRuntime struct {
	store       *securityban.Store
	syncer      *securityban.Syncer
	distributor *securityban.Distributor
}

type securityBanSyncWorker struct{ syncer *securityban.Syncer }

func (worker securityBanSyncWorker) Run(ctx context.Context) error {
	worker.syncer.Run(ctx, time.Minute)
	return ctx.Err()
}

func (runtime *securityBanRuntime) workers() []runtimeWorker {
	workers := []runtimeWorker{}
	if runtime.syncer != nil {
		workers = append(workers, securityBanSyncWorker{syncer: runtime.syncer})
	}
	if runtime.distributor != nil {
		workers = append(workers, runtime.distributor)
	}
	return workers
}

func buildSecurityBanRuntime(pool *pgxpool.Pool, analytics *analyticslog.Client, signer *edgePublishArtifactSigner,
	connection natsRuntimeConnection,
) (*securityBanRuntime, error) {
	runtime := &securityBanRuntime{store: securityban.NewStore(pool, time.Now)}
	// Node security alerts (folded WAF bans, cut lists) go to the notification
	// center even when the notification runtime is off.
	alerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	if analytics != nil {
		syncer, err := securityban.NewSyncer(pool, analytics, time.Now)
		if err != nil {
			return nil, err
		}
		syncer.EnableWAFBanAlerts(alerts)
		runtime.syncer = syncer
	} else {
		slog.Warn("security ban list does not fold node automatic bans: the analytics log ClickHouse client is not configured")
	}
	edgeNATS, _ := connection.(*nats.Conn)
	if signer == nil || edgeNATS == nil {
		slog.Warn("security ban list is not pushed to nodes: the edge publication signer or edge NATS is not configured")
		return runtime, nil
	}
	transport, err := securityban.NewNATSTransport(edgeNATS, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if runtime.distributor, err = securityban.NewDistributor(securityban.DistributorConfig{
		Pool: pool, Transport: transport, KeyID: signer.KeyID(), Sign: signer.Sign, Interval: 30 * time.Second,
		Logger: slog.Default(), Alerts: alerts}); err != nil {
		return nil, err
	}
	runtime.store.OnChange(runtime.distributor.Wake)
	if runtime.syncer != nil {
		runtime.syncer.OnChange(runtime.distributor.Wake)
	}
	return runtime, nil
}
