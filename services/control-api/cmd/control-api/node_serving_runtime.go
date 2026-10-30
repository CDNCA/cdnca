package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/nodednspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeserving"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/originfailover"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// nodeServingInterval is well below the shortest probe interval (1s minimum,
// 10s default) times the failure threshold, so a hold follows the Agent's
// unhealthy report within one tick.
const nodeServingInterval = 10 * time.Second

// openNodeServingWorker always runs: monitoring "pause" and per-node
// auto-disable are platform policy, not optional runtimes. It stops only with
// the process.
func openNodeServingWorker(pool *pgxpool.Pool) (*nodeserving.Worker, error) {
	store, err := nodeserving.NewStore(pool)
	if err != nil {
		return nil, err
	}
	// Alerts are queued even when the notification runtime is off; they are
	// delivered once a provider is configured (repeats are guarded).
	alerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	store.EnableAvailabilityAlerts(alerts)
	// Deployment timeouts run first: config sync then sees them as failed.
	return nodeserving.NewWorker(store, nodeServingInterval, slog.Default(),
		nodeserving.NewDeploymentTimeoutEvaluator(store), nodeserving.NewMonitorEvaluator(store), nodeserving.NewAutoDisableEvaluator(store),
		nodeserving.NewConfigSyncEvaluator(store, edgeautopublish.NewNodeSyncRetrier(pool)),
		// Republishes what a frozen node refused once it serves again.
		nodeserving.NewFrozenRedeliveryEvaluator(store, edgeautopublish.FrozenRepublisher{}),
		// Backup IP state last: it reads the holds the sources above just wrote.
		nodeserving.NewLineBackupEvaluator(store))
}

// nodeExternalProbeInterval is one external probe round (controller + peer
// nodes per monitoring group); thresholds and debounce come from each line
// group's health policy.
const nodeExternalProbeInterval = 30 * time.Second

// openNodeExternalProbe probes published node endpoints from outside the
// node. Peers are asked over the edge NATS connection (MARKET_PROBE); without
// one only the controller votes.
func openNodeExternalProbe(pool *pgxpool.Pool, edgeConnection natsRuntimeConnection) (*nodeprobe.Runner, error) {
	store, err := nodeserving.NewStore(pool)
	if err != nil {
		return nil, err
	}
	var peers *nodeprobe.PeerProber
	if edgeNATS, ok := edgeConnection.(*nats.Conn); ok && edgeNATS != nil {
		requester, err := marketprobe.NewNATSRequester(edgeNATS)
		if err != nil {
			return nil, err
		}
		peers = nodeprobe.NewPeerProber(requester, time.Now)
	}
	return nodeprobe.NewRunner(nodeprobe.Config{Pool: pool, Recorder: nodescheduler.NewService(pool, time.Now), Holds: store,
		Controller: nodeprobe.NewControllerProber(nil), Peers: peers,
		Logger: slog.Default().With("component", "node_external_probe")})
}

// openNodeDNSPupProbe probes published node addresses from dnspup
// checkpoints (module.probe.dnspup with a key pair; internal/nodednspupprobe):
// the availability log and, with the local probe, the serving hold.
func openNodeDNSPupProbe(pool *pgxpool.Pool, sources func(context.Context) dnspupprobe.Runtime) (*nodednspupprobe.Runner, error) {
	alerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	return nodednspupprobe.NewRunner(nodednspupprobe.Config{Pool: pool, Sources: sources, Alerts: alerts,
		Logger: slog.Default().With("component", "node_dnspup_probe")})
}

// openOriginProbe probes every site's origins and moves the active origin
// level. The tenant's own nodes probe what they can
// (HTTPS host targets on 443) over the edge NATS connection; the control
// plane probes the rest.
func openOriginProbe(pool *pgxpool.Pool, edgeConnection natsRuntimeConnection,
	sources originfailover.SourcesFunc) (*originfailover.Runner, error) {
	alerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	var peers originfailover.PeerProber
	if edgeNATS, ok := edgeConnection.(*nats.Conn); ok && edgeNATS != nil {
		requester, err := marketprobe.NewNATSRequester(edgeNATS)
		if err != nil {
			return nil, err
		}
		peers = originfailover.NewNodePeerProber(requester)
	}
	return originfailover.NewRunner(pool, originfailover.NewStore(pool, alerts, time.Now),
		originfailover.NewControllerProber(nil), peers, slog.Default().With("component", "origin_probe")).WithSources(sources), nil
}
