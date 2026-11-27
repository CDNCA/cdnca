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
//
// timeoutsReady holds the deployment timeouts until the deployment status
// runtime finished its startup replay (see nodeserving HoldUntil); there is
// no time limit.
func openNodeServingWorker(pool *pgxpool.Pool, timeoutsReady func() bool) (*nodeserving.Worker, error) {
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
		nodeserving.NewDeploymentTimeoutEvaluator(store).HoldUntil(timeoutsReady), nodeserving.NewMonitorEvaluator(store), nodeserving.NewAutoDisableEvaluator(store),
		nodeserving.NewConfigSyncEvaluator(store, edgeautopublish.NewNodeSyncRetrier(pool)),
		// A reinstalled host whose enrollment republication failed (no ticket or
		// node artifact set yet) gets its scopes again.
		nodeserving.NewReinstallRedeliveryEvaluator(store, edgeautopublish.NewNodeSyncRetrier(pool)),
		// Republishes what a frozen node refused once it serves again.
		nodeserving.NewFrozenRedeliveryEvaluator(store, edgeautopublish.FrozenRepublisher{}),
		// Backup IP state last: it reads the holds the sources above just wrote.
		nodeserving.NewLineBackupEvaluator(store),
		// Then the alerts whose enqueue failed in a transition (migration 593).
		nodeserving.NewAlertIntentEvaluator(store))
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
func openNodeDNSPupProbe(pool *pgxpool.Pool, sources func(context.Context) dnspupprobe.Runtime,
	diagnose nodednspupprobe.Diagnoser) (*nodednspupprobe.Runner, error) {
	alerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	return nodednspupprobe.NewRunner(nodednspupprobe.Config{Pool: pool, Sources: sources, Alerts: alerts, Diagnose: diagnose,
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

// deploymentTimeoutHoldWarning is how long the deployment timeouts may wait
// for the status replay before the wait is reported (and again every as long
// while it lasts).
const deploymentTimeoutHoldWarning = 15 * time.Minute

// deploymentTimeoutGate is ready once replayDone (set when the edge runtime
// opens, before any worker starts) reports true, and not before: a deployment
// timed out ahead of the replay of statuses still in the stream would fail
// for good although the node runs it (its telemetry then refused). There is
// no time limit; a wait past warnAfter is logged.
func deploymentTimeoutGate(replayDone *func() bool, now func() time.Time, warnAfter time.Duration,
	logger *slog.Logger,
) func() bool {
	started := now()
	warned := started
	return func() bool {
		if *replayDone != nil && (*replayDone)() {
			return true
		}
		if at := now(); at.Sub(warned) >= warnAfter {
			warned = at
			logger.Warn("deployment timeouts held by pending deployment status replay", "held_for", at.Sub(started))
		}
		return false
	}
}
