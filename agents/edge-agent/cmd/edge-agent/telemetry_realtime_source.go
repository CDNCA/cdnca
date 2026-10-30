package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/realtimecapture"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type independentMetricsSink interface {
	eventspool.BatchSink
	AppendConnections(context.Context, *agentv1.ConnectionsMetricEnvelopeV1) (eventspool.ConnectionsAppendResult, error)
	ConnectionsWatermark(context.Context) (uint64, error)
	Stats() (eventspool.Stats, error)
}

type pendingIndependentObservation struct {
	metric       *agentv1.ConnectionsMetricEnvelopeV1
	window       *eventspool.Envelope
	metricQueued bool
}

type independentMetricsSource struct {
	config        telemetrySourceConfig
	sink          independentMetricsSink
	readListeners func([]uint16) (map[uint16]realtimecapture.Listener, error)
	now           func() time.Time
	last          time.Time
	configVersion string
	trackers      map[string]*realtimecapture.Tracker
	pending       []pendingIndependentObservation
}

func newIndependentMetricsSource(config telemetrySourceConfig, sink eventspool.BatchSink) (*independentMetricsSource, error) {
	queue, ok := sink.(independentMetricsSink)
	if !ok {
		return nil, errors.New("independent telemetry requires durable observation queues")
	}
	return &independentMetricsSource{config: config, sink: queue, readListeners: realtimecapture.ReadListeners, now: time.Now, trackers: map[string]*realtimecapture.Tracker{}}, nil
}

func (source *independentMetricsSource) invalidate() {
	source.trackers = map[string]*realtimecapture.Tracker{}
}

func (source *independentMetricsSource) collect(ctx context.Context, tailers map[string]*eventspool.Tailer, accessHealthy bool) error {
	if !accessHealthy {
		source.invalidate()
	}
	if err := source.flush(ctx); err != nil {
		source.invalidate()
		return err
	}
	now := source.now().UTC().Truncate(time.Millisecond)
	if !source.last.IsZero() && now.Sub(source.last) >= 0 && now.Sub(source.last) < 5*time.Second {
		return nil
	}
	source.last = now
	manifest, present, err := readActiveTelemetryManifest(source.config.DeploymentRoot)
	if err != nil || !present || manifest.InstallationID == "" {
		source.invalidate()
		return realtimecapture.ErrUnavailable
	}
	if manifest.ConfigVersionID != source.configVersion {
		source.invalidate()
		source.configVersion = manifest.ConfigVersionID
	}
	portSites := map[uint16]int{}
	for _, site := range manifest.Sites {
		portSites[site.ListenPort]++
	}
	ports := make([]uint16, 0, len(portSites))
	for port, count := range portSites {
		if count == 1 {
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		source.invalidate()
		return realtimecapture.ErrUnavailable
	}
	snapshots, err := source.readListeners(ports)
	if err != nil {
		source.invalidate()
		return err
	}
	for _, site := range manifest.Sites {
		if portSites[site.ListenPort] != 1 {
			continue
		} // Shared virtual hosts cannot claim a listener total as a site gauge.
		tailer := tailers[site.AccessLogPath]
		if tailer == nil {
			source.invalidate()
			return realtimecapture.ErrUnavailable
		}
		proof, err := tailer.CompleteSourceProof(ctx)
		if err != nil {
			source.invalidate()
			return err
		}
		key := site.SiteID + "/" + site.Domain + fmt.Sprint(":", site.ListenPort)
		tracker := source.trackers[key]
		if tracker == nil {
			tracker = &realtimecapture.Tracker{}
			source.trackers[key] = tracker
		}
		observation, ok := snapshots[site.ListenPort]
		if !ok || !observation.Listening {
			source.invalidate()
			return realtimecapture.ErrUnavailable
		}
		windows := tracker.Observe(now, observation.Connections, proof, observation.Evidence, accessHealthy)
		if err := source.enqueue(ctx, manifest, site, now, now, observation.Connections, observation.Evidence, nil); err != nil {
			source.invalidate()
			return err
		}
		for _, window := range windows {
			if err := source.enqueue(ctx, manifest, site, window.ObservedAt, window.End, window.Connections, window.ConnectionEvidence, &window); err != nil {
				source.invalidate()
				return err
			}
		}
	}
	return source.flush(ctx)
}

// collectDynamicRouting is collect for a dynamic routing node (D13-b2):
// every site listener shares the node's servers, so the gauge is the site's
// requests in flight on its port (cdnca_limits.site, read over the control
// socket), and the access proof is the shared access log's (one tailer for
// all sites). A site of a scope without a telemetry installation reports
// nothing.
func (source *independentMetricsSource) collectDynamicRouting(ctx context.Context, access *eventspool.Tailer, accessHealthy bool) error {
	if !accessHealthy {
		source.invalidate()
	}
	if err := source.flush(ctx); err != nil {
		source.invalidate()
		return err
	}
	now := source.now().UTC().Truncate(time.Millisecond)
	if !source.last.IsZero() && now.Sub(source.last) >= 0 && now.Sub(source.last) < 5*time.Second {
		return nil
	}
	source.last = now
	shared := source.config.DynamicRouting
	sites := shared.Sites()
	if len(sites) == 0 {
		source.invalidate()
		return realtimecapture.ErrUnavailable
	}
	counts, evidence, err := shared.Connections(ctx)
	if err != nil {
		source.invalidate()
		return err
	}
	proof, err := access.CompleteSourceProof(ctx)
	if err != nil {
		source.invalidate()
		return err
	}
	inFlight := make(map[string]uint64, len(counts))
	for _, count := range counts {
		inFlight[count.SiteID+fmt.Sprint("|", count.Port)] = count.Connections
	}
	live := make(map[string]bool, len(sites))
	for _, site := range sites {
		manifest := edgeconfig.TelemetryIdentityManifest{TenantID: site.TenantID, InstallationID: site.InstallationID,
			ConfigVersionID: site.ConfigVersionID}
		identity := edgeconfig.TelemetrySiteIdentity{SiteID: site.SiteID, Domain: site.Domain, ListenPort: site.Port,
			PackageSubscriptionID: site.PackageSubscriptionID}
		key := site.ConfigVersionID + "/" + site.SiteID + "/" + site.Domain + fmt.Sprint(":", site.Port)
		live[key] = true
		tracker := source.trackers[key]
		if tracker == nil {
			tracker = &realtimecapture.Tracker{}
			source.trackers[key] = tracker
		}
		connections := inFlight[site.SiteID+fmt.Sprint("|", site.Port)]
		windows := tracker.Observe(now, connections, proof, evidence, accessHealthy)
		if err := source.enqueue(ctx, manifest, identity, now, now, connections, evidence, nil); err != nil {
			source.invalidate()
			return err
		}
		for _, window := range windows {
			if err := source.enqueue(ctx, manifest, identity, window.ObservedAt, window.End, window.Connections, window.ConnectionEvidence, &window); err != nil {
				source.invalidate()
				return err
			}
		}
	}
	for key := range source.trackers {
		if !live[key] {
			delete(source.trackers, key) // a removed site or a new version
		}
	}
	return source.flush(ctx)
}

func (source *independentMetricsSource) enqueue(ctx context.Context, manifest edgeconfig.TelemetryIdentityManifest, site edgeconfig.TelemetrySiteIdentity,
	occurred, finalized time.Time, connections uint64, evidence [32]byte, window *realtimecapture.CompletedWindow) error {
	if err := source.flush(ctx); err != nil {
		return err
	}
	watermark, err := source.sink.ConnectionsWatermark(ctx)
	if err != nil || watermark == math.MaxUint64 {
		return realtimecapture.ErrUnavailable
	}
	metric := &agentv1.ConnectionsMetricEnvelopeV1{SchemaVersion: 2, TenantId: manifest.TenantID, InstallationId: manifest.InstallationID,
		SiteId: site.SiteID, PackageSubscriptionId: site.PackageSubscriptionID, NodeId: source.config.EnrollmentNodeID,
		Domain: site.Domain, ListenPort: uint32(site.ListenPort), ConfigVersionId: manifest.ConfigVersionID, Connections: connections,
		DependencyState:  agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY,
		FinalizedThrough: timestamppb.New(finalized), EvidenceSha256: evidence[:], SourceWatermark: watermark + 1}
	idBytes, _ := json.Marshal([]any{manifest.ConfigVersionID, source.config.EnrollmentNodeID, site.SiteID, site.Domain, site.ListenPort, occurred, finalized, watermark + 1})
	id := sha256.Sum256(idBytes)
	metric.Event = &commonv1.EventMetadata{EventId: "observed_" + hex.EncodeToString(id[:]), OccurredTime: timestamppb.New(occurred)}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(metric)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte("cdnca.connections.observed/v2\x00"), canonical...))
	metric.CanonicalEventSha256 = digest[:]
	pending := pendingIndependentObservation{metric: metric}
	if window != nil {
		stats, err := source.sink.Stats()
		if err != nil || stats.NextSequence == 0 {
			return realtimecapture.ErrUnavailable
		}
		event := edgeconfig.AccessWindowEvent{MetricVersion: 1, WindowStart: window.Start, WindowEnd: window.End,
			TenantID: manifest.TenantID, SiteID: site.SiteID, NodeID: source.config.EnrollmentNodeID, ConfigVersionID: manifest.ConfigVersionID,
			Host: site.Domain, ListenPort: site.ListenPort, SourceWatermark: stats.NextSequence, FinalizedThrough: window.End,
			DependencyState: "ready", EvidenceSHA256: hex.EncodeToString(window.AccessEvidence[:])}
		event.EventID = edgeconfig.AccessWindowEventID(event)
		record, err := eventspool.NewAccessWindowRecord(event)
		if err != nil {
			return err
		}
		pending.window = &record
	}
	source.pending = append(source.pending, pending)
	return source.flush(ctx)
}

func (source *independentMetricsSource) flush(ctx context.Context) error {
	for len(source.pending) > 0 {
		item := &source.pending[0]
		if !item.metricQueued {
			if _, err := source.sink.AppendConnections(ctx, item.metric); err != nil {
				return err
			}
			item.metricQueued = true
		}
		if item.window != nil {
			if _, err := source.sink.AppendBatch(ctx, []eventspool.Envelope{*item.window}); err != nil {
				return err
			}
		}
		source.pending = source.pending[1:]
	}
	return nil
}
