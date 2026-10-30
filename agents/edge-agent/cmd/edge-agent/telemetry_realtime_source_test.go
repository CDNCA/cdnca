package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/realtimecapture"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

type independentTestSink struct {
	metrics    []*agentv1.ConnectionsMetricEnvelopeV1
	windows    []eventspool.Envelope
	failWindow bool
}

func (s *independentTestSink) AppendBatch(_ context.Context, events []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	if s.failWindow {
		return nil, eventspool.ErrBackpressure
	}
	s.windows = append(s.windows, events...)
	return make([]eventspool.AppendResult, len(events)), nil
}

func (s *independentTestSink) AppendConnections(_ context.Context, value *agentv1.ConnectionsMetricEnvelopeV1) (eventspool.ConnectionsAppendResult, error) {
	s.metrics = append(s.metrics, value)
	return eventspool.ConnectionsAppendResult{}, nil
}

func (s *independentTestSink) ConnectionsWatermark(context.Context) (uint64, error) {
	return uint64(len(s.metrics)), nil
}
func (s *independentTestSink) Stats() (eventspool.Stats, error) {
	return eventspool.Stats{NextSequence: uint64(len(s.windows) + 1)}, nil
}

func TestIndependentSourceCertifiesOnlyContinuouslyObservedHour(t *testing.T) {
	for _, failure := range []string{"none", "source", "tail", "gap"} {
		t.Run(failure, func(t *testing.T) {
			source, sink, tailers := independentSourceFixture(t)
			start := time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC)
			now := start
			source.now = func() time.Time { return now }
			reader := source.readListeners
			for elapsed := time.Duration(0); elapsed <= time.Hour+realtimecapture.FinalizationGrace; elapsed += 5 * time.Second {
				now = start.Add(elapsed)
				if failure == "gap" && elapsed >= 30*time.Minute && elapsed < 31*time.Minute {
					continue
				}
				source.readListeners = reader
				if failure == "source" && elapsed == 30*time.Minute {
					source.readListeners = func([]uint16) (map[uint16]realtimecapture.Listener, error) {
						return nil, realtimecapture.ErrUnavailable
					}
				}
				err := source.collect(t.Context(), tailers, failure != "tail" || elapsed != 30*time.Minute)
				if err != nil && !(failure == "source" && elapsed == 30*time.Minute) {
					t.Fatal(err)
				}
			}
			want := 0
			if failure == "none" {
				want = 1
			}
			if len(sink.windows) != want {
				t.Fatalf("window count=%d want=%d", len(sink.windows), want)
			}
			if len(sink.metrics) == 0 || sink.metrics[0].Connections != 0 || sink.metrics[0].SchemaVersion != 2 || sink.metrics[0].ConfigVersionId == "" {
				t.Fatal("independent measured zero missing")
			}
		})
	}
}

func TestIndependentSourceRetriesFrozenWindowWithoutRepeatingMetric(t *testing.T) {
	source, sink, _ := independentSourceFixture(t)
	manifest, _, err := readActiveTelemetryManifest(source.config.DeploymentRoot)
	if err != nil {
		t.Fatal(err)
	}
	end := time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)
	window := realtimecapture.CompletedWindow{Start: end.Add(-time.Hour), End: end, ObservedAt: end.Add(-time.Second), AccessEvidence: [32]byte{1}, ConnectionEvidence: [32]byte{2}}
	sink.failWindow = true
	if err := source.enqueue(t.Context(), manifest, manifest.Sites[0], window.ObservedAt, end, 0, window.ConnectionEvidence, &window); !errors.Is(err, eventspool.ErrBackpressure) {
		t.Fatal(err)
	}
	if len(sink.metrics) != 1 || len(source.pending) != 1 {
		t.Fatal("pending observation not retained")
	}
	id := source.pending[0].window.EventID
	sink.failWindow = false
	if err := source.flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(sink.metrics) != 1 || len(sink.windows) != 1 || sink.windows[0].EventID != id || len(source.pending) != 0 {
		t.Fatal("retry changed identity or repeated observation")
	}
}

func independentSourceFixture(t *testing.T) (*independentMetricsSource, *independentTestSink, map[string]*eventspool.Tailer) {
	t.Helper()
	root := telemetrySecureRoot(t)
	version := uuid.NewString()
	bundle := telemetryReleaseBundle(t, root, version, 7, uuid.NewString(), telemetryListener{domain: "www.example.test", port: 18081})
	release := filepath.Join(root, "releases", bundle.ManifestSHA256)
	writeTelemetryRelease(t, release, bundle)
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(t.Context(), version, release); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", bundle.ManifestSHA256), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	manifest, _, err := readActiveTelemetryManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	site := manifest.Sites[0]
	tailer, err := eventspool.NewTailer(eventspool.TailConfig{SourcePath: site.AccessLogPath, StateDir: filepath.Join(root, "test-tail"),
		Identity:     eventspool.TrustedIdentity{EnrollmentNodeID: telemetryTestNodeID, TenantID: telemetryTestTenantID, SiteID: site.SiteID, ConfigVersionID: version, ListenPort: site.ListenPort},
		MaxLineBytes: 8192, MaxBatchEvents: 10, MaxQuarantineBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	sink := &independentTestSink{}
	source, err := newIndependentMetricsSource(telemetrySourceConfig{DeploymentRoot: root, EnrollmentNodeID: telemetryTestNodeID}, sink)
	if err != nil {
		t.Fatal(err)
	}
	source.readListeners = func([]uint16) (map[uint16]realtimecapture.Listener, error) {
		return map[uint16]realtimecapture.Listener{site.ListenPort: {Listening: true, Evidence: [32]byte{1}}}, nil
	}
	return source, sink, map[string]*eventspool.Tailer{site.AccessLogPath: tailer}
}
