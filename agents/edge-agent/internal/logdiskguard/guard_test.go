package logdiskguard

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const (
	segmentHeaderSize = 24
	recordHeaderSize  = 40
)

var testCRCTable = crc32.MakeTable(crc32.Castagnoli)

type fixture struct {
	root       string
	spool      string
	segments   string
	state      string
	temporary  string
	guardState string
	base       time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(root, "event-spool")
	fixture := fixture{
		root: root, spool: spool, segments: filepath.Join(spool, "segments"),
		state: filepath.Join(spool, "state"), temporary: filepath.Join(spool, "tmp"),
		guardState: filepath.Join(root, "log-disk-guard"),
		base:       time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC),
	}
	for _, directory := range []string{fixture.spool, fixture.segments, fixture.state, fixture.temporary} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writePrivateJSON(t, filepath.Join(fixture.state, "ack.json"), map[string]any{
		"schema_version": 1, "sequence": 0,
	})
	if err := os.WriteFile(filepath.Join(fixture.state, "spool.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture fixture) config() Config {
	return Config{
		Enabled: true, SchemaVersion: ConfigSchemaVersion, ConfigID: "edge-agent-log-disk",
		Revision: 1, SpoolRoot: fixture.spool, StateRoot: fixture.guardState,
		LockPath: filepath.Join(fixture.guardState, "guard.lock"), LowWatermark: 8000,
		HighWatermark: 9000, MinimumFreeBytes: 128 << 20, MinimumAge: time.Hour,
		EvaluationPeriod: 30 * time.Second, MaxRoundDuration: time.Second,
		MaxDeletedFiles: 10, MaxDeletedBytes: 64 << 20,
	}
}

func writePrivateJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fixture fixture) ack(t *testing.T, sequence uint64) {
	t.Helper()
	writePrivateJSON(t, filepath.Join(fixture.state, "ack.json"), map[string]any{
		"schema_version": 1, "sequence": sequence, "event_id": "event-ack",
	})
}

func (fixture fixture) segment(t *testing.T, start uint64, suffix string, eventTypes ...string) string {
	t.Helper()
	header := make([]byte, segmentHeaderSize)
	copy(header[:8], []byte{'C', 'D', 'N', 'E', 'V', 'T', '1', 0})
	binary.BigEndian.PutUint16(header[8:10], 1)
	binary.BigEndian.PutUint64(header[16:24], start)
	content := append([]byte(nil), header...)
	for index, eventType := range eventTypes {
		payload, err := json.Marshal(map[string]any{
			"schema_version": 1, "type": eventType, "sequence": start + uint64(index),
		})
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, '\n')
		frame := make([]byte, recordHeaderSize+len(payload))
		binary.BigEndian.PutUint32(frame[0:4], uint32(len(payload)))
		binary.BigEndian.PutUint32(frame[4:8], crc32.Checksum(payload, testCRCTable))
		digest := sha256.Sum256(payload)
		copy(frame[8:40], digest[:])
		copy(frame[40:], payload)
		content = append(content, frame...)
	}
	name := segmentName(start, suffix)
	path := filepath.Join(fixture.segments, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	old := fixture.base.Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return path
}

func (fixture fixture) staleTemp(t *testing.T, name string, stale bool) string {
	t.Helper()
	path := filepath.Join(fixture.temporary, name)
	if err := os.WriteFile(path, []byte("temporary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	modified := fixture.base.Add(-2 * time.Hour)
	if !stale {
		modified = fixture.base.Add(-time.Minute)
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
	return path
}

func highUsage(string) (Usage, error) {
	return Usage{TotalBytes: 1 << 30, AvailableBytes: 50 << 20}, nil
}

func lowUsage(string) (Usage, error) {
	return Usage{TotalBytes: 1 << 30, AvailableBytes: 300 << 20}, nil
}

func requireExists(t *testing.T, path string, exists bool) {
	t.Helper()
	_, err := os.Lstat(path)
	if exists && err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
	if !exists && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected %s to be absent: %v", path, err)
	}
}

func TestGuardDeletesOnlyAckedReproducibleSegmentsAndExpiredTemps(t *testing.T) {
	fixture := newFixture(t)
	fixture.ack(t, 10)
	acked := fixture.segment(t, 1, "seg", "access.v1", "security.v1")
	unacked := fixture.segment(t, 3, "seg", "access.v1", "security.v1", "access.v1", "security.v1", "access.v1", "security.v1", "access.v1", "security.v1", "access.v1")
	open := fixture.segment(t, 12, "open", "access.v1")
	staleTemp := fixture.staleTemp(t, "access-00000000000000000001.tmp", true)
	freshTemp := fixture.staleTemp(t, "security-00000000000000000002.tmp", false)
	unknownTemp := fixture.staleTemp(t, "upgrade-00000000000000000003.tmp", true)

	protected := []string{
		filepath.Join(fixture.root, "audit", "ledger.json"),
		filepath.Join(fixture.root, "upgrades", "journal.json"),
		filepath.Join(fixture.root, "deployments", "active"),
		filepath.Join(fixture.root, "deployments", "last-known-good"),
		filepath.Join(fixture.root, "certificates", "leaf.pem"),
	}
	for _, path := range protected {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("protected\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	guard, err := New(fixture.config(), Options{Now: func() time.Time { return fixture.base }, Usage: highUsage})
	if err != nil {
		t.Fatal(err)
	}
	report, err := guard.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.ReasonCode != ReasonCleanupCompleted || report.Metrics.RoundDeletedFiles != 2 {
		t.Fatalf("report = %+v", report)
	}
	requireExists(t, acked, false)
	requireExists(t, staleTemp, false)
	for _, path := range append([]string{unacked, open, freshTemp, unknownTemp}, protected...) {
		requireExists(t, path, true)
	}
}

func TestGuardPressureUsesWatermarkMinimumFreeAndRoundBudgets(t *testing.T) {
	t.Run("healthy partition", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.ack(t, 1)
		candidate := fixture.segment(t, 1, "seg", "access.v1")
		config := fixture.config()
		config.MinimumFreeBytes = 100 << 20
		guard, err := New(config, Options{Now: func() time.Time { return fixture.base }, Usage: lowUsage})
		if err != nil {
			t.Fatal(err)
		}
		report, err := guard.Evaluate(context.Background())
		if err != nil || report.Metrics.ReasonCode != ReasonHealthy || report.Metrics.Pressure {
			t.Fatalf("Evaluate() = %+v, %v", report, err)
		}
		requireExists(t, candidate, true)
	})

	t.Run("minimum free and file budget", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.ack(t, 2)
		first := fixture.segment(t, 1, "seg", "access.v1")
		second := fixture.segment(t, 2, "seg", "security.v1")
		config := fixture.config()
		config.HighWatermark = 9500
		config.MinimumFreeBytes = 400 << 20
		config.MaxDeletedFiles = 1
		guard, err := New(config, Options{Now: func() time.Time { return fixture.base }, Usage: lowUsage})
		if err != nil {
			t.Fatal(err)
		}
		report, err := guard.Evaluate(context.Background())
		if err != nil || report.Metrics.ReasonCode != ReasonBudgetExhausted || !report.Metrics.Pressure || report.Metrics.RoundDeletedFiles != 1 {
			t.Fatalf("Evaluate() = %+v, %v", report, err)
		}
		remaining := 0
		for _, path := range []string{first, second} {
			if _, err := os.Lstat(path); err == nil {
				remaining++
			}
		}
		if remaining != 1 {
			t.Fatalf("remaining candidates = %d", remaining)
		}
	})

	t.Run("time budget", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.ack(t, 2)
		fixture.segment(t, 1, "seg", "access.v1")
		fixture.segment(t, 2, "seg", "security.v1")
		config := fixture.config()
		config.MaxRoundDuration = 10 * time.Millisecond
		var mu sync.Mutex
		calls := 0
		now := func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			calls++
			if calls > 3 {
				return fixture.base.Add(time.Second)
			}
			return fixture.base
		}
		guard, err := New(config, Options{Now: now, Usage: highUsage})
		if err != nil {
			t.Fatal(err)
		}
		report, err := guard.Evaluate(context.Background())
		if err != nil || report.Metrics.ReasonCode != ReasonBudgetExhausted || report.Metrics.RoundDeletedFiles > 1 {
			t.Fatalf("Evaluate() = %+v, %v", report, err)
		}
	})
}

func TestGuardRejectsSymlinkAndHardlinkWithoutPartialDeletion(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.ack(t, 2)
		safe := fixture.segment(t, 1, "seg", "access.v1")
		outside := filepath.Join(fixture.root, "outside")
		if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(fixture.segments, segmentName(2, "seg"))
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		guard, err := New(fixture.config(), Options{Now: func() time.Time { return fixture.base }, Usage: highUsage})
		if err != nil {
			t.Fatal(err)
		}
		report, err := guard.Evaluate(context.Background())
		if !errors.Is(err, ErrUnsafePath) || report.Metrics.ReasonCode != ReasonUnsafePath || report.Metrics.RoundDeletedFiles != 0 {
			t.Fatalf("Evaluate() = %+v, %v", report, err)
		}
		for _, path := range []string{safe, outside, link} {
			requireExists(t, path, true)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.ack(t, 2)
		first := fixture.segment(t, 1, "seg", "access.v1")
		second := filepath.Join(fixture.segments, segmentName(2, "seg"))
		if err := os.Link(first, second); err != nil {
			t.Fatal(err)
		}
		guard, err := New(fixture.config(), Options{Now: func() time.Time { return fixture.base }, Usage: highUsage})
		if err != nil {
			t.Fatal(err)
		}
		report, err := guard.Evaluate(context.Background())
		if !errors.Is(err, ErrUnsafePath) || report.Metrics.ReasonCode != ReasonUnsafePath || report.Metrics.RoundDeletedFiles != 0 {
			t.Fatalf("Evaluate() = %+v, %v", report, err)
		}
		requireExists(t, first, true)
		requireExists(t, second, true)
	})
}

func TestGuardSingleExecutionAndCrashRecovery(t *testing.T) {
	t.Run("single execution", func(t *testing.T) {
		fixture := newFixture(t)
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		usage := func(string) (Usage, error) {
			once.Do(func() { close(entered) })
			<-release
			return Usage{TotalBytes: 1000, AvailableBytes: 50}, nil
		}
		guard, err := New(fixture.config(), Options{Now: func() time.Time { return fixture.base }, Usage: usage})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, evaluateErr := guard.Evaluate(context.Background()); done <- evaluateErr }()
		<-entered
		if _, err := guard.Evaluate(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
			t.Fatalf("concurrent Evaluate() error = %v", err)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("quarantine restart", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.ack(t, 1)
		candidate := fixture.segment(t, 1, "seg", "access.v1")
		crash := errors.New("injected crash after quarantine")
		guard, err := New(fixture.config(), Options{
			Now: func() time.Time { return fixture.base }, Usage: highUsage,
			hooks: testHooks{afterQuarantine: func() error { return crash }},
		})
		if err != nil {
			t.Fatal(err)
		}
		if report, err := guard.Evaluate(context.Background()); !errors.Is(err, crash) || report.Metrics.ReasonCode != ReasonDeleteFailed {
			t.Fatalf("crash Evaluate() = %+v, %v", report, err)
		}
		requireExists(t, candidate, false)

		restarted, err := New(fixture.config(), Options{Now: func() time.Time { return fixture.base }, Usage: highUsage})
		if err != nil {
			t.Fatal(err)
		}
		report, err := restarted.Evaluate(context.Background())
		if err != nil || report.Metrics.RoundRecoveredFiles != 1 {
			t.Fatalf("restart Evaluate() = %+v, %v", report, err)
		}
		entries, err := os.ReadDir(filepath.Join(fixture.guardState, "quarantine"))
		if err != nil || len(entries) != 0 {
			t.Fatalf("quarantine entries = %v, %v", entries, err)
		}
	})
}

func TestGuardDryRunAndDisabledModeDoNotDeleteOrCreateState(t *testing.T) {
	t.Run("dry run", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.ack(t, 1)
		candidate := fixture.segment(t, 1, "seg", "access.v1")
		config := fixture.config()
		config.DryRun = true
		guard, err := New(config, Options{Now: func() time.Time { return fixture.base }, Usage: highUsage})
		if err != nil {
			t.Fatal(err)
		}
		report, err := guard.Evaluate(context.Background())
		if err != nil || report.Metrics.RoundWouldDeleteFiles != 1 || report.Metrics.RoundDeletedFiles != 0 {
			t.Fatalf("Evaluate() = %+v, %v", report, err)
		}
		requireExists(t, candidate, true)
	})

	t.Run("disabled", func(t *testing.T) {
		root := t.TempDir()
		stateRoot := filepath.Join(root, "must-not-exist")
		guard, err := New(Config{Enabled: false, StateRoot: stateRoot}, Options{})
		if err != nil || guard != nil {
			t.Fatalf("New(disabled) = %v, %v", guard, err)
		}
		requireExists(t, stateRoot, false)
	})
}

func TestGuardEmitsStablePressureAndFailureReasons(t *testing.T) {
	fixture := newFixture(t)
	fixture.ack(t, 1)
	fixture.segment(t, 1, "seg", "access.v1")
	sink := &recordingSink{}
	config := fixture.config()
	config.MinimumFreeBytes = 1 << 20
	guard, err := New(config, Options{Now: func() time.Time { return fixture.base }, Usage: highUsage, EventSink: sink})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !sink.has(ReasonPressureHighWatermark) || !sink.has(ReasonCleanupCompleted) {
		t.Fatalf("events = %+v", sink.events)
	}
}

type recordingSink struct {
	mu     sync.Mutex
	events []Event
}

func (sink *recordingSink) RecordLogDiskGuardEvent(_ context.Context, event Event) {
	sink.mu.Lock()
	sink.events = append(sink.events, event)
	sink.mu.Unlock()
}

func (sink *recordingSink) has(reason ReasonCode) bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, event := range sink.events {
		if event.ReasonCode == reason {
			return true
		}
	}
	return false
}
