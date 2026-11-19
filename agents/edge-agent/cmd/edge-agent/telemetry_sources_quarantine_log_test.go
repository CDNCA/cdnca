package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

// Quarantined lines are summed per source and logged at most every
// quarantineLogInterval with the counts and a sample reason (a node used to
// log an issue and a recovery for every line, about 500 lines an hour, and
// none said why).
func TestReportTailSummarizesQuarantinedLines(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	source := filepath.Join(root, "access.jsonl")
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tailer, err := eventspool.NewTailer(eventspool.TailConfig{SourcePath: source, StateDir: filepath.Join(root, "state"),
		Identity:     eventspool.TrustedIdentity{EnrollmentNodeID: "0d120000-0000-4000-8000-00000000ffff"},
		MaxLineBytes: 1 << 10, MaxBatchEvents: 10, MaxQuarantineBytes: 1 << 20,
		Resolve: func([]byte) (eventspool.ResolvedLine, error) { return eventspool.ResolvedLine{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	defer slog.SetDefault(previous)
	now := time.Date(2026, 11, 19, 5, 0, 0, 0, time.UTC)
	runner := &telemetrySourceRunner{tailState: map[string]string{}, now: func() time.Time { return now }}
	quarantined := func(offset int64) eventspool.TailResult {
		return eventspool.TailResult{QuarantinedLines: 1, Issues: []eventspool.Issue{{Code: "TAIL_INVALID_JSON", Generation: 1,
			Offset: offset, Reason: "dynamic routing log line is invalid: site s does not serve 192.0.2.1:80"}}}
	}
	for round := 0; round < 100; round++ {
		runner.reportTail(tailer, quarantined(int64(round)*1000), nil)
		runner.reportTail(tailer, eventspool.TailResult{}, nil)
		now = now.Add(time.Second)
	}
	logged := output.String()
	if strings.Count(logged, "telemetry lines quarantined") != 1 || strings.Contains(logged, "telemetry source issue") ||
		strings.Contains(logged, "telemetry source recovered") || !strings.Contains(logged, "does not serve 192.0.2.1:80") {
		t.Fatalf("first window logged:\n%s", logged)
	}
	now = now.Add(quarantineLogInterval)
	runner.reportTail(tailer, quarantined(999000), nil)
	logged = output.String()
	if strings.Count(logged, "telemetry lines quarantined") != 2 || !strings.Contains(logged, "TAIL_INVALID_JSON=100") {
		t.Fatalf("second window logged:\n%s", logged)
	}
	// A non-quarantine issue (a line waiting for attribution) still logs as
	// an issue, and its end as a recovery.
	runner.reportTail(tailer, eventspool.TailResult{Issues: []eventspool.Issue{{Code: "TAIL_LINE_NOT_READY", Generation: 1, Offset: 5}}}, nil)
	runner.reportTail(tailer, eventspool.TailResult{}, nil)
	logged = output.String()
	if !strings.Contains(logged, "issue=TAIL_LINE_NOT_READY") || !strings.Contains(logged, "telemetry source recovered") {
		t.Fatalf("not ready logged:\n%s", logged)
	}
}
