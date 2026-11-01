package main

import (
	"regexp"
	"sync"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// telemetryHealthTracker turns the telemetry pipeline's current error code
// (telemetryDaemonSnapshot.LastErrorCode: L4_USAGE_*, TELEMETRY_*, ...) into
// EdgeRuntimeStatus.telemetry. The gateway client is built
// before the pipeline, so the snapshot source is bound later.
type telemetryHealthTracker struct {
	now      func() time.Time
	mu       sync.Mutex
	snapshot func() telemetryDaemonSnapshot
	code     string
	first    time.Time
	last     time.Time
	count    uint64
}

var telemetryHealthCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func newTelemetryHealthTracker(now func() time.Time) *telemetryHealthTracker {
	return &telemetryHealthTracker{now: now}
}

func (t *telemetryHealthTracker) Bind(snapshot func() telemetryDaemonSnapshot) {
	t.mu.Lock()
	t.snapshot = snapshot
	t.mu.Unlock()
}

// Report is called once per heartbeat: nil while healthy, disabled or unbound.
func (t *telemetryHealthTracker) Report() *agentv1.TelemetryHealth {
	t.mu.Lock()
	defer t.mu.Unlock()
	code := ""
	if t.snapshot != nil {
		if snapshot := t.snapshot(); snapshot.Enabled && (snapshot.Degraded || snapshot.LastErrorCode != "") {
			code = snapshot.LastErrorCode
			if code == "" {
				code = "TELEMETRY_UNAVAILABLE"
			}
		}
	}
	if code == "" || !telemetryHealthCodePattern.MatchString(code) {
		t.code, t.count = "", 0
		return nil
	}
	now := t.now().UTC()
	if code != t.code {
		t.code, t.first, t.last, t.count = code, now, now, 0
	}
	if now.After(t.last) {
		t.last = now
	}
	t.count++
	return &agentv1.TelemetryHealth{ErrorCode: code, FirstSeenTime: timestamppb.New(t.first),
		LastSeenTime: timestamppb.New(t.last), Count: t.count}
}
