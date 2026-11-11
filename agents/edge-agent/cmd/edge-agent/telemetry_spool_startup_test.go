package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
	"github.com/google/uuid"
)

// A corrupt event spool must neither stop the
// Agent from assembling (it builds the spool before it hands OpenResty its
// configuration) nor go unseen: the pipeline keeps running and the heartbeat's
// telemetry health carries TELEMETRY_SPOOL_CORRUPT to the control plane.

type offlineTelemetryDialer struct{}

func (offlineTelemetryDialer) Dial(context.Context) (telemetryclient.Connection, error) {
	return nil, errors.New("control plane unreachable")
}

func TestCorruptSpoolDoesNotStopAgentAndReachesHeartbeat(t *testing.T) {
	// A segment whose header magic is overwritten.
	corruptSegment := func(t *testing.T, root string) {
		segments := filepath.Join(root, "segments")
		if err := os.MkdirAll(segments, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(segments, "segment-00000000000000000001.seg"), make([]byte, 64), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// a corrupt ack.json is reported the same way.
	corruptAck := func(t *testing.T, root string) {
		state := filepath.Join(root, "state")
		if err := os.MkdirAll(state, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(state, "ack.json"), []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, test := range map[string]struct {
		corrupt func(*testing.T, string)
		code    string
	}{
		"segment": {corruptSegment, "TELEMETRY_SPOOL_CORRUPT"},
		"ack":     {corruptAck, "TELEMETRY_SPOOL_ACK_CORRUPT"},
	} {
		t.Run(name, func(t *testing.T) { corruptSpoolReachesHeartbeat(t, test.corrupt, test.code) })
	}
}

func corruptSpoolReachesHeartbeat(t *testing.T, corrupt func(*testing.T, string), want string) {
	directory := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(directory); err == nil {
		directory = resolved
	}
	_ = os.Chmod(directory, 0o700)
	config := defaultFileConfig()
	config.DeploymentRoot = filepath.Join(directory, "deploy")
	config.Telemetry.Enabled = true
	config.Telemetry.SpoolRoot = filepath.Join(directory, "spool")
	config.Telemetry.MaxSegmentBytes = 1 << 20
	config.Telemetry.SoftLimitBytes, config.Telemetry.HardLimitBytes, config.Telemetry.MaxTenantBytes = 8<<20, 16<<20, 8<<20
	config.Telemetry.EmptyInterval, config.Telemetry.InitialBackoff, config.Telemetry.MaximumBackoff = "50ms", "50ms", "100ms"
	if err := os.MkdirAll(config.DeploymentRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(config.Telemetry.SpoolRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	corrupt(t, config.Telemetry.SpoolRoot)
	timeouts, err := config.Telemetry.parse(config.DeploymentRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed := parsedTimeouts{TelemetrySoftAgeLimit: timeouts.softAge, TelemetryHardAgeLimit: timeouts.hardAge,
		TelemetryEmptyInterval: timeouts.emptyInterval, TelemetryHandshake: timeouts.handshake, TelemetryAck: timeouts.ack,
		TelemetryInitialBackoff: timeouts.initialBackoff, TelemetryMaximumBackoff: timeouts.maximumBackoff}
	pipeline, err := assembleTelemetryPipeline(config, parsed, uuid.NewString(), uuid.NewString(), offlineTelemetryDialer{}, nil, nil, "", nil)
	if err != nil {
		t.Fatalf("assembling telemetry on a corrupt spool = %v, want success (the Agent must go on to serve)", err)
	}
	daemon := &daemonClient{telemetry: pipeline}
	health := newTelemetryHealthTracker(time.Now)
	health.Bind(daemon.TelemetrySnapshot)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon.setTelemetryStatus(true, false)
	exited := make(chan error, 1)
	go func() { exited <- pipeline.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if report := health.Report(); report != nil && report.GetErrorCode() == want {
			break
		}
		select {
		case err := <-exited:
			t.Fatalf("telemetry pipeline exited on a corrupt spool: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("heartbeat telemetry health = %+v, snapshot = %+v", health.Report(), daemon.TelemetrySnapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code := pipeline.spool.FailureCode(); code != want {
		t.Fatalf("spool failure code = %q", code)
	}
	// Still running a while later (retries at backoff, not an exit).
	select {
	case err := <-exited:
		t.Fatalf("telemetry pipeline exited: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
}
