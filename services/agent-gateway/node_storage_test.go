package gateway

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// NODE_STORAGE v1: the gateway forwards a well formed NodeStorageV1 and
// refuses a malformed one (the whole sample, like every telemetry field).
func TestValidateNodeStorage(t *testing.T) {
	ok := func(storage *agentv1.NodeStorageV1) bool {
		return validateNodeTelemetry(&agentv1.NodeTelemetryV1{SchemaVersion: 1, Storage: storage})
	}
	base := func() *agentv1.NodeStorageV1 {
		return &agentv1.NodeStorageV1{CacheDirectory: "/var/lib/cdnca-edge/dynroute/shared/cache", CacheMaxBytes: 10 << 30,
			LogDirectory: "/var/lib/cdnca-edge/dynroute/shared", State: "default"}
	}
	if !ok(nil) || !ok(base()) {
		t.Fatal("valid storage refused")
	}
	pending := base()
	pending.State, pending.RequestedLogDirectory = "restart_pending", "/data/logs"
	failed := base()
	failed.State, failed.Reason = "failed", "cache directory /data/x: permission denied"
	if !ok(pending) || !ok(failed) {
		t.Fatal("pending/failed refused")
	}
	for name, mutate := range map[string]func(*agentv1.NodeStorageV1){
		"relative cache":     func(s *agentv1.NodeStorageV1) { s.CacheDirectory = "cache" },
		"unclean log":        func(s *agentv1.NodeStorageV1) { s.LogDirectory = "/data/../etc" },
		"unknown state":      func(s *agentv1.NodeStorageV1) { s.State = "ok" },
		"reason not failed":  func(s *agentv1.NodeStorageV1) { s.Reason = "x" },
		"failed no reason":   func(s *agentv1.NodeStorageV1) { s.State = "failed" },
		"pending no request": func(s *agentv1.NodeStorageV1) { s.State = "restart_pending" },
		"request not pending": func(s *agentv1.NodeStorageV1) {
			s.RequestedLogDirectory = "/data/logs"
		},
		"multi-line reason": func(s *agentv1.NodeStorageV1) { s.State, s.Reason = "failed", "a\nb" },
		"over limit":        func(s *agentv1.NodeStorageV1) { s.CacheMaxBytes = 1<<50 + 1 },
	} {
		storage := base()
		mutate(storage)
		if ok(storage) {
			t.Errorf("%s accepted", name)
		}
	}
}
