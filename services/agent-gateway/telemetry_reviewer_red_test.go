package gateway

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestOBSUsageATelemetryStreamRequiresExactSubjectSet(t *testing.T) {
	t.Parallel()
	exact := TelemetryIngestSubjectPrefix + ".*"
	valid := nats.StreamConfig{
		Name: "ANALYTICS_INGEST_V1", Subjects: []string{exact},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 10_000_000, MaxBytes: 10 << 30,
		Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}
	if !validTelemetryStreamInfo(&nats.StreamInfo{Config: valid}) {
		t.Fatal("exact authoritative telemetry subject set was rejected")
	}

	tests := map[string][]string{
		"single node": {TelemetryIngestSubjectPrefix + ".00000000-0000-0000-0000-000000000001"},
		"broad tail":  {TelemetryIngestSubjectPrefix + ".>"},
		"broad root":  {"cdnca.analytics.>"},
		"extra":       {exact, "cdnca.analytics.unrelated.v1.*"},
	}
	for name, subjects := range tests {
		t.Run(name, func(t *testing.T) {
			actual := valid
			actual.Subjects = subjects
			if validTelemetryStreamInfo(&nats.StreamInfo{Config: actual}) {
				t.Fatalf("non-exact telemetry subject set %q was accepted: %v", name, subjects)
			}
		})
	}
}

func TestOBSUsageATelemetryStreamRejectsBehaviorChangingFlags(t *testing.T) {
	t.Parallel()
	valid := nats.StreamConfig{
		Name: "ANALYTICS_INGEST_V1", Subjects: []string{TelemetryIngestSubjectPrefix + ".*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 10_000_000, MaxBytes: 10 << 30,
		Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}
	if !validTelemetryStreamInfo(&nats.StreamInfo{Config: valid}) {
		t.Fatal("exact authoritative telemetry stream was rejected")
	}

	tests := map[string]func(*nats.StreamConfig){
		"no publish ack":                  func(config *nats.StreamConfig) { config.NoAck = true },
		"sealed":                          func(config *nats.StreamConfig) { config.Sealed = true },
		"rollup":                          func(config *nats.StreamConfig) { config.AllowRollup = true },
		"discard new per subject":         func(config *nats.StreamConfig) { config.DiscardNewPerSubject = true },
		"deny delete":                     func(config *nats.StreamConfig) { config.DenyDelete = true },
		"deny purge":                      func(config *nats.StreamConfig) { config.DenyPurge = true },
		"nonzero first sequence":          func(config *nats.StreamConfig) { config.FirstSeq = 10 },
		"direct access":                   func(config *nats.StreamConfig) { config.AllowDirect = true },
		"mirror direct access":            func(config *nats.StreamConfig) { config.MirrorDirect = true },
		"subject delete marker retention": func(config *nats.StreamConfig) { config.SubjectDeleteMarkerTTL = time.Minute },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			actual := valid
			mutate(&actual)
			if validTelemetryStreamInfo(&nats.StreamInfo{Config: actual}) {
				t.Fatalf("behavior-changing stream config %q was accepted", name)
			}
		})
	}
}

func TestOBSUsageATelemetryStreamRequiresExactAuthoritativeLimits(t *testing.T) {
	t.Parallel()
	valid := nats.StreamConfig{
		Name: "ANALYTICS_INGEST_V1", Subjects: []string{TelemetryIngestSubjectPrefix + ".*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 10_000_000, MaxBytes: 10 << 30,
		Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}
	if !validTelemetryStreamInfo(&nats.StreamInfo{Config: valid}) {
		t.Fatal("exact authoritative telemetry stream limits were rejected")
	}
	tests := map[string]func(*nats.StreamConfig){
		"fewer messages":        func(config *nats.StreamConfig) { config.MaxMsgs-- },
		"more messages":         func(config *nats.StreamConfig) { config.MaxMsgs++ },
		"fewer bytes":           func(config *nats.StreamConfig) { config.MaxBytes-- },
		"more bytes":            func(config *nats.StreamConfig) { config.MaxBytes++ },
		"shorter deduplication": func(config *nats.StreamConfig) { config.Duplicates-- },
		"longer deduplication":  func(config *nats.StreamConfig) { config.Duplicates++ },
		"different replicas":    func(config *nats.StreamConfig) { config.Replicas = 2 },
		"larger message cap":    func(config *nats.StreamConfig) { config.MaxMsgSize++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			actual := valid
			mutate(&actual)
			if validTelemetryStreamInfo(&nats.StreamInfo{Config: actual}) {
				t.Fatalf("non-authoritative stream limits %q were accepted", name)
			}
		})
	}
}
