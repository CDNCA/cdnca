package nodemonitoring

import (
	"context"
	"errors"
	"time"
)

var ErrMetricBackpressure = errors.New("node monitoring durable queue is full")

type MetricReport struct {
	SchemaVersion         uint8        `json:"schema_version"`
	ObservedAt            time.Time    `json:"observed_at"`
	NodeID                string       `json:"node_id"`
	ConfigRevision        uint64       `json:"config_revision"`
	ActiveConfigRevision  uint64       `json:"active_config_revision"`
	AppliedConfigRevision uint64       `json:"applied_config_revision,omitempty"`
	ProbeProtocol         string       `json:"probe_protocol,omitempty"`
	ProbePort             uint16       `json:"probe_port"`
	Healthy               bool         `json:"healthy"`
	ProbeSucceeded        bool         `json:"probe_succeeded"`
	ConsecutiveFailures   uint8        `json:"consecutive_failures"`
	ConsecutiveSuccesses  uint8        `json:"consecutive_successes"`
	ProbesTotal           uint64       `json:"probes_total"`
	ProbeFailuresTotal    uint64       `json:"probe_failures_total"`
	Recovered             bool         `json:"recovered"`
	RecoveryNotified      bool         `json:"recovery_notified"`
	RolledBack            bool         `json:"rolled_back"`
	LoadMetrics           *LoadMetrics `json:"-"`
}

type MetricSink interface {
	ReportNodeMonitoring(context.Context, MetricReport) error
}
