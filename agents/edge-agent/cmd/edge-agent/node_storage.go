package main

import (
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
)

// storageMetrics is the node storage in effect for node telemetry
// (NODE_STORAGE v1, NodeTelemetryV1.storage).
func storageMetrics(runtime *dynroute.Runtime) func() *nodemonitoring.StorageMetrics {
	return func() *nodemonitoring.StorageMetrics {
		status := runtime.StorageStatus()
		return &nodemonitoring.StorageMetrics{CacheDirectory: status.CacheDirectory, CacheMaxBytes: uint64(max(status.CacheMaxBytes, 0)),
			LogDirectory: status.LogDirectory, State: status.State, Reason: status.Reason,
			RequestedLogDirectory: status.RequestedLogDirectory}
	}
}
