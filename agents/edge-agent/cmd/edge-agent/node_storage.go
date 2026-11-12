package main

import (
	"context"

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

// stringSetOverBudgetMetrics is the WAF string sets OpenResty refused for the
// worker memory budget (NodeTelemetryV1.string_set_over_budget).
func stringSetOverBudgetMetrics(runtime *dynroute.Runtime) func(context.Context) []nodemonitoring.StringSetOverBudgetMetrics {
	return func(ctx context.Context) []nodemonitoring.StringSetOverBudgetMetrics {
		var sets []nodemonitoring.StringSetOverBudgetMetrics
		for _, set := range runtime.StringSetOverBudget(ctx) {
			sets = append(sets, nodemonitoring.StringSetOverBudgetMetrics{SetID: set.ID, Revision: set.Revision, Mode: set.Mode,
				Members: set.Members, EstimateBytes: set.EstimateBytes, LiveBytes: set.LiveBytes, BudgetBytes: set.BudgetBytes})
		}
		return sets
	}
}
