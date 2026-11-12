package nodemonitoring

import (
	"context"
	"math"
)

// StringSetOverBudgetMetrics is one WAF string set the node refused to
// compile because the matchers of an OpenResty worker would exceed the
// 64 MiB memory budget (NodeStringSetOverBudgetV1, NodeTelemetryV1 field 16).
type StringSetOverBudgetMetrics struct {
	SetID         string `json:"set_id"`
	Revision      int64  `json:"revision"`
	Mode          string `json:"mode"`
	Members       uint32 `json:"members"`
	EstimateBytes uint64 `json:"estimate_bytes"`
	LiveBytes     uint64 `json:"live_bytes"`
	BudgetBytes   uint64 `json:"budget_bytes"`
}

// StringSetOverBudgetMax bounds a sample.
const StringSetOverBudgetMax = 256

// SetStringSetOverBudget names the refused string sets now (the site index
// control socket's /status); every load sample with node telemetry carries
// them (none: nothing refused).
func (runtime *Runtime) SetStringSetOverBudget(source func(context.Context) []StringSetOverBudgetMetrics) {
	if source != nil {
		runtime.stringSetOver.Store(source)
	}
}

// validStringSetOverBudget: at most StringSetOverBudgetMax sets, ascending
// by set_id and unique, a non-empty id of at most 64 bytes, a positive
// revision, a known mode, every count within int64.
func validStringSetOverBudget(sets []StringSetOverBudgetMetrics) bool {
	if len(sets) > StringSetOverBudgetMax {
		return false
	}
	previous := ""
	for _, set := range sets {
		if set.SetID == "" || len(set.SetID) > 64 || set.SetID <= previous || set.Revision < 1 ||
			set.Mode == "" || len(set.Mode) > 16 ||
			set.EstimateBytes > math.MaxInt64 || set.LiveBytes > math.MaxInt64 || set.BudgetBytes > math.MaxInt64 {
			return false
		}
		previous = set.SetID
	}
	return true
}
