package dnspupprobe

import "time"

// Purposes (probe_dnspup_purposes rows): every charged dnspup job is counted
// under one of them; smart scheduling reads the node availability rows and
// has no purpose of its own.
const (
	PurposeNodeAvailability = "node_availability"
	PurposeOriginFailover   = "origin_failover"
	PurposeEdgeHealth       = "edge_health"
	PurposePlugin           = "plugin"
	PurposeDiagnose         = "diagnose"
)

// Priority classes: when the account cannot cover the month, report is
// slowed (then stopped) first, then schedule; availability is never stopped
// here (node probing keeps its own low / exhausted handling).
const (
	ClassAvailability = 1
	ClassSchedule     = 2
	ClassReport       = 3
)

// DegradeFactor stretches a slowed purpose's interval.
const DegradeFactor = 3

// PurposeClasses is the fixed class of each purpose.
var PurposeClasses = map[string]int{
	PurposeNodeAvailability: ClassAvailability, PurposeOriginFailover: ClassAvailability,
	PurposeEdgeHealth: ClassSchedule, PurposePlugin: ClassSchedule, PurposeDiagnose: ClassReport,
}

// ConsumerPurposes maps a Prober consumer to the purpose it is metered under.
var ConsumerPurposes = map[string]string{
	ConsumerNode: PurposeNodeAvailability, ConsumerOrigin: PurposeOriginFailover, ConsumerEdge: PurposeEdgeHealth,
	ConsumerPlugin: PurposePlugin, ConsumerDiagnose: PurposeDiagnose,
}

// Purpose is one purpose's settings and this month's usage.
type Purpose struct {
	Name       string
	Class      int
	Enabled    bool
	MonthlyCap int64 // 0: no cap
	Used       int64
}

// Gate is what a purpose may do now.
type Gate struct {
	Stopped bool   `json:"stopped"`
	Factor  int    `json:"factor"`           // interval multiplier (1: normal)
	Reason  string `json:"reason,omitempty"` // disabled / monthly_cap / account_budget / account_slowdown
	// DailyAverage and ProjectedMonthly are the page's usage estimate.
	DailyAverage     int64 `json:"daily_average"`
	ProjectedMonthly int64 `json:"projected_monthly"`
}

// PlanBudget decides every purpose's gate for now. limit 0 is an unlimited
// account; used is the account's monthly use (all purposes and anything else
// using the key). Usage so far is extrapolated per day (at least one day
// elapsed).
func PlanBudget(purposes []Purpose, limit, used int64, now time.Time) map[string]Gate {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	days := int64(start.AddDate(0, 1, 0).Sub(start) / (24 * time.Hour))
	elapsed := max(int64(now.Sub(start)/(24*time.Hour)), 1)
	left := max(days-elapsed, 0)
	plan := make(map[string]Gate, len(purposes))
	need := map[int]int64{}
	for _, purpose := range purposes {
		gate := Gate{Factor: 1, DailyAverage: purpose.Used / elapsed}
		gate.ProjectedMonthly = purpose.Used + gate.DailyAverage*left
		switch {
		case !purpose.Enabled:
			gate.Stopped, gate.Reason = true, "disabled"
		case purpose.MonthlyCap > 0 && purpose.Used >= purpose.MonthlyCap:
			gate.Stopped, gate.Reason = true, "monthly_cap"
		default:
			need[purpose.Class] += gate.DailyAverage * left
		}
		plan[purpose.Name] = gate
	}
	if limit <= 0 {
		return plan
	}
	remaining := max(limit-used, 0)
	total := need[ClassAvailability] + need[ClassSchedule] + need[ClassReport]
	for _, class := range []int{ClassReport, ClassSchedule} {
		if total <= remaining {
			break
		}
		slowed := need[class] / DegradeFactor
		reason, factor, stop := "account_slowdown", DegradeFactor, false
		if total-need[class]+slowed > remaining {
			reason, stop, slowed = "account_budget", true, 0
		}
		total += slowed - need[class]
		for _, purpose := range purposes {
			gate := plan[purpose.Name]
			if purpose.Class != class || gate.Stopped {
				continue
			}
			gate.Reason, gate.Factor, gate.Stopped = reason, factor, stop
			plan[purpose.Name] = gate
		}
	}
	return plan
}
