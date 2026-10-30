// Package nodednspupprobe adds dnspup checkpoints to node availability
// monitoring: with module.probe.dnspup active, every
// published node IP:port is probed (tcping) from the selected monitoring
// groups' checkpoints at the configured interval. Each probed address and
// round is one availability log row (failed / total checkpoints).
//
// A node's dnspup verdict turns failing after FailureRounds consecutive
// failed rounds (more than FailurePercent of the answering checkpoints
// failed on every probed address). The availability monitor
// (nodeserving.DecideMonitor) removes a node from serving only when the
// local probe and a fresh failing dnspup verdict agree; dnspup failing alone
// only alerts. Without a fresh verdict (interval off, balance exhausted,
// source paused) the local probe decides alone: missing dnspup data never
// marks a node offline.
//
// dnspup meters requests, not checkpoints (one POST /v1/probes = 1, any
// checkpoint count; dnspup persistence consumeCustomerAPIQuotaTx), and its
// account only exposes monthlyLimit / monthlyUsed: the estimate and the
// balance are in requests.
package nodednspupprobe

import (
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
)

// Monitoring groups (same codes as nodeprobe / systemconfig monitor_groups).
const (
	GroupDomestic = "domestic"
	GroupTelecom  = "telecom"
	GroupUnicom   = "unicom"
	GroupMobile   = "mobile"
	GroupOverseas = "overseas"
)

var allGroups = []string{GroupDomestic, GroupTelecom, GroupUnicom, GroupMobile, GroupOverseas}

// Budget states.
const (
	BudgetNormal    = "normal"
	BudgetLow       = "low"
	BudgetExhausted = "exhausted"
)

// LowBudgetFactor stretches the interval while the balance is low.
const LowBudgetFactor = 3

// ErrInvalidSettings answers 422 invalid_input.
var ErrInvalidSettings = dnspupprobe.ErrNodeProbeInvalid

// Settings is the node_dnspup_probe_settings row.
type Settings struct {
	IntervalSeconds int      `json:"interval_seconds"` // 0 off, 60, 300, 900
	Groups          []string `json:"groups"`
	PointsPerGroup  int      `json:"points_per_group"`
	FailurePercent  int      `json:"failure_percent"`
	FailureRounds   int      `json:"failure_rounds"`
	RecoveryRounds  int      `json:"recovery_rounds"`
	LowBalance      int64    `json:"low_balance"`
}

func DefaultSettings() Settings {
	return Settings{IntervalSeconds: 300, Groups: []string{GroupTelecom, GroupUnicom, GroupMobile}, PointsPerGroup: 3,
		FailurePercent: 50, FailureRounds: 3, RecoveryRounds: 1, LowBalance: 1000}
}

func Validate(value Settings) error {
	if !slices.Contains([]int{0, 60, 300, 900}, value.IntervalSeconds) || len(value.Groups) == 0 ||
		len(value.Groups) > len(allGroups) || value.PointsPerGroup < 1 || value.PointsPerGroup > 20 ||
		value.FailurePercent < 1 || value.FailurePercent > 99 || value.FailureRounds < 1 || value.FailureRounds > 10 ||
		value.RecoveryRounds < 1 || value.RecoveryRounds > 10 || value.LowBalance < 0 || value.LowBalance > 1_000_000_000 {
		return ErrInvalidSettings
	}
	seen := map[string]bool{}
	for _, group := range value.Groups {
		if !slices.Contains(allGroups, group) || seen[group] {
			return ErrInvalidSettings
		}
		seen[group] = true
	}
	return nil
}

// Checkpoint is one dnspup checkpoint's answer in the availability log.
type Checkpoint struct {
	ID       string `json:"id"`
	Group    string `json:"group"`
	Carrier  string `json:"carrier,omitempty"`
	Region   string `json:"region,omitempty"`
	Location string `json:"location,omitempty"`
	OK       bool   `json:"ok"`
	Latency  int    `json:"latency_ms,omitempty"`
}

// RoundResult is one probed address in one round.
type RoundResult struct {
	Failed, Total  int
	FailurePercent int
	Checkpoints    []Checkpoint
}

// RoundFailed: more than FailurePercent of the answering checkpoints failed.
func (round RoundResult) RoundFailed() bool {
	return round.Total > 0 && round.Failed*100 > round.FailurePercent*round.Total
}

// CheckpointGroup is the monitoring group a checkpoint votes in: its carrier
// on the mainland, overseas outside it, domestic for a mainland checkpoint
// without a known carrier.
func CheckpointGroup(vote dnspupprobe.Vote) string {
	switch {
	case vote.Region != "" && vote.Region != "cn":
		return GroupOverseas
	case vote.Carrier == GroupTelecom || vote.Carrier == GroupUnicom || vote.Carrier == GroupMobile:
		return vote.Carrier
	case vote.Region == "cn":
		return GroupDomestic
	}
	return ""
}

// Round tallies the answering checkpoints of the selected groups (domestic
// takes every mainland checkpoint).
func Round(results []dnspupprobe.Result, settings Settings) RoundResult {
	round := RoundResult{FailurePercent: settings.FailurePercent}
	if round.FailurePercent <= 0 {
		round.FailurePercent = 50
	}
	votes := dnspupprobe.TCPVotes(results)
	for index, vote := range votes {
		if !vote.Voted {
			continue
		}
		group := CheckpointGroup(vote)
		selected := slices.Contains(settings.Groups, group) ||
			slices.Contains(settings.Groups, GroupDomestic) && (group == GroupTelecom || group == GroupUnicom || group == GroupMobile)
		if group == "" || !selected {
			continue
		}
		round.Total++
		if !vote.OK {
			round.Failed++
		}
		region, _ := marketprobe.Region(results[index].Region)
		round.Checkpoints = append(round.Checkpoints, Checkpoint{ID: vote.NodeID, Group: group, Carrier: vote.Carrier,
			Region: region, Location: results[index].Location, OK: vote.OK, Latency: vote.LatencyMS})
	}
	return round
}

// State is a node's dnspup verdict (node_dnspup_probe_states).
type State struct {
	ConsecutiveFailed int
	ConsecutiveOK     int
	Failing           bool
	ObservedAt        time.Time
}

// Next applies one round: decided=false (no checkpoint answered) keeps the
// state.
func (state State) Next(decided, failed bool, settings Settings, now time.Time) State {
	if !decided {
		return state
	}
	state.ObservedAt = now
	if failed {
		state.ConsecutiveFailed++
		state.ConsecutiveOK = 0
		if state.ConsecutiveFailed >= max(settings.FailureRounds, 1) {
			state.Failing = true
		}
		return state
	}
	state.ConsecutiveOK++
	state.ConsecutiveFailed = 0
	if state.ConsecutiveOK >= max(settings.RecoveryRounds, 1) {
		state.Failing = false
	}
	return state
}

// BudgetFor classifies the remaining monthly dnspup requests (limit 0:
// unlimited).
func BudgetFor(limit, used, lowBalance int64) string {
	if limit <= 0 {
		return BudgetNormal
	}
	remaining := limit - used
	switch {
	case remaining <= 0:
		return BudgetExhausted
	case remaining < lowBalance:
		return BudgetLow
	}
	return BudgetNormal
}

// EffectiveInterval is the probe interval after the budget (0: no probing).
func EffectiveInterval(settings Settings, budget string) time.Duration {
	interval := time.Duration(settings.IntervalSeconds) * time.Second
	switch {
	case interval <= 0 || budget == BudgetExhausted:
		return 0
	case budget == BudgetLow:
		return interval * LowBudgetFactor
	}
	return interval
}

// FreshFor is how long a verdict counts for the availability monitor.
func FreshFor(interval time.Duration) time.Duration { return 2*interval + time.Minute }

// Estimation is the consumption estimate shown next to the balance.
type Estimation struct {
	Addresses           int   `json:"addresses"`
	CheckpointsPerRound int   `json:"checkpoints_per_round"`
	RoundsPerDay        int64 `json:"rounds_per_day"`
	RequestsPerDay      int64 `json:"requests_per_day"`
	RequestsPerMonth    int64 `json:"requests_per_month"`
}

// Estimate: one dnspup request per probed address and round (checkpoints do
// not change the metering); a month is 30 days.
func Estimate(settings Settings, addresses int) Estimation {
	estimate := Estimation{Addresses: addresses, CheckpointsPerRound: settings.PointsPerGroup * len(settings.Groups)}
	if settings.IntervalSeconds > 0 {
		estimate.RoundsPerDay = int64(86400 / settings.IntervalSeconds)
	}
	estimate.RequestsPerDay = estimate.RoundsPerDay * int64(addresses)
	estimate.RequestsPerMonth = estimate.RequestsPerDay * 30
	return estimate
}
