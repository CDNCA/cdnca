package packagesubscription

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
)

var (
	ErrEnforcementInvalidInput     = errors.New("invalid package cycle enforcement input")
	ErrEnforcementEvidenceConflict = errors.New("package cycle enforcement evidence conflict")
)

type EnforcementStatus string

const (
	EnforcementUnknown   EnforcementStatus = "unknown"
	EnforcementActive    EnforcementStatus = "active"
	EnforcementSuspended EnforcementStatus = "suspended"
)

type EnforcementReason string

const (
	EnforcementTrafficExceeded       EnforcementReason = "traffic_exceeded"
	EnforcementBandwidthExceeded     EnforcementReason = "bandwidth_exceeded"
	EnforcementConnectionsExceeded   EnforcementReason = "connections_exceeded"
	EnforcementSitesExceeded         EnforcementReason = "sites_exceeded"
	EnforcementManualOverride        EnforcementReason = "manual_override"
	EnforcementDependencyUnavailable EnforcementReason = "dependency_unavailable"
)

type EnforcementTransition string

const (
	EnforcementNoChange     EnforcementTransition = ""
	EnforcementSuspendedNow EnforcementTransition = "suspended"
	EnforcementRecovered    EnforcementTransition = "recovered"
)

const (
	SuccessorExistingTraffic = "existing_traffic"
	SuccessorCreate          = "create"
	SuccessorExpand          = "expand"
)

type EnforcementMetric string

const (
	EnforcementMetricTraffic     EnforcementMetric = "traffic_bytes"
	EnforcementMetricBandwidth   EnforcementMetric = "bandwidth_bps"
	EnforcementMetricConnections EnforcementMetric = "connections"
	EnforcementMetricSites       EnforcementMetric = "sites"
)

type AdjustmentKind string

const (
	AdjustmentCredit   AdjustmentKind = "credit"
	AdjustmentReversal AdjustmentKind = "reversal"
)

type OverrideMode string

const (
	OverrideKeepActive   OverrideMode = "keep_active"
	OverrideForceSuspend OverrideMode = "force_suspend"
)

type EnforcementLimits struct {
	TrafficBytes uint64
	BandwidthBPS uint64
	Connections  uint64
	Sites        int64
}

type EnforcementUsage struct {
	TrafficBytes uint64
	BandwidthBPS uint64
	Connections  uint64
	Sites        int64
}

type UsageAdjustment struct {
	ID         string
	ReversesID string
	PeriodKey  string
	Metric     EnforcementMetric
	Kind       AdjustmentKind
	Amount     uint64
}

type EnforcementOverride struct {
	PeriodKey string
	Mode      OverrideMode
	Revision  uint64
}

type EnforcementInput struct {
	At           time.Time
	Subscription Subscription
	Limits       EnforcementLimits
	Usage        EnforcementUsage
	Adjustments  []UsageAdjustment
	Override     *EnforcementOverride
	EvidenceID   string
}

type EnforcementState struct {
	SubscriptionID uuid.UUID
	TenantScopeID  uuid.UUID
	PeriodKey      string
	CycleStartsAt  time.Time
	CycleEndsAt    time.Time
	Status         EnforcementStatus
	Reason         EnforcementReason
	Revision       uint64
	EvidenceID     string
	EvidenceDigest [sha256.Size]byte
	DecisionDigest [sha256.Size]byte
	LKGStatus      EnforcementStatus
	LKGReason      EnforcementReason
}

type EnforcementDecision struct {
	State             EnforcementState
	Transition        EnforcementTransition
	EffectiveUsage    EnforcementUsage
	BlockedOperations []string
	EdgeAction        string
}

func DecideCycleEnforcement(input EnforcementInput, current *EnforcementState) (EnforcementDecision, error) {
	cycle, err := enforcementCycle(input)
	if err != nil {
		return EnforcementDecision{}, err
	}
	normalized, err := normalizeEnforcementInput(input, cycle.ResetKey())
	if err != nil {
		return EnforcementDecision{}, err
	}
	evidenceDigest, err := enforcementEvidenceDigest(normalized)
	if err != nil {
		return EnforcementDecision{}, ErrEnforcementInvalidInput
	}
	if current != nil && current.EvidenceID == input.EvidenceID {
		if current.EvidenceDigest != evidenceDigest {
			return EnforcementDecision{}, ErrEnforcementEvidenceConflict
		}
		return decisionFromState(*current, normalized.Usage, EnforcementNoChange), nil
	}

	effective, err := effectiveEnforcementUsage(normalized.Usage, normalized.Adjustments, cycle.ResetKey())
	if err != nil {
		return EnforcementDecision{}, err
	}
	status, reason := automaticEnforcementStatus(normalized.Limits, effective)
	if normalized.Override != nil && normalized.Override.PeriodKey == cycle.ResetKey() {
		reason = EnforcementManualOverride
		if normalized.Override.Mode == OverrideKeepActive {
			status = EnforcementActive
		} else {
			status = EnforcementSuspended
		}
	}
	revision := uint64(1)
	transition := EnforcementNoChange
	if current != nil {
		revision = current.Revision + 1
		if current.Status == EnforcementSuspended && status == EnforcementActive {
			transition = EnforcementRecovered
		} else if current.Status != EnforcementSuspended && status == EnforcementSuspended {
			transition = EnforcementSuspendedNow
		}
	} else if status == EnforcementSuspended {
		transition = EnforcementSuspendedNow
	}
	state := EnforcementState{
		SubscriptionID: input.Subscription.ID, TenantScopeID: input.Subscription.TenantScopeID,
		PeriodKey: cycle.ResetKey(), CycleStartsAt: cycle.StartsAt(), CycleEndsAt: cycle.EndsAt(),
		Status: status, Reason: reason, Revision: revision, EvidenceID: input.EvidenceID,
		EvidenceDigest: evidenceDigest, LKGStatus: status, LKGReason: reason,
	}
	state.DecisionDigest = enforcementDecisionDigest(state)
	return decisionFromState(state, effective, transition), nil
}

func enforcementCycle(input EnforcementInput) (packageperiod.Cycle, error) {
	subscription := input.Subscription
	if input.At.IsZero() || subscription.ID == uuid.Nil || subscription.TenantScopeID == uuid.Nil ||
		subscription.LifecycleStatus != LifecycleActive || input.Usage.Sites < 0 || input.Limits.Sites < 0 ||
		!validEnforcementPart(input.EvidenceID) {
		return packageperiod.Cycle{}, ErrEnforcementInvalidInput
	}
	location, err := time.LoadLocation(subscription.Period.TimeZone)
	if err != nil {
		return packageperiod.Cycle{}, ErrEnforcementInvalidInput
	}
	end := subscription.Period.EndsAt
	validity, err := packageperiod.NewValidity(subscription.Period.StartsAt, location, packageperiod.Terms{EndAt: &end})
	if err != nil {
		return packageperiod.Cycle{}, ErrEnforcementInvalidInput
	}
	cycle, err := packageperiod.CurrentCycle(subscription.ID.String(), validity, subscription.Period.CyclePolicy, input.At)
	if err != nil {
		return packageperiod.Cycle{}, err
	}
	return cycle, nil
}

// EnforcementCycle is the cycle DecideCycleEnforcement evaluates for subscription at at.
func EnforcementCycle(subscription Subscription, at time.Time) (packageperiod.Cycle, error) {
	return enforcementCycle(EnforcementInput{At: at, Subscription: subscription, EvidenceID: "cycle"})
}

func normalizeEnforcementInput(input EnforcementInput, periodKey string) (EnforcementInput, error) {
	result := input
	result.At = input.At.UTC()
	result.Adjustments = append([]UsageAdjustment(nil), input.Adjustments...)
	sort.Slice(result.Adjustments, func(left, right int) bool {
		return result.Adjustments[left].ID < result.Adjustments[right].ID
	})
	seen := make(map[string]struct{}, len(result.Adjustments))
	for _, adjustment := range result.Adjustments {
		if !validEnforcementPart(adjustment.ID) || !validEnforcementPart(adjustment.PeriodKey) ||
			!validEnforcementMetric(adjustment.Metric) || adjustment.Amount == 0 ||
			(adjustment.Kind != AdjustmentCredit && adjustment.Kind != AdjustmentReversal) {
			return EnforcementInput{}, ErrEnforcementInvalidInput
		}
		if _, exists := seen[adjustment.ID]; exists {
			return EnforcementInput{}, ErrEnforcementInvalidInput
		}
		seen[adjustment.ID] = struct{}{}
		if adjustment.Kind == AdjustmentCredit && adjustment.ReversesID != "" ||
			adjustment.Kind == AdjustmentReversal && !validEnforcementPart(adjustment.ReversesID) {
			return EnforcementInput{}, ErrEnforcementInvalidInput
		}
	}
	if result.Override != nil {
		copy := *result.Override
		result.Override = &copy
		if !validEnforcementPart(copy.PeriodKey) || copy.Revision == 0 ||
			(copy.Mode != OverrideKeepActive && copy.Mode != OverrideForceSuspend) {
			return EnforcementInput{}, ErrEnforcementInvalidInput
		}
	}
	_ = periodKey
	return result, nil
}

func effectiveEnforcementUsage(usage EnforcementUsage, adjustments []UsageAdjustment, periodKey string) (EnforcementUsage, error) {
	credits := make(map[string]UsageAdjustment)
	reversed := make(map[string]struct{})
	for _, adjustment := range adjustments {
		if adjustment.PeriodKey != periodKey {
			continue
		}
		if adjustment.Kind == AdjustmentCredit {
			credits[adjustment.ID] = adjustment
		}
	}
	for _, adjustment := range adjustments {
		if adjustment.PeriodKey != periodKey || adjustment.Kind != AdjustmentReversal {
			continue
		}
		credit, exists := credits[adjustment.ReversesID]
		if !exists || credit.Metric != adjustment.Metric || credit.Amount != adjustment.Amount {
			return EnforcementUsage{}, ErrEnforcementInvalidInput
		}
		reversed[credit.ID] = struct{}{}
	}
	result := usage
	for id, credit := range credits {
		if _, exists := reversed[id]; exists {
			continue
		}
		switch credit.Metric {
		case EnforcementMetricTraffic:
			result.TrafficBytes = subtractFloor(result.TrafficBytes, credit.Amount)
		case EnforcementMetricBandwidth:
			result.BandwidthBPS = subtractFloor(result.BandwidthBPS, credit.Amount)
		case EnforcementMetricConnections:
			result.Connections = subtractFloor(result.Connections, credit.Amount)
		case EnforcementMetricSites:
			if credit.Amount > math.MaxInt64 {
				return EnforcementUsage{}, ErrEnforcementInvalidInput
			}
			result.Sites -= minInt64(result.Sites, int64(credit.Amount))
		}
	}
	return result, nil
}

func automaticEnforcementStatus(limits EnforcementLimits, usage EnforcementUsage) (EnforcementStatus, EnforcementReason) {
	switch {
	case usage.TrafficBytes > limits.TrafficBytes:
		return EnforcementSuspended, EnforcementTrafficExceeded
	case usage.BandwidthBPS > limits.BandwidthBPS:
		return EnforcementSuspended, EnforcementBandwidthExceeded
	case usage.Connections > limits.Connections:
		return EnforcementSuspended, EnforcementConnectionsExceeded
	case usage.Sites > limits.Sites:
		return EnforcementSuspended, EnforcementSitesExceeded
	default:
		return EnforcementActive, ""
	}
}

func decisionFromState(state EnforcementState, usage EnforcementUsage, transition EnforcementTransition) EnforcementDecision {
	decision := EnforcementDecision{State: state, Transition: transition, EffectiveUsage: usage}
	if state.Status == EnforcementSuspended {
		decision.BlockedOperations = []string{SuccessorCreate, SuccessorExpand}
	}
	return decision
}

func enforcementEvidenceDigest(input EnforcementInput) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func enforcementDecisionDigest(state EnforcementState) [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		Schema         string
		SubscriptionID uuid.UUID
		TenantScopeID  uuid.UUID
		PeriodKey      string
		Status         EnforcementStatus
		Reason         EnforcementReason
		EvidenceDigest [sha256.Size]byte
	}{
		Schema: "package-cycle-enforcement-decision/v1", SubscriptionID: state.SubscriptionID,
		TenantScopeID: state.TenantScopeID, PeriodKey: state.PeriodKey, Status: state.Status,
		Reason: state.Reason, EvidenceDigest: state.EvidenceDigest,
	})
	return sha256.Sum256(encoded)
}

func validEnforcementPart(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value
}

func validEnforcementMetric(metric EnforcementMetric) bool {
	return metric == EnforcementMetricTraffic || metric == EnforcementMetricBandwidth ||
		metric == EnforcementMetricConnections || metric == EnforcementMetricSites
}

func subtractFloor(value, amount uint64) uint64 {
	if amount >= value {
		return 0
	}
	return value - amount
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
