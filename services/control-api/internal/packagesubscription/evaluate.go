package packagesubscription

import (
	"math"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
)

func Evaluate(at time.Time, subscription Subscription, usage Usage,
	current packageperiod.ServiceState,
) (Evaluation, error) {
	if subscription.ID == uuid.Nil || subscription.TenantScopeID == uuid.Nil ||
		subscription.LifecycleStatus != LifecycleActive ||
		!validLimit(subscription.Quotas.Sites) || !validLimit(subscription.Quotas.Domains) ||
		!validLimit(subscription.Quotas.Nodes) ||
		(subscription.Quotas.TrafficBytes != -1 && subscription.Quotas.TrafficBytes < 0) ||
		usage.Sites < 0 || usage.Domains < 0 || usage.Nodes < 0 {
		return Evaluation{}, ErrInvalidInput
	}
	location, err := loadIANAZone(subscription.Period.TimeZone)
	if err != nil {
		return Evaluation{}, ErrInvalidInput
	}
	end := subscription.Period.EndsAt
	validity, err := packageperiod.NewValidity(subscription.Period.StartsAt, location, packageperiod.Terms{EndAt: &end})
	if err != nil || subscription.Period.CyclePolicy.Validate() != nil {
		return Evaluation{}, ErrInvalidInput
	}
	factor, err := packageperiod.NewTrafficFactor(
		subscription.Period.TrafficFactor.Numerator,
		subscription.Period.TrafficFactor.Denominator,
	)
	if err != nil {
		return Evaluation{}, ErrInvalidInput
	}
	weightedTCP, err := factor.Apply(usage.TCPTrafficBytes)
	if err != nil || usage.OtherTrafficBytes > math.MaxUint64-weightedTCP {
		return Evaluation{}, ErrUsageOverflow
	}
	evaluation := Evaluation{
		BilledTraffic:    usage.OtherTrafficBytes + weightedTCP,
		BlockedResources: []string{},
		Warnings:         []QuotaWarning{},
	}
	checkCapacity(&evaluation, ResourceSites, subscription.Quotas.Sites, usage.Sites)
	checkCapacity(&evaluation, ResourceDomains, subscription.Quotas.Domains, usage.Domains)
	checkCapacity(&evaluation, ResourceNodes, subscription.Quotas.Nodes, usage.Nodes)

	var cycle packageperiod.Cycle
	if !at.Before(validity.StartsAt()) && at.Before(validity.EndsAt()) {
		cycle, err = packageperiod.CurrentCycle(subscription.ID.String(), validity, subscription.Period.CyclePolicy, at)
		if err != nil {
			return Evaluation{}, err
		}
		evaluation.ResetKey = cycle.ResetKey()
	}
	trafficExceeded := subscription.Quotas.TrafficBytes != -1 &&
		evaluation.BilledTraffic > uint64(subscription.Quotas.TrafficBytes)
	decision, err := packageperiod.DecideAvailability(at, validity, cycle, trafficExceeded, current)
	if err != nil {
		return Evaluation{}, err
	}
	if decision.Changed {
		evaluation.Intent = intentFromDecision(subscription, decision, evaluation.ResetKey)
	}
	return evaluation, nil
}

func checkCapacity(evaluation *Evaluation, resource string, limit, used int64) {
	if limit == -1 || used <= limit {
		return
	}
	evaluation.BlockedResources = append(evaluation.BlockedResources, resource)
	evaluation.Warnings = append(evaluation.Warnings, QuotaWarning{
		Resource: resource,
		Limit:    uint64(limit),
		Used:     uint64(used),
	})
}

func intentFromDecision(subscription Subscription, decision packageperiod.AvailabilityDecision, cycleResetKey string) *TaskIntent {
	intent := &TaskIntent{
		SubscriptionID: subscription.ID,
		TenantScopeID:  subscription.TenantScopeID,
		ResetKey:       decision.State.ResetKey,
		DesiredEnabled: decision.State.Enabled,
	}
	switch decision.Cause {
	case packageperiod.DecisionExpired:
		intent.Action, intent.Reason = TaskActionSuspend, TaskReasonExpired
	case packageperiod.DecisionQuotaExceeded:
		intent.Action, intent.Reason = TaskActionSuspend, TaskReasonTrafficExceeded
	case packageperiod.DecisionNewCycle:
		intent.Action, intent.Reason = TaskActionRecover, TaskReasonNewCycle
		intent.ResetKey = cycleResetKey
	case packageperiod.DecisionActivated:
		intent.Action, intent.Reason = TaskActionActivate, TaskReasonRenewed
	default:
		return nil
	}
	return intent
}
