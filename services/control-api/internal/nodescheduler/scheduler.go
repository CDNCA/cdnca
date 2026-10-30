package nodescheduler

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"
)

func BuildPlan(group LineGroupRevision, selector Selector, now time.Time) (Plan, error) {
	if now.IsZero() {
		return Plan{}, ErrInvalidInput
	}
	region, ok := normalizeLabel(selector.Region, 0, 64)
	if !ok {
		return Plan{}, ErrInvalidInput
	}
	carrier, ok := normalizeLabel(selector.Carrier, 0, 64)
	if !ok {
		return Plan{}, ErrInvalidInput
	}
	selector = Selector{Region: region, Carrier: carrier}
	now = now.UTC().Truncate(time.Microsecond)
	plan := Plan{
		TenantScopeID: group.TenantScopeID, GroupID: group.GroupID, Revision: group.Revision,
		ConfigurationDigest: slices.Clone(group.ConfigurationDigest), Selector: selector, EvaluatedAt: now,
	}

	endpoints := slices.Clone(group.Endpoints)
	for index := range endpoints {
		endpoints[index].DisplayID = ""
	}
	slices.SortFunc(endpoints, compareEndpoint)
	eligible := make([]Endpoint, 0, len(endpoints))
	specificities := make(map[uuid.UUID]int, len(endpoints))
	bestSpecificity := -1
	for _, endpoint := range endpoints {
		evaluation := EndpointEvaluation{Endpoint: endpoint}
		if !endpoint.Enabled {
			evaluation.Disposition = EndpointDispositionDisabled
			plan.Evaluations = append(plan.Evaluations, evaluation)
			continue
		}
		specificity, matches := selectorSpecificity(endpoint, selector)
		if !matches {
			evaluation.Disposition = EndpointDispositionSelectorMismatch
			plan.Evaluations = append(plan.Evaluations, evaluation)
			continue
		}
		specificities[endpoint.ID] = specificity
		evaluation.Disposition = endpointHealthDisposition(endpoint.Health, group.Policy, now)
		plan.Evaluations = append(plan.Evaluations, evaluation)
		if evaluation.Disposition != EndpointDispositionCandidate {
			continue
		}
		if specificity > bestSpecificity {
			eligible = eligible[:0]
			bestSpecificity = specificity
		}
		if specificity == bestSpecificity {
			eligible = append(eligible, endpoint)
		}
	}
	for index := range plan.Evaluations {
		evaluation := &plan.Evaluations[index]
		if evaluation.Disposition == EndpointDispositionCandidate &&
			specificities[evaluation.Endpoint.ID] < bestSpecificity {
			evaluation.Disposition = EndpointDispositionLessSpecific
		}
	}
	if len(eligible) == 0 {
		plan.TierReason = ReasonNoHealthyEndpoint
		return sealPlan(plan)
	}
	slices.SortFunc(eligible, compareEndpoint)
	priority := eligible[0].Priority
	cut := 0
	for cut < len(eligible) && eligible[cut].Priority == priority {
		cut++
	}
	plan.Priority = priority
	plan.Candidates = slices.Clone(eligible[:cut])
	plan.Standby = slices.Clone(eligible[cut:])
	primaryPriority := maxPriority + 1
	for _, endpoint := range endpoints {
		specificity, matched := specificities[endpoint.ID]
		if !endpoint.Enabled || !matched || specificity != bestSpecificity {
			continue
		}
		primaryPriority = min(primaryPriority, endpoint.Priority)
	}
	plan.TierReason = ReasonPrimaryPrioritySelected
	if priority > primaryPriority {
		plan.TierReason = ReasonBackupPrioritySelected
	}
	candidates := make(map[uuid.UUID]struct{}, len(plan.Candidates))
	standby := make(map[uuid.UUID]struct{}, len(plan.Standby))
	for _, endpoint := range plan.Candidates {
		candidates[endpoint.ID] = struct{}{}
	}
	for _, endpoint := range plan.Standby {
		standby[endpoint.ID] = struct{}{}
	}
	for index := range plan.Evaluations {
		evaluation := &plan.Evaluations[index]
		if _, ok := candidates[evaluation.Endpoint.ID]; ok {
			evaluation.Disposition = EndpointDispositionCandidate
		} else if _, ok := standby[evaluation.Endpoint.ID]; ok {
			evaluation.Disposition = EndpointDispositionStandby
		}
	}
	return sealPlan(plan)
}

func sealPlan(plan Plan) (Plan, error) {
	encoded, err := json.Marshal(struct {
		TenantScopeID       string               `json:"tenant_scope_id"`
		GroupID             string               `json:"group_id"`
		Revision            int64                `json:"revision"`
		ConfigurationDigest string               `json:"configuration_digest"`
		Selector            Selector             `json:"selector"`
		EvaluatedAt         string               `json:"evaluated_at"`
		Priority            int                  `json:"priority"`
		TierReason          string               `json:"tier_reason"`
		Candidates          []canonicalEndpoint  `json:"candidates"`
		Standby             []canonicalEndpoint  `json:"standby"`
		Evaluations         []EndpointEvaluation `json:"evaluations"`
	}{
		plan.TenantScopeID.String(), plan.GroupID.String(), plan.Revision,
		hex.EncodeToString(plan.ConfigurationDigest), plan.Selector,
		plan.EvaluatedAt.Format(time.RFC3339Nano), plan.Priority, plan.TierReason,
		canonicalizeEndpoints(plan.Candidates), canonicalizeEndpoints(plan.Standby), plan.Evaluations,
	})
	if err != nil {
		return Plan{}, err
	}
	plan.Digest = sha256.Sum256(encoded)
	if len(plan.Candidates) == 0 {
		return plan, ErrNoHealthyEndpoint
	}
	return plan, nil
}

func endpointHealthDisposition(health HealthState, policy HealthPolicy, now time.Time) string {
	if health.Status == HealthUnknown {
		return EndpointDispositionUnknown
	}
	if health.Status != HealthHealthy {
		return EndpointDispositionUnhealthy
	}
	if health.LastReceivedAt == nil {
		return EndpointDispositionStale
	}
	deadline := health.LastReceivedAt.Add(
		time.Duration(policy.FailureThreshold)*policy.ProbeInterval +
			policy.ProbeTimeout + policy.FailureDebounce,
	)
	if !now.Before(deadline) {
		return EndpointDispositionStale
	}
	return EndpointDispositionCandidate
}

func (plan Plan) ChooseWeighted(sample uint64) (Endpoint, error) {
	if len(plan.Candidates) == 0 {
		return Endpoint{}, ErrNoHealthyEndpoint
	}
	if len(plan.Candidates) > maxEndpoints {
		return Endpoint{}, ErrInvalidInput
	}
	var total uint64
	for _, endpoint := range plan.Candidates {
		if endpoint.Weight < 1 || endpoint.Weight > maxWeight {
			return Endpoint{}, ErrInvalidInput
		}
		total += uint64(endpoint.Weight)
	}
	position := sample % total
	for _, endpoint := range plan.Candidates {
		weight := uint64(endpoint.Weight)
		if position < weight {
			return endpoint, nil
		}
		position -= weight
	}
	return Endpoint{}, ErrInvalidInput
}

func (plan Plan) ChooseKey(key string) (Endpoint, error) {
	digest := sha256.Sum256([]byte(key))
	return plan.ChooseWeighted(binary.BigEndian.Uint64(digest[:8]))
}

func selectorSpecificity(endpoint Endpoint, selector Selector) (int, bool) {
	specificity := 0
	if endpoint.Region != "" {
		if selector.Region == "" || endpoint.Region != selector.Region {
			return 0, false
		}
		specificity++
	}
	if endpoint.Carrier != "" {
		if selector.Carrier == "" || endpoint.Carrier != selector.Carrier {
			return 0, false
		}
		specificity++
	}
	return specificity, true
}
