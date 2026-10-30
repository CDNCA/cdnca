package nodescheduler

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const defaultTelemetryMaxAge = 30 * time.Second

func Decide(plan Plan, request DecisionRequest, loads map[uuid.UUID]LoadSample, now time.Time) (Decision, error) {
	strategy := strings.TrimSpace(request.Strategy)
	stableKey, valid := normalizeStableKey(request.StableKey)
	if strategy == "" {
		strategy = StrategyWeightedBaseline
	}
	if !valid {
		return Decision{}, ErrInvalidInput
	}
	request.StableKey = stableKey
	if len(plan.Candidates) == 0 {
		return Decision{Plan: plan, Strategy: strategy, Reason: ReasonNoHealthyEndpoint}, ErrNoHealthyEndpoint
	}
	if len(plan.Candidates) == 1 {
		if strategy == StrategyWeightedBaseline {
			return Decision{Endpoint: plan.Candidates[0], Plan: plan, Strategy: strategy,
				Reason: ReasonBaselineWeightedSelected}, nil
		}
		return Decision{Endpoint: plan.Candidates[0], Plan: plan, Strategy: strategy,
			Reason: ReasonSingleCandidateFallback, Fallback: true}, nil
	}
	switch strategy {
	case StrategyWeightedBaseline:
		endpoint, err := plan.ChooseKey(request.StableKey)
		return Decision{Endpoint: endpoint, Plan: plan, Strategy: strategy, Reason: ReasonBaselineWeightedSelected}, err
	case StrategyWeightedRendezvous:
		endpoint, err := chooseWeightedRendezvous(plan.Candidates, request.StableKey)
		return Decision{Endpoint: endpoint, Plan: plan, Strategy: strategy, Reason: ReasonWeightedRendezvousSelected}, err
	case StrategyP2CLeastLoaded:
		fallbackReason := ""
		if len(loads) < len(plan.Candidates) {
			fallbackReason = ReasonTelemetryInsufficient
		} else {
			for _, endpoint := range plan.Candidates {
				sample, ok := loads[endpoint.ID]
				if !ok || sample.Inflight < 0 {
					fallbackReason = ReasonTelemetryInsufficient
					break
				}
				if sample.ObservedAt.IsZero() || now.Sub(sample.ObservedAt) < 0 || now.Sub(sample.ObservedAt) > defaultTelemetryMaxAge {
					fallbackReason = ReasonTelemetryStaleFallback
					break
				}
			}
		}
		if fallbackReason != "" {
			endpoint, err := plan.ChooseKey(request.StableKey)
			return Decision{Endpoint: endpoint, Plan: plan, Strategy: strategy, Reason: fallbackReason, Fallback: true}, err
		}
		endpoint, err := chooseP2C(plan.Candidates, request.StableKey, loads)
		return Decision{Endpoint: endpoint, Plan: plan, Strategy: strategy, Reason: ReasonP2CLeastLoadedSelected}, err
	default:
		return Decision{}, ErrInvalidInput
	}
}

func normalizeStableKey(value string) (string, bool) {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 1024 {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, utf8.RuneCountInString(value) >= 1
}

func chooseWeightedRendezvous(candidates []Endpoint, key string) (Endpoint, error) {
	if len(candidates) == 0 {
		return Endpoint{}, ErrNoHealthyEndpoint
	}
	bestScore := math.Inf(1)
	best := Endpoint{}
	for _, endpoint := range candidates {
		if endpoint.Weight < 1 || endpoint.Weight > maxWeight {
			return Endpoint{}, ErrInvalidInput
		}
		digest := sha256.Sum256([]byte("nodescheduler/hrw/v1\x00" + key + "\x00" + endpoint.ID.String()))
		value := binary.BigEndian.Uint64(digest[:8])
		u := (float64(value) + 1) / (float64(^uint64(0)) + 1)
		score := -math.Log(u) / float64(endpoint.Weight)
		if score < bestScore {
			bestScore, best = score, endpoint
		}
	}
	return best, nil
}

func chooseP2C(candidates []Endpoint, key string, loads map[uuid.UUID]LoadSample) (Endpoint, error) {
	if len(candidates) < 2 {
		return Endpoint{}, errors.New("p2c requires at least two candidates")
	}
	first := candidateIndex(candidates, key, "first")
	second := candidateIndex(candidates, key, "second")
	if second == first {
		second = (second + 1) % len(candidates)
	}
	left, right := candidates[first], candidates[second]
	leftScore := float64(loads[left.ID].Inflight+1) / float64(left.Weight)
	rightScore := float64(loads[right.ID].Inflight+1) / float64(right.Weight)
	if rightScore < leftScore || rightScore == leftScore && right.ID.String() < left.ID.String() {
		return right, nil
	}
	return left, nil
}

func candidateIndex(candidates []Endpoint, key, domain string) int {
	digest := sha256.Sum256([]byte("nodescheduler/p2c/v1\x00" + domain + "\x00" + key))
	return int(binary.BigEndian.Uint64(digest[:8]) % uint64(len(candidates)))
}
