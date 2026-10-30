package originroute

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

func Canonical(policy Policy) ([]byte, error) {
	normalized, err := Normalize(policy)
	if err != nil {
		return nil, err
	}
	value, err := json.Marshal(normalized)
	if err != nil {
		return nil, invalid("encode canonical policy: %v", err)
	}
	return value, nil
}

func CanonicalDigest(policy Policy) (string, error) {
	value, err := Canonical(policy)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:]), nil
}

func Match(policy Policy, facts RequestFacts) (Decision, error) {
	value, err := Normalize(policy)
	if err != nil {
		return Decision{}, err
	}
	if _, err := listenerByID(value, facts.ListenerID); err != nil {
		return Decision{}, err
	}
	path, err := normalizeRequestPath(facts.Path)
	if err != nil {
		return Decision{}, err
	}
	region := strings.ToLower(facts.NodeRegion)
	if region == "" {
		region = value.Node.Region
	}
	if !validRegion(region) {
		return Decision{}, invalid("request region is invalid")
	}
	clientIP, err := netip.ParseAddr(facts.ClientIP)
	if err != nil || clientIP.Is4In6() || clientIP.Zone() != "" {
		return Decision{}, invalid("request client IP is invalid")
	}
	for _, route := range value.Routes {
		if !routeMatches(route, path, region, clientIP) {
			continue
		}
		decision := Decision{
			RouteID: route.ID, PoolID: route.PoolID, FallbackPoolID: route.FallbackPoolID,
			Explanation: fmt.Sprintf("route=%s priority=%d path_specificity=%d region=%t cidr_bits=%d",
				route.ID, route.Priority, len(route.PathPrefix), len(route.NodeRegions) > 0,
				maxPrefixBits(route.ClientCIDRs)),
		}
		return applyHopGuard(value, facts.HopCount, decision)
	}
	decision := Decision{
		PoolID: value.DefaultPoolID, FallbackPoolID: value.DefaultFallbackPoolID,
		Defaulted: true, Explanation: "default_pool",
	}
	return applyHopGuard(value, facts.HopCount, decision)
}

func PlanRetry(policy RetryPolicy, state AttemptState) RetryDecision {
	budget := time.Duration(policy.TotalBudgetMS) * time.Millisecond
	remaining := budget - state.Elapsed
	if remaining <= 0 {
		return stoppedRetry(0, ReasonTotalBudgetExhausted)
	}
	if state.ResponseStarted {
		return stoppedRetry(remaining, ReasonResponseAlreadyStarted)
	}
	if state.StreamingBody || state.HasRequestBody {
		return stoppedRetry(remaining, ReasonRequestBodyNotReplayable)
	}
	method := strings.ToUpper(state.Method)
	if !containsString(policy.Methods, method) {
		return stoppedRetry(remaining, ReasonMethodNotRetryable)
	}
	if state.Attempt >= policy.MaxAttempts {
		return stoppedRetry(remaining, ReasonAttemptLimitReached)
	}
	switch state.Failure {
	case "connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504":
		return RetryDecision{
			Retry: true, Remaining: remaining, ResultCode: ResultCodeRetry,
			Reason: ReasonRetryableUpstreamFailure,
		}
	default:
		return stoppedRetry(remaining, ReasonFailureNotRetryable)
	}
}

func stoppedRetry(remaining time.Duration, reason string) RetryDecision {
	return RetryDecision{Remaining: remaining, ResultCode: ResultCodeStop, Reason: reason}
}

func PlanL2Fallback(policy Policy, decision Decision, state L2FallbackState) L2FallbackDecision {
	remaining := time.Duration(policy.Retry.TotalBudgetMS)*time.Millisecond - state.Attempt.Elapsed
	if remaining < 0 {
		remaining = 0
	}
	if poolByID(policy, decision.PoolID).Kind != PoolL2 {
		return stoppedL2Fallback(remaining, ReasonL2NotSelected)
	}
	if poolByID(policy, decision.FallbackPoolID).Kind != PoolOrigin {
		return stoppedL2Fallback(remaining, ReasonDirectOriginRequired)
	}
	if state.DirectOriginAttempted {
		return stoppedL2Fallback(remaining, ReasonDirectOriginAttemptLimit)
	}
	retry := PlanRetry(policy.Retry, state.Attempt)
	if !retry.Retry {
		return stoppedL2Fallback(retry.Remaining, retry.Reason)
	}
	return L2FallbackDecision{
		Fallback: true, PoolID: decision.FallbackPoolID, Remaining: retry.Remaining,
		ResultCode: ResultCodeDirectOriginFallback, ReasonCode: ReasonL2RetryableFailure,
	}
}

func stoppedL2Fallback(remaining time.Duration, reason string) L2FallbackDecision {
	return L2FallbackDecision{Remaining: remaining, ResultCode: ResultCodeStop, ReasonCode: reason}
}

func PlanL2Attempt(policy L2Policy, state CircuitState, now time.Time) L2AttemptDecision {
	switch state.Phase {
	case "", CircuitClosed:
		state.Phase = CircuitClosed
		state.ProbeInFlight = false
		return L2AttemptDecision{
			State: state, Allowed: true, ResultCode: ResultCodeL2Attempt, ReasonCode: ReasonCircuitClosed,
		}
	case CircuitOpen:
		if !now.Before(state.ProbeAfter) {
			state.Phase = CircuitHalfOpen
			state.ConsecutiveSuccesses = 0
			state.ProbeInFlight = true
			return L2AttemptDecision{
				State: state, Allowed: true, Probe: true,
				ResultCode: ResultCodeL2Attempt, ReasonCode: ReasonHalfOpenProbe,
			}
		}
		return L2AttemptDecision{
			State: state, ResultCode: ResultCodeDirectOriginFallback, ReasonCode: ReasonCircuitOpen,
		}
	case CircuitHalfOpen:
		if state.ProbeInFlight {
			return L2AttemptDecision{
				State: state, ResultCode: ResultCodeDirectOriginFallback,
				ReasonCode: ReasonHalfOpenProbeInFlight,
			}
		}
		state.ProbeInFlight = true
		return L2AttemptDecision{
			State: state, Allowed: true, Probe: true,
			ResultCode: ResultCodeL2Attempt, ReasonCode: ReasonHalfOpenProbe,
		}
	default:
		return L2AttemptDecision{
			State: CircuitState{
				Phase:      CircuitOpen,
				ProbeAfter: now.Add(time.Duration(policy.ProbeIntervalMS) * time.Millisecond),
			},
			ResultCode: ResultCodeDirectOriginFallback, ReasonCode: ReasonCircuitStateInvalid,
		}
	}
}

func AllowL2(policy L2Policy, state CircuitState, now time.Time) (CircuitState, bool) {
	decision := PlanL2Attempt(policy, state, now)
	return decision.State, decision.Allowed
}

func ObserveL2(policy L2Policy, state CircuitState, success bool, now time.Time) CircuitState {
	if state.Phase == "" {
		state.Phase = CircuitClosed
	}
	state.ProbeInFlight = false
	if success {
		state.ConsecutiveFailures = 0
		if state.Phase == CircuitHalfOpen {
			state.ConsecutiveSuccesses++
			if state.ConsecutiveSuccesses >= policy.RecoveryThreshold {
				return CircuitState{Phase: CircuitClosed}
			}
			return state
		}
		state.ConsecutiveSuccesses = 0
		return state
	}
	state.ConsecutiveSuccesses = 0
	state.ConsecutiveFailures++
	if state.Phase == CircuitHalfOpen || state.ConsecutiveFailures >= policy.FailureThreshold {
		state.Phase = CircuitOpen
		state.ProbeAfter = now.Add(time.Duration(policy.ProbeIntervalMS) * time.Millisecond)
	}
	return state
}

type AddressInspector interface {
	HasAddress(context.Context, netip.Addr) (bool, error)
}

type SystemAddressInspector struct{}

func (SystemAddressInspector) HasAddress(_ context.Context, expected netip.Addr) (bool, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}
	for _, item := range addresses {
		prefix, err := netip.ParsePrefix(item.String())
		if err == nil && prefix.Addr().Unmap() == expected {
			return true, nil
		}
	}
	return false, nil
}

func ValidateLocalBindings(ctx context.Context, policy Policy, inspector AddressInspector) error {
	if inspector == nil {
		return invalid("address inspector is required")
	}
	value, err := Normalize(policy)
	if err != nil {
		return err
	}
	seen := make(map[netip.Addr]struct{})
	for _, listener := range value.Listeners {
		for _, raw := range []string{listener.IngressSourceIPv4, listener.IngressSourceIPv6} {
			if raw == "" {
				continue
			}
			address := netip.MustParseAddr(raw)
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			present, err := inspector.HasAddress(ctx, address)
			if err != nil {
				return fmt.Errorf("inspect local source address: %w", err)
			}
			if !present {
				return invalid("ingress source address %s is not assigned to this node", address)
			}
		}
	}
	return nil
}

func listenerByID(policy Policy, id string) (Listener, error) {
	for _, listener := range policy.Listeners {
		if listener.ID == id {
			return listener, nil
		}
	}
	return Listener{}, invalid("listener_id does not exist")
}

func applyHopGuard(policy Policy, hop uint8, decision Decision) (Decision, error) {
	pool := poolByID(policy, decision.PoolID)
	if pool.Kind != PoolL2 || hop < policy.L2.MaxHops {
		return decision, nil
	}
	if decision.FallbackPoolID == "" {
		return Decision{}, ErrNoRoute
	}
	decision.PoolID = decision.FallbackPoolID
	decision.FallbackPoolID = ""
	decision.Explanation += " loop_guard=direct_origin"
	return decision, nil
}

func poolByID(policy Policy, id string) Pool {
	for _, pool := range policy.Pools {
		if pool.ID == id {
			return pool
		}
	}
	return Pool{}
}

func routeMatches(route Route, path, region string, clientIP netip.Addr) bool {
	if route.PathPrefix != "" && !pathPrefixMatches(route.PathPrefix, path) {
		return false
	}
	if len(route.NodeRegions) > 0 && !containsString(route.NodeRegions, region) {
		return false
	}
	if len(route.ClientCIDRs) > 0 {
		matched := false
		for _, raw := range route.ClientCIDRs {
			prefix := netip.MustParsePrefix(raw)
			if prefix.Contains(clientIP) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func normalizeRequestPath(value string) (string, error) {
	if value == "" || value[0] != '/' || len(value) > 8192 || strings.ContainsAny(value, "\x00\r\n") {
		return "", invalid("request path is invalid")
	}
	return value, nil
}

func pathPrefixMatches(prefix, path string) bool {
	return prefix == "/" || path == prefix ||
		(len(path) > len(prefix) && strings.HasPrefix(path, prefix) && path[len(prefix)] == '/')
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
