package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	maximumQueryTimeout = 30 * time.Second
	maximumAttempts     = 3
	maximumCNAMEDepth   = 16
	maximumNegativeTTL  = 7 * 24 * 60 * 60
)

type Checker struct {
	resolver      Resolver
	authoritative []NamedResolver
	public        []NamedResolver
	queryTimeout  time.Duration
	attempts      int
	maxCNAMEDepth int
	now           func() time.Time
}

type resolverOutcome struct {
	observations []Observation
	status       Classification
}

func NewChecker(config Config) (*Checker, error) {
	if config.Resolver == nil || len(config.EndpointPolicy.allowed) == 0 || len(config.AuthoritativeResolvers) == 0 || len(config.PublicResolvers) == 0 ||
		config.QueryTimeout <= 0 || config.QueryTimeout > maximumQueryTimeout || config.Attempts < 1 || config.Attempts > maximumAttempts ||
		config.MaxCNAMEDepth < 1 || config.MaxCNAMEDepth > maximumCNAMEDepth {
		return nil, ErrInvalidInput
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	seenVoteIdentities := make(map[string]struct{}, len(config.AuthoritativeResolvers)+len(config.PublicResolvers))
	authoritative, err := normalizeResolvers(config.AuthoritativeResolvers, config.EndpointPolicy, true, seenVoteIdentities)
	if err != nil {
		return nil, err
	}
	public, err := normalizeResolvers(config.PublicResolvers, config.EndpointPolicy, false, seenVoteIdentities)
	if err != nil {
		return nil, err
	}
	return &Checker{
		resolver: config.Resolver, authoritative: authoritative, public: public,
		queryTimeout: config.QueryTimeout, attempts: config.Attempts, maxCNAMEDepth: config.MaxCNAMEDepth, now: config.Now,
	}, nil
}

func normalizeResolvers(resolvers []NamedResolver, policy EndpointPolicy, dnsNames bool, seenVoteIdentities map[string]struct{}) ([]NamedResolver, error) {
	result := make([]NamedResolver, 0, len(resolvers))
	seen := make(map[string]struct{}, len(resolvers))
	for _, resolver := range resolvers {
		var err error
		if dnsNames {
			resolver.Name, err = normalizeDNSName(resolver.Name, false)
		} else {
			resolver.Name, err = normalizeResolverName(resolver.Name)
		}
		if err != nil || policy.Check(resolver.Endpoint) != nil {
			return nil, ErrInvalidInput
		}
		if _, duplicate := seen[resolver.Name]; duplicate {
			return nil, ErrInvalidInput
		}
		voteIdentity := netip.AddrPortFrom(resolver.Endpoint.Address.Unmap(), resolver.Endpoint.Port).String()
		if _, duplicate := seenVoteIdentities[voteIdentity]; duplicate {
			return nil, ErrInvalidInput
		}
		seen[resolver.Name] = struct{}{}
		seenVoteIdentities[voteIdentity] = struct{}{}
		result = append(result, resolver)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (c *Checker) Check(ctx context.Context, request CheckRequest) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	now := c.now().UTC()
	normalized, err := normalizeRequest(request, now)
	if err != nil {
		return CheckResult{}, err
	}
	authoritative, err := c.selectAuthoritative(normalized.AuthoritativeNS)
	if err != nil {
		return CheckResult{}, err
	}
	plan, err := buildRepairPlan(normalized)
	if err != nil {
		return CheckResult{}, err
	}
	result := CheckResult{
		TenantID: normalized.TenantID, SiteID: normalized.SiteID, Name: normalized.Name,
		CheckedAt: now, RepairPlan: plan, Observations: make([]Observation, 0),
	}
	authorityOutcomes, err := c.checkResolvers(ctx, authoritative, ResolverAuthoritative, normalized)
	if err != nil {
		return CheckResult{}, err
	}
	publicOutcomes, err := c.checkResolvers(ctx, c.public, ResolverPublic, normalized)
	if err != nil {
		return CheckResult{}, err
	}
	for _, outcome := range append(authorityOutcomes, publicOutcomes...) {
		result.Observations = append(result.Observations, outcome.observations...)
	}
	authorityStatus := aggregateOutcomes(authorityOutcomes, true)
	publicStatus := aggregateOutcomes(publicOutcomes, false)
	result.Status = authorityStatus
	if authorityStatus == ClassificationHealthy && publicStatus != ClassificationHealthy {
		if propagationActive(normalized, now) || publicNegativeCacheActive(publicStatus, publicOutcomes) {
			result.Status = ClassificationPublicPropagating
		} else {
			result.Status = ClassificationPublicPropagationFailed
		}
	}
	result.Compliant = result.Status == ClassificationHealthy && len(result.RepairPlan.Operations) == 0
	return result, nil
}

func (c *Checker) selectAuthoritative(names []string) ([]NamedResolver, error) {
	if len(names) == 0 {
		return c.authoritative, nil
	}
	configured := make(map[string]NamedResolver, len(c.authoritative))
	for _, resolver := range c.authoritative {
		configured[resolver.Name] = resolver
	}
	selected := make([]NamedResolver, 0, len(names))
	for _, name := range names {
		resolver, ok := configured[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrResolverNameAbsent, name)
		}
		selected = append(selected, resolver)
	}
	return selected, nil
}

func (c *Checker) checkResolvers(ctx context.Context, resolvers []NamedResolver, role ResolverRole, request CheckRequest) ([]resolverOutcome, error) {
	outcomes := make([]resolverOutcome, 0, len(resolvers))
	for _, resolver := range resolvers {
		outcome := resolverOutcome{observations: make([]Observation, 0, len(request.Expected))}
		for _, expected := range request.Expected {
			observation, err := c.resolveExpected(ctx, resolver, role, request.Name, expected)
			if err != nil {
				return nil, err
			}
			outcome.observations = append(outcome.observations, observation)
		}
		outcome.status = aggregateObservations(outcome.observations)
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

func (c *Checker) resolveExpected(ctx context.Context, resolver NamedResolver, role ResolverRole, owner string, expected ExpectedRecord) (Observation, error) {
	observation := Observation{Role: role, Resolver: resolver.Name, RecordType: expected.Type, Status: ClassificationMissing}
	current := owner
	visited := map[string]struct{}{current: {}}
	minimumTTLObserved := false
	for depth := 0; depth <= c.maxCNAMEDepth; depth++ {
		response, attempts, err := c.query(ctx, resolver.Endpoint, DNSQuery{Name: current, Type: expected.Type})
		observation.Attempts += attempts
		if err != nil {
			if contextError := ctx.Err(); contextError != nil {
				return Observation{}, contextError
			}
			observation.Status, observation.ErrorCode = classifyResolverError(err)
			return observation, nil
		}
		if role == ResolverAuthoritative && !response.Authoritative && (response.RCode == 0 || response.RCode == 3) {
			observation.Status = ClassificationResolverFailure
			observation.ErrorCode = "not_authoritative"
			return observation, nil
		}
		switch response.RCode {
		case 0:
		case 2:
			observation.Status = ClassificationSERVFAIL
			observation.ErrorCode = "servfail"
			return observation, nil
		case 3:
			negativeTTL, found, valid := minimumSOANegativeTTL(response.Authority, current)
			if !found || !valid {
				observation.Status = ClassificationMalformedResponse
				observation.ErrorCode = "invalid_negative_soa"
				return observation, nil
			}
			observation.MinimumTTL = negativeTTL
			observation.Status = ClassificationNXDOMAIN
			observation.ErrorCode = "nxdomain"
			return observation, nil
		default:
			observation.Status = ClassificationResolverFailure
			observation.ErrorCode = fmt.Sprintf("rcode_%d", response.RCode)
			return observation, nil
		}
		values, cnames, minimumTTL, ttlObserved, malformed := recordsForOwner(response.Answers, current, expected.Type)
		if ttlObserved && (!minimumTTLObserved || minimumTTL < observation.MinimumTTL) {
			observation.MinimumTTL = minimumTTL
			minimumTTLObserved = true
		}
		if malformed {
			observation.Status = ClassificationMalformedResponse
			observation.ErrorCode = "conflicting_cname_answers"
			return observation, nil
		}
		if len(values) == 0 && len(cnames) == 0 {
			negativeTTL, found, valid := minimumSOANegativeTTL(response.Authority, current)
			if !found {
				return observation, nil
			}
			if !valid {
				observation.Status = ClassificationMalformedResponse
				observation.ErrorCode = "invalid_negative_soa"
				return observation, nil
			}
			observation.MinimumTTL = negativeTTL
			observation.Status = ClassificationNODATA
			observation.ErrorCode = "nodata"
			return observation, nil
		}
		if expected.Type == RecordCNAME {
			if len(cnames) == 0 {
				if len(observation.CNAMEChain) > 0 {
					observation.Status = ClassificationWrongValue
					observation.Values = []string{current}
				}
				return observation, nil
			}
			target, normalizationErr := normalizeDNSName(cnames[0], false)
			if normalizationErr != nil {
				observation.Status = ClassificationMalformedResponse
				observation.ErrorCode = "invalid_cname_target"
				return observation, nil
			}
			if len(observation.CNAMEChain) >= c.maxCNAMEDepth {
				observation.Status = ClassificationCNAMEDepthExceeded
				observation.ErrorCode = "cname_depth_exceeded"
				return observation, nil
			}
			observation.CNAMEChain = append(observation.CNAMEChain, target)
			if _, loop := visited[target]; loop {
				observation.Status = ClassificationCNAMELoop
				observation.ErrorCode = "cname_loop"
				return observation, nil
			}
			if target == expected.Values[0] {
				if len(observation.CNAMEChain) == 1 {
					observation.Status = ClassificationHealthy
				} else {
					observation.Status = ClassificationCNAMEChain
				}
				observation.Values = []string{target}
				return observation, nil
			}
			visited[target] = struct{}{}
			current = target
			continue
		}
		if len(values) > 0 {
			observation.Values = values
			if len(observation.CNAMEChain) > 0 && equalStrings(values, expected.Values) {
				observation.Status = ClassificationCNAMEChain
			} else if equalStrings(values, expected.Values) {
				observation.Status = ClassificationHealthy
			} else {
				observation.Status = ClassificationWrongValue
			}
			return observation, nil
		}
		target, normalizationErr := normalizeDNSName(cnames[0], false)
		if normalizationErr != nil {
			observation.Status = ClassificationMalformedResponse
			observation.ErrorCode = "invalid_cname_target"
			return observation, nil
		}
		if len(observation.CNAMEChain) >= c.maxCNAMEDepth {
			observation.Status = ClassificationCNAMEDepthExceeded
			observation.ErrorCode = "cname_depth_exceeded"
			return observation, nil
		}
		observation.CNAMEChain = append(observation.CNAMEChain, target)
		if _, loop := visited[target]; loop {
			observation.Status = ClassificationCNAMELoop
			observation.ErrorCode = "cname_loop"
			return observation, nil
		}
		visited[target] = struct{}{}
		current = target
	}
	observation.Status = ClassificationCNAMEDepthExceeded
	observation.ErrorCode = "cname_depth_exceeded"
	return observation, nil
}

func (c *Checker) query(ctx context.Context, endpoint ResolverEndpoint, query DNSQuery) (DNSResponse, int, error) {
	var lastError error
	for attempt := 1; attempt <= c.attempts; attempt++ {
		attemptContext, cancel := context.WithTimeout(ctx, c.queryTimeout)
		response, err := c.resolver.Resolve(attemptContext, endpoint, query)
		cancel()
		if contextError := ctx.Err(); contextError != nil {
			return DNSResponse{}, attempt, contextError
		}
		if err == nil && response.RCode != 2 {
			return response, attempt, nil
		}
		if err == nil {
			lastError = nil
			if attempt == c.attempts {
				return response, attempt, nil
			}
			continue
		}
		lastError = err
	}
	return DNSResponse{}, c.attempts, lastError
}

func recordsForOwner(records []DNSRecord, owner string, recordType RecordType) ([]string, []string, uint32, bool, bool) {
	values := make([]string, 0)
	cnames := make([]string, 0)
	var minimumTTL uint32
	ttlObserved := false
	for _, record := range records {
		if record.Name != owner {
			continue
		}
		if record.Type == recordType && recordType != RecordCNAME {
			normalized, err := normalizeRecordValue(recordType, record.Value)
			if err != nil {
				return nil, nil, 0, false, true
			}
			values = append(values, normalized)
			if !ttlObserved || record.TTL < minimumTTL {
				minimumTTL = record.TTL
			}
			ttlObserved = true
		}
		if record.Type == RecordCNAME {
			cnames = append(cnames, record.Value)
			if !ttlObserved || record.TTL < minimumTTL {
				minimumTTL = record.TTL
			}
			ttlObserved = true
		}
	}
	values = sortedUnique(values)
	cnames = sortedUnique(cnames)
	return values, cnames, minimumTTL, ttlObserved, len(cnames) > 1
}

func classifyResolverError(err error) (Classification, string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return ClassificationTimeout, "timeout"
	case errors.Is(err, ErrResponseTooLarge):
		return ClassificationMalformedResponse, "response_too_large"
	case errors.Is(err, ErrMalformedResponse):
		return ClassificationMalformedResponse, "malformed_response"
	case errors.Is(err, ErrEndpointDenied):
		return ClassificationResolverFailure, "endpoint_denied"
	case errors.Is(err, ErrDependencyUnavailable):
		return ClassificationResolverFailure, "dependency_unavailable"
	default:
		return ClassificationResolverFailure, "transport_error"
	}
}

func aggregateObservations(observations []Observation) Classification {
	status := ClassificationHealthy
	for _, observation := range observations {
		if classificationPriority(observation.Status) > classificationPriority(status) {
			status = observation.Status
		}
	}
	return status
}

func aggregateOutcomes(outcomes []resolverOutcome, authoritative bool) Classification {
	if len(outcomes) == 0 {
		return ClassificationResolverFailure
	}
	counts := make(map[string]int, len(outcomes))
	for _, outcome := range outcomes {
		counts[outcomeFingerprint(outcome, authoritative)]++
	}
	winner, winnerCount := "", 0
	for fingerprint, count := range counts {
		if count > winnerCount || (count == winnerCount && (winner == "" || fingerprint < winner)) {
			winner, winnerCount = fingerprint, count
		}
	}
	if winnerCount*2 <= len(outcomes) {
		if authoritative {
			return ClassificationAuthorityInconsistent
		}
		return ClassificationResolverFailure
	}
	for _, outcome := range outcomes {
		if outcomeFingerprint(outcome, authoritative) == winner {
			return outcome.status
		}
	}
	return ClassificationResolverFailure
}

func minimumSOANegativeTTL(records []DNSRecord, owner string) (uint32, bool, bool) {
	var minimum uint32
	found := false
	for _, record := range records {
		if record.Type != RecordSOA {
			continue
		}
		if found {
			return 0, true, false
		}
		found = true
		soaOwner, err := normalizeDNSName(record.Name, false)
		if err != nil || !soaEnclosesOwner(soaOwner, owner) || record.TTL == 0 || record.TTL > maximumNegativeTTL {
			return 0, true, false
		}
		negativeTTL := record.TTL
		if record.negativeTTLSet {
			if record.NegativeTTL == 0 || record.NegativeTTL > maximumNegativeTTL {
				return 0, true, false
			}
			if record.NegativeTTL < negativeTTL {
				negativeTTL = record.NegativeTTL
			}
		}
		if minimum == 0 || negativeTTL < minimum {
			minimum = negativeTTL
		}
	}
	return minimum, found, found
}

func soaEnclosesOwner(soaOwner, owner string) bool {
	return soaOwner == "." || owner == soaOwner || strings.HasSuffix(owner, "."+soaOwner)
}

func outcomeFingerprint(outcome resolverOutcome, includeTTL bool) string {
	parts := make([]string, 0, len(outcome.observations))
	for _, observation := range outcome.observations {
		part := recordTypeKey(observation.RecordType) + ":" + string(observation.Status) + ":" +
			strings.Join(observation.Values, ",") + ":" + strings.Join(observation.CNAMEChain, ",") + ":" + observation.ErrorCode
		if includeTTL {
			part += fmt.Sprintf(":%d", observation.MinimumTTL)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "|")
}

func classificationPriority(classification Classification) int {
	switch classification {
	case ClassificationMalformedResponse:
		return 12
	case ClassificationCNAMELoop, ClassificationCNAMEDepthExceeded:
		return 11
	case ClassificationSERVFAIL, ClassificationTimeout, ClassificationResolverFailure:
		return 10
	case ClassificationNXDOMAIN:
		return 9
	case ClassificationNODATA:
		return 8
	case ClassificationWrongValue:
		return 7
	case ClassificationMissing:
		return 6
	case ClassificationCNAMEChain:
		return 5
	case ClassificationHealthy:
		return 1
	default:
		return 13
	}
}

func propagationActive(request CheckRequest, now time.Time) bool {
	return request.PropagationStartedAt != nil && !now.After(request.PropagationStartedAt.Add(request.PropagationWindow))
}

func publicNegativeCacheActive(status Classification, outcomes []resolverOutcome) bool {
	if status != ClassificationNXDOMAIN && status != ClassificationNODATA {
		return false
	}
	for _, outcome := range outcomes {
		if outcome.status != status {
			continue
		}
		for _, observation := range outcome.observations {
			if observation.Status == status && observation.MinimumTTL > 0 {
				return true
			}
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
