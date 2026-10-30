package dnspropagation

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

type Engine struct {
	source         Source
	public         []Resolver
	publicQuorum   int
	minTTL         time.Duration
	maxTTL         time.Duration
	minNegativeTTL time.Duration
	maxNegativeTTL time.Duration
	maxAge         time.Duration
	now            func() time.Time
	metrics        Metrics
	// endpointTimeout bounds one endpoint so a slow anycast node cannot stall the check.
	endpointTimeout time.Duration
	logger          *slog.Logger

	logMu         sync.Mutex
	lastSkipped   string
	lastSkippedAt time.Time
}

const (
	defaultEndpointTimeout = 10 * time.Second
	skippedLogInterval     = 10 * time.Minute
)

func NewEngine(config Config) (*Engine, error) {
	if nilPort(config.Source) || nilPort(config.Metrics) || config.Now == nil ||
		len(config.Public) == 0 || config.PublicQuorum < 1 || config.PublicQuorum > len(config.Public) ||
		config.MinTTL <= 0 || config.MaxTTL < config.MinTTL ||
		config.MinNegativeTTL <= 0 || config.MaxNegativeTTL < config.MinNegativeTTL || config.MaxAge <= 0 ||
		config.EndpointTimeout < 0 {
		return nil, ErrInvalidInput
	}
	if !uniqueResolvers(config.Public, nil) {
		return nil, ErrInvalidInput
	}
	endpointTimeout := config.EndpointTimeout
	if endpointTimeout == 0 {
		endpointTimeout = defaultEndpointTimeout
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		source: config.Source, public: append([]Resolver(nil), config.Public...), publicQuorum: config.PublicQuorum,
		minTTL: config.MinTTL, maxTTL: config.MaxTTL,
		minNegativeTTL: config.MinNegativeTTL, maxNegativeTTL: config.MaxNegativeTTL,
		maxAge: config.MaxAge, now: config.Now, metrics: config.Metrics,
		endpointTimeout: endpointTimeout, logger: logger,
	}, nil
}

func (engine *Engine) Observe(ctx context.Context, request Request) (result Result, err error) {
	if engine == nil {
		return Result{}, ErrInvalidInput
	}
	result = Result{
		TenantID: request.TenantID, ZoneID: request.ZoneID, OperationID: request.OperationID,
		Reason: ReasonPublicQuorumPending, RequiredPublic: engine.publicQuorum,
		LKG: LKGPreserve, Compensation: CompensationNone,
	}
	if ctx == nil || ctx.Err() != nil || !validRequest(request) {
		return Result{}, ErrInvalidInput
	}
	defer func() {
		engine.metrics.Record(Metric{
			Reason: result.Reason, Success: result.Success,
			AuthoritativeVotes: result.AuthoritativeVotes, PublicVotes: result.PublicVotes,
		})
	}()

	delegation, err := engine.source.Discover(ctx, request.OperationID, request.Zone)
	if err != nil {
		return result, err
	}
	publicIDs := make(map[string]struct{}, len(engine.public))
	for _, resolver := range engine.public {
		publicIDs[resolver.ID] = struct{}{}
	}
	if delegation.Zone != request.Zone || len(delegation.Authorities) == 0 ||
		!uniqueResolvers(delegation.Authorities, publicIDs) {
		result.Reason = ReasonResolverIdentityConflict
		return result, nil
	}

	types := expectedTypes(request.Expected)
	answered, skipped, err := engine.observeEndpoints(ctx, request, delegation.Authorities, types)
	if err != nil {
		return result, err
	}
	var authorityResolvers, publicResolvers []Resolver
	var authority, public []Observation
	for index, item := range answered {
		if item.skipped {
			continue
		}
		item.observation.OperationID = request.OperationID
		result.Observations = append(result.Observations, item.observation)
		if index < len(delegation.Authorities) {
			authorityResolvers = append(authorityResolvers, item.resolver)
			authority = append(authority, item.observation)
		} else {
			publicResolvers = append(publicResolvers, item.resolver)
			public = append(public, item.observation)
		}
	}
	result.Skipped = skipped
	defer func() {
		if len(result.Skipped) != 0 {
			engine.logSkipped(request, result, err)
		}
	}()

	// Authority quorum (N21): an NS host name counts as reachable when at least
	// one of its addresses answered. A strict majority of NS names must be
	// reachable, so a lagging NS cannot hide behind unreachable siblings
	// (with the usual two NS names both must answer). Below that the check is
	// Unknown rather than a negative verdict.
	if !authorityNamesQuorum(delegation.Authorities, authorityResolvers) {
		return result, ErrAuthoritiesUnavailable
	}

	now := engine.now().UTC()
	// Every authority endpoint that answered must agree (unchanged semantics).
	authorityReason := engine.authorityReason(delegation, request.Expected, authorityResolvers, authority, now)
	if authorityReason != ReasonConverged {
		result.Reason = authorityReason
		return result, nil
	}
	result.AuthoritativeVotes = len(authority)
	authorityFingerprint := answerFingerprint(authority[0], false)
	publicStale := false
	publicDNSSECUnverified := false
	for index, observation := range public {
		if !validObservationIdentity(observation, publicResolvers[index], RolePublicRecursive) {
			continue
		}
		if staleObservation(observation, now, engine.maxAge) ||
			observation.Status == ResponseAnswer && !engine.validAnswerTTL(observation.TTL) {
			publicStale = true
			continue
		}
		if delegation.Signed && observation.Status == ResponseAnswer && observation.DNSSEC != DNSSECSecure {
			publicDNSSECUnverified = true
			continue
		}
		if observation.Status == ResponseAnswer &&
			answerFingerprint(observation, false) == authorityFingerprint &&
			equalRRsets(observation.Records, request.Expected) {
			result.PublicVotes++
		}
	}
	if result.PublicVotes < engine.publicQuorum {
		if len(public) < engine.publicQuorum {
			// Skipped public resolvers made the quorum unreachable: Unknown.
			return result, ErrAuthoritiesUnavailable
		}
		switch {
		case publicStale:
			result.Reason = ReasonStale
		case publicDNSSECUnverified:
			result.Reason = ReasonDNSSECUnverified
		default:
			result.Reason = ReasonPublicQuorumPending
		}
		return result, nil
	}
	result.Reason = ReasonConverged
	result.Success = true
	result.LKG = LKGPromote
	return result, nil
}

func (engine *Engine) authorityReason(delegation Delegation, expected []RRSet, resolvers []Resolver,
	observations []Observation, now time.Time) ReasonCode {
	fingerprints := make([]string, 0, len(observations))
	invalid := false
	stale := false
	dnssecUnverified := false
	for index, observation := range observations {
		if !validObservationIdentity(observation, resolvers[index], RoleAuthoritative) {
			invalid = true
		}
		if staleObservation(observation, now, engine.maxAge) {
			stale = true
		}
		if delegation.Signed && observation.DNSSEC == DNSSECBogus {
			dnssecUnverified = true
		}
		if observation.Status != ResponseAnswer && observation.Status != ResponseNXDOMAIN &&
			observation.Status != ResponseNODATA && observation.Status != ResponseSERVFAIL {
			invalid = true
		}
		fingerprints = append(fingerprints, observationFingerprint(observation, true))
	}
	if invalid {
		return ReasonAuthorityConflict
	}
	if stale {
		return ReasonStale
	}
	if dnssecUnverified {
		return ReasonDNSSECUnverified
	}
	for _, fingerprint := range fingerprints[1:] {
		if fingerprint != fingerprints[0] {
			return ReasonAuthorityConflict
		}
	}
	first := observations[0]
	switch first.Status {
	case ResponseSERVFAIL:
		return ReasonSERVFAIL
	case ResponseNXDOMAIN:
		_ = engine.validNegativeTTL(first.NegativeTTL)
		return ReasonNXDOMAIN
	case ResponseNODATA:
		_ = engine.validNegativeTTL(first.NegativeTTL)
		return ReasonNODATA
	case ResponseAnswer:
		if !engine.validAnswerTTL(first.TTL) {
			return ReasonStale
		}
		if !equalRRsets(first.Records, expected) {
			return ReasonAuthorityConflict
		}
	}
	return ReasonConverged
}

type endpointResult struct {
	resolver    Resolver
	observation Observation
	skipped     bool
}

// observeEndpoints queries the authorities followed by the configured public
// resolvers concurrently, each under its own timeout.
func (engine *Engine) observeEndpoints(ctx context.Context, request Request, authorities []Resolver,
	types []dnscheck.RecordType) ([]endpointResult, []SkippedEndpoint, error) {
	resolvers := append(append([]Resolver(nil), authorities...), engine.public...)
	return observeConcurrently(ctx, engine.source, engine.endpointTimeout, request.OperationID, request.Name,
		types, resolvers, len(authorities))
}

// observeConcurrently queries every resolver concurrently, each under its own
// timeout; the first authorityCount resolvers are authorities. Endpoints that
// are unreachable, refuse the connection or time out are skipped and
// reported; any other error, or the parent context ending, fails the check.
func observeConcurrently(ctx context.Context, source Source, timeout time.Duration, operationID, name string,
	types []dnscheck.RecordType, resolvers []Resolver, authorityCount int) ([]endpointResult, []SkippedEndpoint, error) {
	results := make([]endpointResult, len(resolvers))
	errs := make([]error, len(resolvers))
	var wait sync.WaitGroup
	for index, resolver := range resolvers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			endpointCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			observation, err := source.Observe(endpointCtx, operationID, resolver, name, types)
			results[index] = endpointResult{resolver: resolver, observation: observation}
			errs[index] = err
		}()
	}
	wait.Wait()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var skipped []SkippedEndpoint
	for index, err := range errs {
		if err == nil {
			continue
		}
		reason := endpointUnavailableReason(err)
		if reason == "" {
			return nil, nil, err
		}
		role := RolePublicRecursive
		if index < authorityCount {
			role = RoleAuthoritative
		}
		results[index].skipped = true
		skipped = append(skipped, SkippedEndpoint{
			Role: role, ResolverID: resolvers[index].ID, Name: resolvers[index].Name, Reason: reason,
		})
	}
	return results, skipped, nil
}

// endpointUnavailableReason classifies the errors that mean "this endpoint is
// not usable from here" as opposed to a malformed or hostile answer.
func endpointUnavailableReason(err error) string {
	switch {
	case errors.Is(err, errAddressFamilyUnavailable):
		return "address_family_unavailable"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network_unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host_unreachable"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	return ""
}

// authorityNamesQuorum reports whether a strict majority of the delegation's
// NS host names had at least one answering address.
func authorityNamesQuorum(all, answered []Resolver) bool {
	names := make(map[string]struct{}, len(all))
	for _, resolver := range all {
		names[resolver.Name] = struct{}{}
	}
	reachable := make(map[string]struct{}, len(names))
	for _, resolver := range answered {
		reachable[resolver.Name] = struct{}{}
	}
	return len(reachable)*2 > len(names)
}

// logSkipped writes one line per check that skipped endpoints, repeating an
// unchanged set at most once per skippedLogInterval.
func (engine *Engine) logSkipped(request Request, result Result, err error) {
	parts := make([]string, 0, len(result.Skipped))
	for _, skipped := range result.Skipped {
		parts = append(parts, string(skipped.Role)+" "+skipped.Name+" "+skipped.ResolverID+" "+skipped.Reason)
	}
	signature := request.Zone + "\x00" + strings.Join(parts, "\x00")
	now := engine.now()
	engine.logMu.Lock()
	if signature == engine.lastSkipped && now.Sub(engine.lastSkippedAt) < skippedLogInterval {
		engine.logMu.Unlock()
		return
	}
	engine.lastSkipped, engine.lastSkippedAt = signature, now
	engine.logMu.Unlock()
	outcome := string(result.Reason)
	if err != nil {
		outcome = err.Error()
	}
	engine.logger.Warn("dns propagation skipped unavailable resolver endpoints",
		"zone", request.Zone, "operation_id", request.OperationID, "skipped", parts,
		"answered", len(result.Observations), "outcome", outcome)
}

func validRequest(request Request) bool {
	if request.TenantID == uuid.Nil || request.ZoneID == uuid.Nil || !validText(request.OperationID, 256) ||
		!validText(request.Zone, 255) || !validText(request.Name, 255) || len(request.Expected) == 0 {
		return false
	}
	seen := make(map[dnscheck.RecordType]struct{}, len(request.Expected))
	for _, set := range request.Expected {
		if !supportedType(set.Type) || len(set.Values) == 0 {
			return false
		}
		if _, duplicate := seen[set.Type]; duplicate {
			return false
		}
		seen[set.Type] = struct{}{}
		values := make(map[string]struct{}, len(set.Values))
		for _, value := range set.Values {
			if !validText(value, 65535) {
				return false
			}
			if _, duplicate := values[value]; duplicate {
				return false
			}
			values[value] = struct{}{}
		}
		if set.Type == dnscheck.RecordCNAME && len(set.Values) != 1 {
			return false
		}
	}
	return true
}

func uniqueResolvers(resolvers []Resolver, existing map[string]struct{}) bool {
	seen := make(map[string]struct{}, len(resolvers))
	for key := range existing {
		seen[key] = struct{}{}
	}
	for _, resolver := range resolvers {
		if !validText(resolver.ID, 256) || !validText(resolver.Name, 255) {
			return false
		}
		if _, duplicate := seen[resolver.ID]; duplicate {
			return false
		}
		seen[resolver.ID] = struct{}{}
	}
	return true
}

func validObservationIdentity(observation Observation, resolver Resolver, role ResolverRole) bool {
	return observation.ResolverID == resolver.ID && observation.Role == role
}

func staleObservation(observation Observation, now time.Time, maxAge time.Duration) bool {
	observedAt := observation.ObservedAt.UTC()
	return observation.Stale || observedAt.IsZero() || observedAt.After(now) || now.Sub(observedAt) > maxAge
}

func (engine *Engine) validAnswerTTL(ttl time.Duration) bool {
	return ttl >= engine.minTTL && ttl <= engine.maxTTL
}

func (engine *Engine) validNegativeTTL(ttl time.Duration) bool {
	return ttl >= engine.minNegativeTTL && ttl <= engine.maxNegativeTTL
}

func expectedTypes(expected []RRSet) []dnscheck.RecordType {
	result := make([]dnscheck.RecordType, 0, len(expected))
	for _, set := range expected {
		result = append(result, set.Type)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func equalRRsets(left, right []RRSet) bool {
	return rrsetFingerprint(left) == rrsetFingerprint(right)
}

func answerFingerprint(observation Observation, includeTTL bool) string {
	result := string(observation.Status) + "\x00" + rrsetFingerprint(observation.Records) + "\x00" +
		strings.Join(observation.CNAMEChain, "\x00")
	if includeTTL {
		result += "\x00" + observation.TTL.String()
	}
	return result
}

func observationFingerprint(observation Observation, includeTTL bool) string {
	result := answerFingerprint(observation, includeTTL)
	if observation.Status == ResponseNXDOMAIN || observation.Status == ResponseNODATA {
		result += "\x00" + observation.NegativeTTL.String()
	}
	return result
}

func rrsetFingerprint(sets []RRSet) string {
	parts := make([]string, 0, len(sets))
	for _, set := range sets {
		values := append([]string(nil), set.Values...)
		sort.Strings(values)
		parts = append(parts, set.Type.String()+"="+strings.Join(values, "\x00"))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x01")
}

func supportedType(recordType dnscheck.RecordType) bool {
	return recordType == dnscheck.RecordA || recordType == dnscheck.RecordAAAA ||
		recordType == dnscheck.RecordCNAME || recordType == dnscheck.RecordTXT
}

func validText(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maximum && !strings.ContainsRune(value, 0)
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface ||
		kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}
