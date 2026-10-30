package cachefreshness

import (
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxOriginFreshnessSeconds = uint64(1<<31 - 1)

func Decide(input Policy, request RequestFacts, object ObjectFacts, now time.Time) (Decision, error) {
	policy, err := normalizePolicy(input)
	if err != nil {
		return Decision{}, err
	}
	factsDigest := ObjectFactsDigest(object)
	decision := Decision{
		PolicyVersion:        policy.PolicyVersion,
		ConfigurationVersion: policy.ConfigurationVersion,
		TenantID:             policy.TenantID,
		SiteID:               policy.SiteID,
		Mode:                 policy.Mode,
		FreshSeconds:         uint64(policy.FreshSeconds),
		StaleWindowSeconds:   policy.Enhancement.StaleWindowSeconds,
		ObjectFactsSHA256:    hex.EncodeToString(factsDigest[:]),
		State:                StateExpired,
	}
	method := strings.ToUpper(request.Method)
	if request.Authorization || request.Cookie || request.CacheControlNoStore {
		decision.Reason, decision.Bypass = ReasonPrivateBypass, true
		return decision, nil
	}
	if method != "GET" && method != "HEAD" || request.CacheControlNoCache || request.Range || request.Conditional || request.Upgrade {
		decision.Reason, decision.Bypass = ReasonRequestBypass, true
		return decision, nil
	}
	if object.Exists && !object.Cacheable {
		decision.Reason, decision.Bypass = ReasonPrivateBypass, true
		return decision, nil
	}
	if !object.Exists {
		switch {
		case object.LockTimedOut:
			decision.Reason, decision.Fallback = ReasonCoalesceTimeout, true
		case object.Coalesced:
			decision.Reason, decision.State = ReasonCoalescedFollower, StateFresh
		case object.FailureClass != "":
			decision.Reason, decision.Fallback = ReasonOriginError, true
		default:
			decision.Reason = ReasonMiss
		}
		return decision, nil
	}
	if object.StoredAt.IsZero() || now.Before(object.StoredAt) {
		decision.Reason, decision.Bypass, decision.Fallback = ReasonStaleHardLimit, true, true
		return decision, nil
	}
	age := now.Sub(object.StoredAt)
	decision.AgeSeconds = int64(age / time.Second)
	freshSeconds := uint64(policy.FreshSeconds)
	forceExpired := false
	if policy.FollowOriginHeaders {
		origin, valid := parseOriginFreshness(object, uint64(policy.FreshSeconds))
		if !valid {
			decision.FreshSeconds = 0
			decision.Reason, decision.Bypass, decision.Fallback = ReasonOriginHeadersInvalid, true, true
			return decision, nil
		}
		decision.OriginAgeSeconds = origin.ageSeconds
		decision.OriginFreshnessSource = origin.source
		decision.VaryHeaders = origin.varyHeaders
		if origin.uncacheable {
			decision.FreshSeconds = 0
			decision.Reason, decision.Bypass = ReasonOriginUncacheable, true
			return decision, nil
		}
		freshSeconds = origin.freshSeconds
		decision.FreshSeconds = freshSeconds
		forceExpired = origin.forceExpired
	}
	if forceExpired {
		decision.Reason = ReasonMiss
		return decision, nil
	}
	if uint64(decision.AgeSeconds) < freshSeconds {
		decision.Reason, decision.State = ReasonFreshHit, StateFresh
		return decision, nil
	}
	if policy.Enhancement.Enabled {
		hardSeconds := freshSeconds + uint64(policy.Enhancement.StaleWindowSeconds)
		if hardSeconds < freshSeconds {
			hardSeconds = ^uint64(0)
		}
		if uint64(decision.AgeSeconds) < hardSeconds {
			if failureClassAllowed(policy, object.FailureClass) {
				decision.Reason, decision.State = ReasonStaleRevalidate, StateStale
				return decision, nil
			}
		}
		if uint64(decision.AgeSeconds) >= hardSeconds {
			decision.Reason, decision.Bypass, decision.Fallback = ReasonStaleHardLimit, true, true
			return decision, nil
		}
	}
	if object.FailureClass != "" {
		decision.Reason, decision.Fallback = ReasonOriginError, true
	} else {
		decision.Reason = ReasonMiss
	}
	return decision, nil
}

type originFreshnessFacts struct {
	freshSeconds uint64
	ageSeconds   uint64
	source       OriginFreshnessSource
	varyHeaders  []string
	uncacheable  bool
	forceExpired bool
}

type cacheControlFacts struct {
	sMaxAge        *uint64
	maxAge         *uint64
	noStore        bool
	private        bool
	noCache        bool
	mustRevalidate bool
}

// parseOriginFreshness mirrors guard.lua parse_origin_freshness. defaultSeconds
// applies when the origin sends no explicit lifetime, as proxy_cache_valid does
// outside the freshness mode.
func parseOriginFreshness(object ObjectFacts, defaultSeconds uint64) (originFreshnessFacts, bool) {
	control, valid := parseOriginCacheControl(object.OriginCacheControl)
	if !valid {
		return originFreshnessFacts{}, false
	}
	result := originFreshnessFacts{
		uncacheable:  control.noStore || control.private,
		forceExpired: control.noCache || control.mustRevalidate,
	}
	if result.uncacheable || result.forceExpired {
		return result, true
	}
	vary, varyStar, valid := parseOriginVary(object.OriginVary)
	if !valid {
		return originFreshnessFacts{}, false
	}
	result.varyHeaders = vary
	if varyStar {
		result.uncacheable = true
		return result, true
	}
	age, valid := parseOriginAge(object.OriginAge)
	if !valid {
		return originFreshnessFacts{}, false
	}
	result.ageSeconds = age
	var lifetime uint64
	switch {
	case control.sMaxAge != nil:
		lifetime, result.source = *control.sMaxAge, FreshnessSourceSMaxAge
	case control.maxAge != nil:
		lifetime, result.source = *control.maxAge, FreshnessSourceMaxAge
	default:
		expires, hasExpires, valid := parseOriginDate(object.OriginExpires)
		if !valid {
			return originFreshnessFacts{}, false
		}
		if !hasExpires {
			result.freshSeconds, result.source = defaultSeconds, FreshnessSourceDefault
			return result, true
		}
		date, hasDate, valid := parseOriginDate(object.OriginDate)
		if !valid || !hasDate {
			return originFreshnessFacts{}, false
		}
		result.source = FreshnessSourceExpires
		if expires.After(date) {
			// time.Duration saturates near 292 years, well above 2^31 seconds.
			lifetime = min(uint64(expires.Sub(date)/time.Second), maxOriginFreshnessSeconds)
		}
	}
	if age < lifetime {
		result.freshSeconds = lifetime - age
	}
	return result, true
}

func parseOriginCacheControl(values []string) (cacheControlFacts, bool) {
	var result cacheControlFacts
	seen := make(map[string]struct{})
	for _, value := range values {
		directives, valid := splitHeaderList(value)
		if !valid {
			return cacheControlFacts{}, false
		}
		for _, directive := range directives {
			name, raw, hasValue := strings.Cut(directive, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if !validHeaderToken(name) {
				return cacheControlFacts{}, false
			}
			if _, duplicate := seen[name]; duplicate {
				return cacheControlFacts{}, false
			}
			seen[name] = struct{}{}
			raw = strings.TrimSpace(raw)
			switch name {
			case "s-maxage", "max-age":
				seconds, valid := parseDeltaSeconds(raw, hasValue)
				if !valid {
					return cacheControlFacts{}, false
				}
				if name == "s-maxage" {
					result.sMaxAge = &seconds
				} else {
					result.maxAge = &seconds
				}
			case "no-store", "must-revalidate", "public":
				if hasValue {
					return cacheControlFacts{}, false
				}
				result.noStore = result.noStore || name == "no-store"
				result.mustRevalidate = result.mustRevalidate || name == "must-revalidate"
			case "private", "no-cache":
				if hasValue && !validQuotedString(raw) {
					return cacheControlFacts{}, false
				}
				result.private = result.private || name == "private"
				result.noCache = result.noCache || name == "no-cache"
			default:
				if hasValue && !validDirectiveValue(raw) {
					return cacheControlFacts{}, false
				}
			}
		}
	}
	return result, true
}

func parseOriginAge(values []string) (uint64, bool) {
	if len(values) == 0 {
		return 0, true
	}
	if len(values) != 1 {
		return 0, false
	}
	return parseDeltaSeconds(strings.TrimSpace(values[0]), true)
}

func parseOriginDate(values []string) (time.Time, bool, bool) {
	if len(values) == 0 {
		return time.Time{}, false, true
	}
	if len(values) != 1 {
		return time.Time{}, false, false
	}
	value := strings.TrimSpace(values[0])
	parsed, err := http.ParseTime(value)
	return parsed, true, err == nil && value != ""
}

func parseOriginVary(values []string) ([]string, bool, bool) {
	seen := make(map[string]struct{})
	star := false
	for _, value := range values {
		names, valid := splitHeaderList(value)
		if !valid {
			return nil, false, false
		}
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "*" {
				star = true
				continue
			}
			if !validHeaderToken(name) {
				return nil, false, false
			}
			seen[name] = struct{}{}
		}
	}
	if star && len(seen) != 0 {
		return nil, false, false
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, star, true
}

func splitHeaderList(value string) ([]string, bool) {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
		return nil, false
	}
	var result []string
	start, quoted, escaped := 0, false, false
	for index, character := range value {
		switch {
		case escaped:
			escaped = false
		case quoted && character == '\\':
			escaped = true
		case character == '"':
			quoted = !quoted
		case character == ',' && !quoted:
			item := strings.TrimSpace(value[start:index])
			if item == "" {
				return nil, false
			}
			result = append(result, item)
			start = index + 1
		}
	}
	item := strings.TrimSpace(value[start:])
	if quoted || escaped || item == "" {
		return nil, false
	}
	return append(result, item), true
}

func parseDeltaSeconds(value string, present bool) (uint64, bool) {
	if !present {
		return 0, false
	}
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	if value == "" {
		return 0, false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, false
	}
	// RFC 9111 1.2.2: delta-seconds beyond the representable range are treated as 2^31.
	return min(parsed, maxOriginFreshnessSeconds), true
}

func validHeaderToken(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character <= 32 || character >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", character) {
			return false
		}
	}
	return true
}

func validQuotedString(value string) bool {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	escaped := false
	for _, character := range value[1 : len(value)-1] {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == '"' || character < 32 || character == 127 {
			return false
		}
	}
	return !escaped
}

func validDirectiveValue(value string) bool {
	return validHeaderToken(value) || validQuotedString(value)
}

func failureClassAllowed(policy Policy, failure FailureClass) bool {
	if failure == "" || !policy.Enhancement.Enabled || policy.Enhancement.Expert == nil {
		return false
	}
	for _, allowed := range policy.Enhancement.Expert.FailureClasses {
		if failure == allowed {
			return true
		}
	}
	return false
}
