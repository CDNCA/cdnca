package securitypolicy

import (
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

func evaluate(policy Policy, facts RequestFacts) (Evaluation, error) {
	return evaluateAt(policy, facts, time.Now().UTC())
}

func evaluateAt(policy Policy, facts RequestFacts, now time.Time) (Evaluation, error) {
	if !policy.Enabled {
		return Evaluation{
			PolicyID: policy.ID, PolicyRevision: policy.Revision, Action: policy.DefaultAction, UsedDefault: true,
		}, nil
	}
	if err := normalizeFacts(&facts); err != nil {
		return Evaluation{}, err
	}
	result := Evaluation{
		PolicyID: policy.ID, PolicyRevision: policy.Revision, Action: policy.DefaultAction,
		MatchedRuleIDs: make([]uuid.UUID, 0), UsedDefault: true,
		ExpiredRuleIDs: make([]uuid.UUID, 0),
	}
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}
		if rule.ExpiresAt != "" {
			expiresAt, err := time.Parse("2006-01-02T15:04:05Z", rule.ExpiresAt)
			if err != nil {
				return Evaluation{}, ErrInvalidInput
			}
			if !now.Before(expiresAt) {
				result.ExpiredRuleIDs = append(result.ExpiredRuleIDs, rule.ID)
				continue
			}
		}
		matched, err := ruleMatches(rule, facts)
		if err != nil {
			return Evaluation{}, err
		}
		if !matched {
			continue
		}
		result.MatchedRuleIDs = append(result.MatchedRuleIDs, rule.ID)
		result.Action = rule.Action
		result.UsedDefault = false
		if rule.Flow == FlowStop {
			id := rule.ID
			result.TerminalRuleID = &id
			return result, nil
		}
	}
	return result, nil
}

func normalizeFacts(facts *RequestFacts) error {
	facts.Host = strings.ToLower(strings.TrimSpace(facts.Host))
	facts.Method = strings.ToUpper(strings.TrimSpace(facts.Method))
	facts.Country = strings.ToUpper(strings.TrimSpace(facts.Country))
	normalizedHeaders := make(HeaderValues, len(facts.Headers))
	fieldCount := 0
	for key, values := range facts.Headers {
		name := strings.ToLower(strings.TrimSpace(key))
		if !headerNamePattern.MatchString(name) || len(values) == 0 || len(values) > 100-fieldCount {
			return ErrInvalidInput
		}
		fieldCount += len(values)
		for _, value := range values {
			if !utf8.ValidString(value) || len(value) > 4096 || strings.IndexFunc(value, func(r rune) bool {
				return r < 0x20 || r == 0x7f
			}) >= 0 {
				return ErrInvalidInput
			}
			normalizedHeaders[name] = append(normalizedHeaders[name], value)
		}
	}
	for name := range normalizedHeaders {
		sort.Strings(normalizedHeaders[name])
	}
	facts.Headers = normalizedHeaders
	return nil
}

func ruleMatches(rule Rule, facts RequestFacts) (bool, error) {
	for _, condition := range rule.Conditions {
		matched, err := conditionMatches(condition, facts)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

func conditionMatches(condition Condition, facts RequestFacts) (bool, error) {
	var actual string
	switch condition.Field {
	case "client_ip":
		address, err := netip.ParseAddr(strings.TrimSpace(facts.ClientIP))
		if err != nil {
			return false, ErrInvalidInput
		}
		if condition.Operator == "ip_in_cidr" || condition.Operator == "ip_not_in_cidr" {
			matched := false
			for _, value := range condition.Values {
				prefix, err := netip.ParsePrefix(value)
				if err != nil {
					return false, ErrInvalidInput
				}
				matched = matched || prefix.Contains(address)
			}
			if condition.Operator == "ip_not_in_cidr" {
				matched = !matched
			}
			return matched, nil
		}
		actual = address.String()
	case "host":
		actual = facts.Host
	case "path":
		actual = facts.Path
	case "method":
		actual = facts.Method
	case "header", "user_agent", "referer":
		name := condition.Key
		if condition.Field == "user_agent" {
			name = "user-agent"
		} else if condition.Field == "referer" {
			name = "referer"
		}
		values := facts.Headers[name]
		if len(values) != 1 {
			return false, nil
		}
		actual = values[0]
	case "country":
		actual = facts.Country
	case "asn":
		actual = strconv.FormatUint(uint64(facts.ASN), 10)
	case "ja4":
		actual = facts.JA4
	case "port":
		actual = strconv.FormatUint(uint64(facts.Port), 10)
	case "distinct_user_agents":
		actual = strconv.FormatUint(uint64(facts.DistinctUserAgents), 10)
	case "status_404_count":
		actual = strconv.FormatUint(uint64(facts.Status404Count), 10)
	default:
		return false, ErrInvalidInput
	}
	return compare(actual, condition.Operator, condition.Values)
}

func compare(actual, operator string, values []string) (bool, error) {
	contains := func(candidate string) bool {
		for _, value := range values {
			if candidate == value {
				return true
			}
		}
		return false
	}
	switch operator {
	case "equals", "in":
		return contains(actual), nil
	case "not_equals", "not_in":
		return !contains(actual), nil
	case "prefix":
		for _, value := range values {
			if strings.HasPrefix(actual, value) {
				return true, nil
			}
		}
		return false, nil
	case "suffix":
		for _, value := range values {
			if strings.HasSuffix(actual, value) {
				return true, nil
			}
		}
		return false, nil
	case "contains":
		for _, value := range values {
			if strings.Contains(actual, value) {
				return true, nil
			}
		}
		return false, nil
	case "regex":
		for _, value := range values {
			pattern, err := regexp.Compile(value)
			if err != nil {
				return false, ErrInvalidInput
			}
			if pattern.MatchString(actual) {
				return true, nil
			}
		}
		return false, nil
	case "number_eq", "number_gte", "number_lte":
		actualNumber, err := strconv.ParseUint(actual, 10, 64)
		if err != nil {
			return false, ErrInvalidInput
		}
		value, err := strconv.ParseUint(values[0], 10, 64)
		if err != nil {
			return false, ErrInvalidInput
		}
		switch operator {
		case "number_eq":
			return actualNumber == value, nil
		case "number_gte":
			return actualNumber >= value, nil
		default:
			return actualNumber <= value, nil
		}
	default:
		return false, ErrInvalidInput
	}
}
