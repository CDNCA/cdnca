package wafreport

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	maxPolicies    = 256
	maxPolicyBytes = 64 << 10
	maxReportBytes = 512 << 10
	maxDepth       = 16
	maxItems       = 256
	maxFields      = 64
	maxStringBytes = 4096
)

func canonicalPolicies(policies []json.RawMessage) ([]json.RawMessage, [32]byte, error) {
	var zero [32]byte
	if len(policies) > maxPolicies {
		return nil, zero, errors.New("custom WAF report contains too many policies")
	}
	type item struct {
		id  string
		raw json.RawMessage
	}
	items := make([]item, 0, len(policies))
	seen := make(map[string]struct{}, len(policies))
	total := 2
	for _, raw := range policies {
		if len(raw) == 0 || len(raw) > maxPolicyBytes {
			return nil, zero, errors.New("custom WAF policy is too large")
		}
		var value any
		if json.Unmarshal(raw, &value) != nil || !validJSON(value, 0) {
			return nil, zero, errors.New("custom WAF policy is not valid JSON")
		}
		policy, ok := value.(map[string]any)
		if !ok || policy["kind"] != "waf" {
			return nil, zero, errors.New("custom WAF report contains a non-WAF policy")
		}
		for key := range policy {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "protected") || strings.Contains(lower, "system") {
				return nil, zero, errors.New("protected WAF policy cannot be reported")
			}
		}
		id, ok := policy["id"].(string)
		parsed, parseErr := uuid.Parse(id)
		if !ok || parseErr != nil || parsed == uuid.Nil || parsed.String() != id {
			return nil, zero, errors.New("custom WAF policy id is invalid")
		}
		if _, exists := seen[id]; exists {
			return nil, zero, errors.New("custom WAF policy ids must be unique")
		}
		seen[id] = struct{}{}
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) > maxPolicyBytes {
			return nil, zero, fmt.Errorf("encode custom WAF policy: %w", err)
		}
		total += len(encoded) + 1
		if total > maxReportBytes {
			return nil, zero, errors.New("custom WAF report is too large")
		}
		items = append(items, item{id: id, raw: encoded})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].id < items[j].id })
	result := make([]json.RawMessage, len(items))
	for index := range items {
		result[index] = items[index].raw
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maxReportBytes {
		return nil, zero, errors.New("encode custom WAF report")
	}
	return result, sha256.Sum256(encoded), nil
}

// skippedPolicy is a policy left out of a report: the license service would
// refuse the whole report for it, and the sequence would never be sent.
type skippedPolicy struct {
	ID     string
	Reason string
}

// reportablePolicies keeps the policies the license service accepts. The
// checks follow services/license-service internal/licensing
// validWAFCustomPolicy and must change with it.
func reportablePolicies(policies []json.RawMessage) ([]json.RawMessage, []skippedPolicy) {
	kept := make([]json.RawMessage, 0, len(policies))
	var skipped []skippedPolicy
	for _, raw := range policies {
		var policy map[string]any
		if err := json.Unmarshal(raw, &policy); err != nil {
			skipped = append(skipped, skippedPolicy{Reason: "policy is not a JSON object"})
			continue
		}
		if reason := policyRefusal(policy); reason != "" {
			id, _ := policy["id"].(string)
			skipped = append(skipped, skippedPolicy{ID: id, Reason: reason})
			continue
		}
		kept = append(kept, raw)
	}
	return kept, skipped
}

func policyRefusal(policy map[string]any) string {
	for key := range policy {
		switch key {
		case "id", "scope_id", "owner", "kind", "name", "description", "enabled", "default_action", "rules", "version", "schema_version":
		default:
			return "unsupported policy field " + key
		}
	}
	if policy["kind"] != "waf" {
		return "kind is not waf"
	}
	rules, ok := policy["rules"].([]any)
	if !ok || len(rules) == 0 || len(rules) > maxItems {
		return "rules must be 1-256 items"
	}
	for index, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return fmt.Sprintf("rules[%d] is not an object", index)
		}
		if reason := ruleRefusal(rule); reason != "" {
			return fmt.Sprintf("rules[%d]: %s", index, reason)
		}
	}
	return ""
}

func ruleRefusal(rule map[string]any) string {
	for key := range rule {
		switch key {
		case "id", "name", "priority", "enabled", "comment", "expires_at", "conditions", "action", "flow", "action_config":
		default:
			return "unsupported rule field " + key
		}
	}
	// managed_waf has no conditions; every other action needs one.
	conditions, ok := rule["conditions"].([]any)
	if rule["conditions"] == nil && rule["action"] == "managed_waf" {
		conditions, ok = nil, true
	}
	if !ok || len(conditions) == 0 && rule["action"] != "managed_waf" || len(conditions) > maxItems {
		return "conditions must be 1-256 items"
	}
	for index, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok {
			return fmt.Sprintf("conditions[%d] is not an object", index)
		}
		for key := range condition {
			switch key {
			case "field", "operator", "key", "values", "filters", "body_overflow":
			default:
				return fmt.Sprintf("conditions[%d]: unsupported field %s", index, key)
			}
		}
		if value, present := condition["body_overflow"]; present {
			if _, ok := value.(string); !ok {
				return fmt.Sprintf("conditions[%d]: body_overflow is not a string", index)
			}
		}
		if value, present := condition["filters"]; present && !stringItems(value, false) {
			return fmt.Sprintf("conditions[%d]: filters must be 1-256 strings", index)
		}
		noValues := condition["field"] == "jwt_claim" && condition["operator"] == "exists"
		if !stringItems(condition["values"], noValues) {
			return fmt.Sprintf("conditions[%d]: values must be 1-256 strings", index)
		}
	}
	return ""
}

func stringItems(value any, allowEmpty bool) bool {
	items, ok := value.([]any)
	if !ok || len(items) == 0 && !allowEmpty || len(items) > maxItems {
		return false
	}
	for _, item := range items {
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}

func validJSON(value any, depth int) bool {
	if depth > maxDepth {
		return false
	}
	switch value := value.(type) {
	case nil, bool, float64:
		return true
	case string:
		return utf8.ValidString(value) && len(value) <= maxStringBytes
	case []any:
		if len(value) > maxItems {
			return false
		}
		for _, item := range value {
			if !validJSON(item, depth+1) {
				return false
			}
		}
		return true
	case map[string]any:
		if len(value) > maxFields {
			return false
		}
		for key, item := range value {
			if key == "" || len(key) > maxStringBytes || !utf8.ValidString(key) || !validJSON(item, depth+1) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
