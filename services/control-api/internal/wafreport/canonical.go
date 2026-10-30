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
