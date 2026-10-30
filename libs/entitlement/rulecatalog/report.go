package rulecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Custom rule upload (management side -> license service). Every
// tenant-created CC rule group, matcher, filter and WAF policy is reported;
// owner identity is replaced by an installation-salted SHA-256 hash.
const (
	ReportSchema       = "cdnca.security-custom-rule-report/v2"
	ReportPath         = "/installation/v2/security-custom-rule-reports"
	ReportProofDomain  = "cdnca-security-custom-rule-report-proof/v2"
	ownerHashDomain    = "cdnca-security-rule-owner/v1"
	maxReportSectionN  = 256
	maxReportItemBytes = 64 << 10
	MaxReportBytes     = 1 << 20
	maxReportDepth     = 16
	maxReportFields    = 64
	maxReportArray     = 256
	maxReportString    = 4096
)

var ErrInvalidReport = errors.New("invalid security custom rule report")

// Report holds the four sections, each sorted by id.
type Report struct {
	WAFPolicies  []json.RawMessage `json:"waf_policies"`
	CCRuleGroups []json.RawMessage `json:"cc_rule_groups"`
	CCMatchers   []json.RawMessage `json:"cc_matchers"`
	CCFilters    []json.RawMessage `json:"cc_filters"`
}

type ReportRequest struct {
	Schema         string `json:"schema"`
	InstallationID string `json:"installation_id"`
	Sequence       uint64 `json:"sequence"`
	ObservedAt     int64  `json:"observed_at"`
	Report         Report `json:"report"`
	RequestID      string `json:"request_id"`
	Signature      string `json:"signature"`
}

// reportSectionKeys is the exact allow-list per section. No display names,
// usernames, e-mails or protected/system fields are accepted.
var reportSectionKeys = map[string]map[string]bool{
	"waf_policies": set("id", "scope_id", "owner_hash", "name", "description", "enabled", "default_action",
		"rules", "version"),
	"cc_rule_groups": set("id", "scope_id", "owner_hash", "name", "description", "enabled", "default_action",
		"rules", "version"),
	"cc_matchers": set("id", "scope_id", "owner_hash", "name", "description", "enabled", "field", "operator",
		"key", "values", "version"),
	"cc_filters": set("id", "scope_id", "owner_hash", "name", "description", "enabled", "type", "parameters",
		"version"),
}

// OwnerHash pseudonymizes a tenant user. The installation salt prevents
// cross-installation correlation of the same user id.
func OwnerHash(installationID, ownerUserID string) string {
	digest := sha256.Sum256(DigestFields(ownerHashDomain, installationID, ownerUserID))
	return hex.EncodeToString(digest[:])
}

// CanonicalReport validates every section, sorts items by id and returns the
// canonical report with its digest.
func CanonicalReport(report Report) (Report, [32]byte, error) {
	var zero [32]byte
	result := Report{}
	total := 0
	for _, section := range []struct {
		name   string
		input  []json.RawMessage
		output *[]json.RawMessage
	}{
		{"waf_policies", report.WAFPolicies, &result.WAFPolicies},
		{"cc_rule_groups", report.CCRuleGroups, &result.CCRuleGroups},
		{"cc_matchers", report.CCMatchers, &result.CCMatchers},
		{"cc_filters", report.CCFilters, &result.CCFilters},
	} {
		items, size, err := canonicalSection(section.name, section.input)
		if err != nil {
			return Report{}, zero, err
		}
		total += size
		*section.output = items
	}
	encoded, err := json.Marshal(result)
	if err != nil || total > MaxReportBytes || len(encoded) > MaxReportBytes {
		return Report{}, zero, ErrInvalidReport
	}
	return result, sha256.Sum256(encoded), nil
}

func canonicalSection(name string, items []json.RawMessage) ([]json.RawMessage, int, error) {
	if items == nil || len(items) > maxReportSectionN {
		return nil, 0, ErrInvalidReport
	}
	type entry struct {
		id  string
		raw json.RawMessage
	}
	allowed := reportSectionKeys[name]
	entries := make([]entry, 0, len(items))
	seen := map[string]bool{}
	total := 0
	for _, raw := range items {
		if len(raw) == 0 || len(raw) > maxReportItemBytes || RejectDuplicateKeys(raw) != nil {
			return nil, 0, ErrInvalidReport
		}
		var value any
		if json.Unmarshal(raw, &value) != nil || !validReportJSON(value, 0) {
			return nil, 0, ErrInvalidReport
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, 0, ErrInvalidReport
		}
		for key := range object {
			lower := strings.ToLower(key)
			if !allowed[key] || strings.Contains(lower, "protected") || strings.Contains(lower, "system") {
				return nil, 0, ErrInvalidReport
			}
		}
		id, _ := object["id"].(string)
		owner, _ := object["owner_hash"].(string)
		if !uuidPattern.MatchString(id) || seen[id] || !validOwnerHash(owner) {
			return nil, 0, ErrInvalidReport
		}
		if scope, present := object["scope_id"]; present {
			if text, ok := scope.(string); !ok || !uuidPattern.MatchString(text) {
				return nil, 0, ErrInvalidReport
			}
		}
		seen[id] = true
		encoded, err := json.Marshal(object)
		if err != nil || len(encoded) > maxReportItemBytes {
			return nil, 0, ErrInvalidReport
		}
		total += len(encoded) + 1
		entries = append(entries, entry{id: id, raw: encoded})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	result := make([]json.RawMessage, len(entries))
	for index := range entries {
		result[index] = entries[index].raw
	}
	return result, total, nil
}

func ReportProofMessage(request ReportRequest, digest [32]byte) []byte {
	return DigestFields(ReportProofDomain, request.Schema, request.RequestID, request.InstallationID,
		strconv.FormatUint(request.Sequence, 10), strconv.FormatInt(request.ObservedAt, 10),
		hex.EncodeToString(digest[:]))
}

func validOwnerHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func validReportJSON(value any, depth int) bool {
	if depth > maxReportDepth {
		return false
	}
	switch value := value.(type) {
	case nil, bool, float64:
		return true
	case string:
		return utf8.ValidString(value) && len(value) <= maxReportString
	case []any:
		if len(value) > maxReportArray {
			return false
		}
		for _, item := range value {
			if !validReportJSON(item, depth+1) {
				return false
			}
		}
		return true
	case map[string]any:
		if len(value) > maxReportFields {
			return false
		}
		for key, item := range value {
			if key == "" || len(key) > 128 || !utf8.ValidString(key) || !validReportJSON(item, depth+1) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func set(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
