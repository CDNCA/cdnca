package edgeconfig

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// WAFInspect is a request-content condition evaluated by cdnca_waf.lua
// inspect(). A target yields a list of values (URL-decoded repeatedly for
// double encoding); Filters then transform each value in order; the operator
// compares them with Values:
//
//   - text operators: contains / not_contains / contains_all (lower-cased
//     substring), regex / not_regex (PCRE, (?i) allowed), prefix / suffix /
//     equals / not_equals (exact bytes), detect (sqli | xss | ssti | java_deser |
//     php_deser detectors). A
//     positive operator matches when some target value matches some entry
//     (contains_all: some value contains every entry); a negated operator
//     matches when no target value matches (so it matches a missing target);
//   - number operators gt / gte / lt / lte / eq / neq: one integer entry,
//     compared with a number target (request_length, body_length,
//     uri_length, header_max_length, header_count, arg_count) or with a text
//     target whose last filter is "length".
//
// Key selects one named value: header (required, lower case), args / query /
// body / cookie (optional, exact name; for body a form field or a JSON key
// path a.b.0). upload_filename / upload_extension are the file names (and
// lower-case extensions) of a multipart body; header_names the request's
// lower-case header names; content_type the request's Content-Type header
// ("" without one); http_version the request's HTTP version, one of 1.0, 1.1,
// 2 or 3 (needs CAPABILITY_NAME_WAF v4, WAFConditionsAPIVersion).
// multipart_field_names are the part names (name= / name*=, as sent) of a
// multipart body; multipart_part_count its part count and
// multipart_field_max_length its longest non-file part body in bytes
// (needs CAPABILITY_NAME_WAF v5, WAFMultipartAPIVersion).
//
// Body targets read at most WAFInspectBodyLimit bytes; BodyOverflow says what
// a longer body does: "" inspects the first bytes only, "match" makes the
// condition hold (the rule's action applies to an uninspectable body).
// Upload targets scan at most WAFInspectUploadScanLimit bytes the same way.
type WAFInspect struct {
	Target       string   `json:"target"`
	Key          string   `json:"key,omitempty"`
	Operator     string   `json:"operator"`
	Values       []string `json:"values"`
	Filters      []string `json:"filters,omitempty"`
	BodyOverflow string   `json:"body_overflow,omitempty"`
}

const (
	WAFInspectBodyLimit       = 64 << 10
	WAFInspectUploadScanLimit = 16 << 20
	// WAFInspectBodyOverflowMatch: a body over the inspection limit makes
	// the condition hold.
	WAFInspectBodyOverflowMatch = "match"
	// MaxWAFInspectPerRule bounds the inspect clauses of one rule.
	MaxWAFInspectPerRule = 8
	wafInspectMaxValues  = 64
	wafInspectMaxFilters = 4
	wafInspectLuaModule  = "cdnca_waf"
)

var (
	wafInspectTextTargets = []string{"args", "query", "body", "request_uri", "path", "header", "cookie", "user_agent",
		"referer", "upload_filename", "upload_extension", "header_names", "content_type", "http_version",
		"multipart_field_names"}
	wafInspectNumberTargets = []string{"request_length", "body_length", "uri_length", "header_max_length", "header_count", "arg_count",
		"multipart_part_count", "multipart_field_max_length"}
	wafInspectTextOperators = []string{"contains", "not_contains", "contains_all", "regex", "not_regex", "prefix", "suffix",
		"equals", "not_equals", "detect"}
	wafInspectNumberOperators = []string{"gt", "gte", "lt", "lte", "eq", "neq"}
	wafInspectDetectors       = []string{"sqli", "xss", "ssti", "java_deser", "php_deser", "ssrf", "cmd"}
	wafInspectFilters         = []string{"lowercase", "base64_decode", "unicode_decode", "html_unescape", "length"}
	// Targets reading the request body (and so subject to BodyOverflow).
	wafInspectBodyTargets = []string{"args", "body", "upload_filename", "upload_extension", "multipart_field_names",
		"multipart_part_count", "multipart_field_max_length"}
	// http_version values (equals / not_equals only).
	wafInspectHTTPVersions = []string{"1.0", "1.1", "2", "3"}
	wafInspectKeyedTargets = []string{"header", "args", "query", "body", "cookie"}
	wafInspectHeaderKey    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	wafInspectNameKey      = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]-]{1,128}$`)
)

// WAFInspectTarget reports whether target is an inspect target and whether
// it yields a number.
func WAFInspectTarget(target string) (known, number bool) {
	if containsString(wafInspectNumberTargets, target) {
		return true, true
	}
	return containsString(wafInspectTextTargets, target), false
}

// WAFInspectOperator reports whether operator is an inspect operator and
// whether it compares numbers.
func WAFInspectOperator(operator string) (known, number bool) {
	if containsString(wafInspectNumberOperators, operator) {
		return true, true
	}
	return containsString(wafInspectTextOperators, operator), false
}

// WAFInspectReadsBody reports whether target reads the request body.
func WAFInspectReadsBody(target string) bool { return containsString(wafInspectBodyTargets, target) }

func normalizeWAFInspect(values []WAFInspect) ([]WAFInspect, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) == 0 || len(values) > MaxWAFInspectPerRule {
		return nil, ErrInvalidConfig
	}
	result := make([]WAFInspect, len(values))
	for index, value := range values {
		normalized, err := normalizeOneWAFInspect(value)
		if err != nil {
			return nil, err
		}
		result[index] = normalized
	}
	return result, nil
}

func normalizeOneWAFInspect(value WAFInspect) (WAFInspect, error) {
	knownTarget, numberTarget := WAFInspectTarget(value.Target)
	knownOperator, numberOperator := WAFInspectOperator(value.Operator)
	if !knownTarget || !knownOperator || len(value.Values) == 0 || len(value.Values) > wafInspectMaxValues ||
		len(value.Filters) > wafInspectMaxFilters {
		return WAFInspect{}, ErrInvalidConfig
	}
	switch {
	case value.Target == "header":
		if !wafInspectHeaderKey.MatchString(value.Key) {
			return WAFInspect{}, ErrInvalidConfig
		}
	case containsString(wafInspectKeyedTargets, value.Target):
		if value.Key != "" && !wafInspectNameKey.MatchString(value.Key) {
			return WAFInspect{}, ErrInvalidConfig
		}
	case value.Key != "":
		return WAFInspect{}, ErrInvalidConfig
	}
	for index, filter := range value.Filters {
		if !containsString(wafInspectFilters, filter) || filter == "length" && index != len(value.Filters)-1 {
			return WAFInspect{}, ErrInvalidConfig
		}
	}
	lengthFilter := len(value.Filters) > 0 && value.Filters[len(value.Filters)-1] == "length"
	// A number target takes no filter; a number operator needs a number
	// (a number target, or a text target ending in the length filter).
	if numberTarget && len(value.Filters) != 0 || numberOperator != (numberTarget || lengthFilter) {
		return WAFInspect{}, ErrInvalidConfig
	}
	if value.BodyOverflow != "" && (value.BodyOverflow != WAFInspectBodyOverflowMatch ||
		!WAFInspectReadsBody(value.Target) && value.Target != "body_length" && value.Target != "request_length") {
		return WAFInspect{}, ErrInvalidConfig
	}
	if numberOperator {
		if len(value.Values) != 1 {
			return WAFInspect{}, ErrInvalidConfig
		}
		number, err := strconv.ParseInt(value.Values[0], 10, 64)
		if err != nil || number < 0 || number > 1<<40 || strconv.FormatInt(number, 10) != value.Values[0] {
			return WAFInspect{}, ErrInvalidConfig
		}
	}
	if value.Target == "http_version" && (value.Operator != "equals" && value.Operator != "not_equals" || len(value.Filters) != 0) {
		return WAFInspect{}, ErrInvalidConfig
	}
	for _, entry := range value.Values {
		if value.Target == "http_version" && !containsString(wafInspectHTTPVersions, entry) {
			return WAFInspect{}, ErrInvalidConfig
		}
		if entry == "" || len(entry) > 1024 || !utf8.ValidString(entry) || strings.ContainsAny(entry, "\r\n\x00") ||
			value.Operator == "detect" && !containsString(wafInspectDetectors, entry) {
			return WAFInspect{}, ErrInvalidConfig
		}
	}
	normalized := WAFInspect{Target: value.Target, Key: value.Key, Operator: value.Operator,
		Values: append([]string(nil), value.Values...), BodyOverflow: value.BodyOverflow}
	if len(value.Filters) != 0 {
		normalized.Filters = append([]string(nil), value.Filters...)
	}
	return normalized, nil
}

// RenderWAFInspectCondition is the Lua condition the security state machine
// evaluates for one inspect clause. The JSON travels in a long-bracket string
// whose level is chosen so the payload can never close it early.
func RenderWAFInspectCondition(value WAFInspect) string {
	encoded := wafInspectJSON(value)
	level := 0
	for strings.Contains(encoded, "]"+strings.Repeat("=", level)+"]") {
		level++
	}
	equals := strings.Repeat("=", level)
	return "require(\"" + wafInspectLuaModule + "\").inspect([" + equals + "[" + encoded + "]" + equals + "])"
}

// NormalizeWAFInspect validates inspect clauses the way the renderer does, so
// the node precheck can independently re-derive the rendered conditions.
func NormalizeWAFInspect(values []WAFInspect) ([]WAFInspect, error) {
	return normalizeWAFInspect(values)
}

// WAFInspectDetectors lists the node's built-in detectors (operator detect).
func WAFInspectDetectors() []string { return append([]string(nil), wafInspectDetectors...) }

func hasWAFInspect(sites []Site) bool {
	for _, site := range sites {
		for _, policy := range site.SecurityPolicies {
			for _, rule := range policy.Rules {
				if len(rule.Match.Inspect) != 0 {
					return true
				}
			}
		}
	}
	return false
}

// Security policy condition operators that compare numbers, mapped to the
// inspect number operators.
var wafPolicyNumberOperators = map[string]string{
	"number_gt": "gt", "number_gte": "gte", "number_lt": "lt", "number_lte": "lte", "number_eq": "eq", "number_neq": "neq",
}

// WAFInspectPolicyCondition maps one WAF security policy condition (field,
// operator, key, values, filters, body overflow) to the inspect clause the
// node evaluates. ok is false for conditions the node matches natively
// (path equals / prefix and header equals without filters, and every
// non-content field); err is set for an inspect condition the node cannot
// run. The control plane (publication) and the node precheck both use it,
// so they cannot disagree on the mapping.
func WAFInspectPolicyCondition(field, operator, key string, values, filters []string, bodyOverflow string) (WAFInspect, bool, error) {
	known, number := WAFInspectTarget(field)
	if !known {
		return WAFInspect{}, false, nil
	}
	plain := len(filters) == 0 && bodyOverflow == ""
	if plain && (field == "path" && (operator == "equals" || operator == "prefix") || field == "header" && operator == "equals") {
		return WAFInspect{}, false, nil
	}
	inspectOperator := operator
	if mapped, ok := wafPolicyNumberOperators[operator]; ok {
		inspectOperator = mapped
	} else if _, isNumber := WAFInspectOperator(operator); isNumber || number {
		// Number comparisons are spelled number_* in policies.
		return WAFInspect{}, true, ErrInvalidConfig
	}
	value := WAFInspect{Target: field, Key: key, Operator: inspectOperator, Values: append([]string(nil), values...),
		BodyOverflow: bodyOverflow}
	if len(filters) != 0 {
		value.Filters = append([]string(nil), filters...)
	}
	normalized, err := normalizeOneWAFInspect(value)
	if err != nil {
		return WAFInspect{}, true, err
	}
	return normalized, true, nil
}
