package edgeconfig

import (
	"regexp"
	"strings"
)

// HTTP policy header variables and rule conditions
// (新增请求头 / 新增转向). Control plane (httppolicycontrol), agent
// (httppolicy) and the node engine (edge/openresty/httppolicy/engine.lua)
// apply the same rules; migration 490 (placeholder) checks the stored form.

// HeaderVariables are the names a header value may reference as $name; the
// node expands them per request (engine.lua VARIABLES). "$$" is a literal
// "$". Values are expanded by the Lua engine, never rendered into nginx
// directives; an expanded value keeps printable ASCII only (CR, LF and other
// control or non-ASCII bytes are dropped) and at most MaxHeaderValueBytes.
var HeaderVariables = []string{
	"areacode", "args", "city", "country", "host", "http_referer", "http_user_agent", "isp",
	"province", "remote_addr", "request_method", "request_uri", "scheme", "server_port", "tls_fp", "uri",
}

// MaxHeaderValueBytes bounds a header value, declared and expanded.
const MaxHeaderValueBytes = 1024

var headerVariableName = regexp.MustCompile(`^[a-z][a-z0-9_]*`)

// ValidHeaderValueVariables reports whether every "$" in value starts "$$"
// or a HeaderVariables name followed by a byte that cannot continue a name
// ([a-z0-9_]: "$hostx" is refused, "$host-x" is $host then "-x").
func ValidHeaderValueVariables(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] != '$' {
			continue
		}
		if index+1 < len(value) && value[index+1] == '$' {
			index++
			continue
		}
		name := headerVariableName.FindString(value[index+1:])
		if !headerVariableKnown(name) {
			return false
		}
		index += len(name)
	}
	return true
}

func headerVariableKnown(name string) bool {
	for _, known := range HeaderVariables {
		if known == name {
			return true
		}
	}
	return false
}

// Rule condition sources (高级条件 of a URL 转向 / 内部重写).
const (
	RuleConditionHost           = "host" // 域名:端口 ($http_host)
	RuleConditionUserAgent      = "user_agent"
	RuleConditionReferer        = "referer"
	RuleConditionCountry        = "country" // IP 库国家码 (CN)
	RuleConditionAcceptLanguage = "accept_language"
	RuleConditionProvince       = "province" // IP 库省级码 (440000)
	RuleConditionCity           = "city"     // IP 库市级码 (440300)
	RuleConditionISP            = "isp"      // telecom | unicom | mobile
	RuleConditionASN            = "asn"      // AS 号码 (decimal)
	RuleConditionHeader         = "header"   // one request header (Name)
	MaxRuleConditions           = 8
)

var ruleConditionSources = map[string]bool{RuleConditionHost: true, RuleConditionUserAgent: true,
	RuleConditionReferer: true, RuleConditionCountry: true, RuleConditionAcceptLanguage: true,
	RuleConditionProvince: true, RuleConditionCity: true, RuleConditionISP: true, RuleConditionASN: true,
	RuleConditionHeader: true}

// RuleCondition: the rule applies only when Pattern (a bounded regular
// expression, ValidateCachePathRegex) matches the source's value; an
// absent value is "". A rule's conditions must all match.
type RuleCondition struct {
	Source  string `json:"source"`
	Name    string `json:"name,omitempty"`
	Pattern string `json:"pattern"`
}

// NormalizeRuleConditions validates conditions (nil = none) and lower-cases
// header names; an empty non-nil list is refused.
func NormalizeRuleConditions(conditions []RuleCondition) ([]RuleCondition, error) {
	if conditions == nil {
		return nil, nil
	}
	if len(conditions) == 0 || len(conditions) > MaxRuleConditions {
		return nil, ErrInvalidConfig
	}
	result := make([]RuleCondition, len(conditions))
	for index, condition := range conditions {
		condition.Name = strings.ToLower(condition.Name)
		if !ruleConditionSources[condition.Source] || ValidateCachePathRegex(condition.Pattern) != nil ||
			strings.ContainsFunc(condition.Pattern, func(r rune) bool { return r > 0x7e }) ||
			(condition.Source == RuleConditionHeader) != (condition.Name != "") ||
			condition.Name != "" && !cacheConditionHeaderPattern.MatchString(condition.Name) {
			return nil, ErrInvalidConfig
		}
		result[index] = condition
	}
	return result, nil
}
