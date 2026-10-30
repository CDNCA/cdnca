package edgeconfig

import (
	"regexp"
	"strings"
)

// SiteResponseRule is one response phase rule of a site
// (响应阶段状态码/响应头；响应体不做). The node
// evaluates the site's rules in order in header_filter, never reading the
// body (EDGE_RESPONSE_RULES, docs/edge/dynroute-filters.md §2.1).
//
// A rule matches when the response status is in one of Statuses (none =
// any status) and every header condition holds. Actions:
//
//   - headers: HeaderActions are applied, evaluation goes on;
//   - log: a security log line (type "response", action "log"), goes on;
//   - error_page: the response is replaced with the site's error page of
//     Status (origin_response, then edge_route, else the built-in page),
//     evaluation ends;
//   - block: the response is replaced with Status and the built-in text
//     page, a security log line (action "block"), evaluation ends.
//
// Which responses: headers rules run on every origin response and on
// responses served from the cache; log, error_page and block run on origin
// responses only, and a response they replace is not stored in the cache.
// Responses the edge generated itself (its own errors and pages) are never
// evaluated.
type SiteResponseRule struct {
	ID            string                    `json:"id"`
	Statuses      []StatusRange             `json:"statuses,omitempty"`
	Headers       []ResponseHeaderCondition `json:"headers,omitempty"`
	Action        string                    `json:"action"`
	HeaderActions []ResponseHeaderAction    `json:"header_actions,omitempty"`
	// Status is the error_page / block response status (400-599).
	Status int `json:"status,omitempty"`
}

// StatusRange is an inclusive status range; From == To is one status.
type StatusRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// ResponseHeaderCondition tests one response header (Name lower case):
// exists, absent, equals (any value, exact) or regex (any value, PCRE on
// the node, checked here with Go's RE2 syntax, which PCRE accepts).
type ResponseHeaderCondition struct {
	Name  string `json:"name"`
	Op    string `json:"op"`
	Value string `json:"value,omitempty"`
}

// ResponseHeaderAction sets (replaces), adds or deletes one header.
type ResponseHeaderAction struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

const (
	ResponseActionHeaders   = "headers"
	ResponseActionLog       = "log"
	ResponseActionErrorPage = "error_page"
	ResponseActionBlock     = "block"

	ResponseHeaderExists = "exists"
	ResponseHeaderAbsent = "absent"
	ResponseHeaderEquals = "equals"
	ResponseHeaderRegex  = "regex"

	ResponseHeaderSet    = "set"
	ResponseHeaderAdd    = "add"
	ResponseHeaderDelete = "delete"

	MaxSiteResponseRules         = 32
	MaxResponseRuleStatuses      = 16
	MaxResponseRuleHeaders       = 8
	MaxResponseRuleHeaderActions = 16
	MaxResponseHeaderValue       = 1024
	MaxResponseHeaderRegex       = 256

	// EdgeResponseRulesCapability is the site runtime document capability
	// of CAPABILITY_NAME_EDGE_RESPONSE_RULES (v1).
	EdgeResponseRulesCapability = "edge_response_rules"
)

var (
	responseRuleIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	responseHeaderNamePattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$")
)

// responseReservedHeaders are framing headers and the headers later
// header_filter slots own (Alt-Svc, HSTS, cache status): a rule cannot set
// or delete them (the HTTP policy's response list, httppolicycontrol).
var responseReservedHeaders = map[string]bool{
	"connection": true, "content-length": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-connection": true, "te": true, "trailer": true, "transfer-encoding": true, "upgrade": true,
	"alt-svc": true, "strict-transport-security": true, "x-cdn-cache": true, "x-cdn-cache-reason": true,
}

func responseHeaderReserved(name string) bool {
	return responseReservedHeaders[name] || strings.HasPrefix(name, "x-cdnca-")
}

func validResponseHeaderValue(value string, empty bool) bool {
	if value == "" {
		return empty
	}
	if len(value) > MaxResponseHeaderValue {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

// validateSiteResponseRules checks a site's rules (names already lower case).
func validateSiteResponseRules(rules []SiteResponseRule) error {
	if len(rules) > MaxSiteResponseRules {
		return ErrInvalidConfig
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if !responseRuleIDPattern.MatchString(rule.ID) || seen[rule.ID] ||
			len(rule.Statuses) > MaxResponseRuleStatuses || len(rule.Headers) > MaxResponseRuleHeaders {
			return ErrInvalidConfig
		}
		seen[rule.ID] = true
		for _, status := range rule.Statuses {
			if status.From < 100 || status.To > 599 || status.From > status.To {
				return ErrInvalidConfig
			}
		}
		for _, condition := range rule.Headers {
			if !responseHeaderNamePattern.MatchString(condition.Name) {
				return ErrInvalidConfig
			}
			switch condition.Op {
			case ResponseHeaderExists, ResponseHeaderAbsent:
				if condition.Value != "" {
					return ErrInvalidConfig
				}
			case ResponseHeaderEquals:
				if !validResponseHeaderValue(condition.Value, true) {
					return ErrInvalidConfig
				}
			case ResponseHeaderRegex:
				if condition.Value == "" || len(condition.Value) > MaxResponseHeaderRegex ||
					!validResponseHeaderValue(condition.Value, false) {
					return ErrInvalidConfig
				}
				if _, err := regexp.Compile(condition.Value); err != nil {
					return ErrInvalidConfig
				}
			default:
				return ErrInvalidConfig
			}
		}
		switch rule.Action {
		case ResponseActionHeaders:
			if len(rule.HeaderActions) == 0 || len(rule.HeaderActions) > MaxResponseRuleHeaderActions || rule.Status != 0 {
				return ErrInvalidConfig
			}
			for _, action := range rule.HeaderActions {
				if !responseHeaderNamePattern.MatchString(action.Name) || responseHeaderReserved(action.Name) {
					return ErrInvalidConfig
				}
				switch action.Kind {
				case ResponseHeaderSet, ResponseHeaderAdd:
					if !validResponseHeaderValue(action.Value, false) {
						return ErrInvalidConfig
					}
				case ResponseHeaderDelete:
					if action.Value != "" {
						return ErrInvalidConfig
					}
				default:
					return ErrInvalidConfig
				}
			}
		case ResponseActionLog:
			if len(rule.HeaderActions) != 0 || rule.Status != 0 {
				return ErrInvalidConfig
			}
		case ResponseActionErrorPage, ResponseActionBlock:
			if len(rule.HeaderActions) != 0 || rule.Status < 400 || rule.Status > 599 {
				return ErrInvalidConfig
			}
		default:
			return ErrInvalidConfig
		}
	}
	return nil
}
