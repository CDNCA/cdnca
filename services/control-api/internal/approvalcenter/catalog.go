// Package approvalcenter is the platform approval center
// (decisions Q1–Q8). An HTTP gate in front of the control API
// mux holds the managed operations a platform administration session sends:
// without a reason it answers 428 approval_required; with X-Approval-Reason it
// stores the request as-is and answers 202 approval_submitted. An approver's
// approval replays the stored request through the same handler with the
// approver's own session, so the business permission, revision and idempotency
// checks run unchanged. When the center is off the gate passes every request.
package approvalcenter

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Rule names one managed operation. The catalog is fixed in code (Q7); the
// settings only choose which entries are held.
type Rule struct {
	Name string `json:"name"`
	// Default rules are checked when the center is first turned on (Q7 first batch).
	Default bool `json:"default"`
	// Grouped requests from one browser action (X-Approval-Group) merge into
	// one approval request: the batch delete of L4 forwards is sent as one
	// DELETE per stream.
	Grouped bool `json:"grouped"`
	// TargetPath is the page where the operation is done (shown in the center).
	TargetPath string `json:"target_path"`
	match      func(method, path string, body []byte) bool
}

const (
	RuleSiteBatchDelete     = "site.batch_delete"
	RuleCacheWholeSite      = "cache.whole_site_purge"
	RuleFirewallPolicy      = "firewall.policy"
	RuleControlUpgrade      = "control.upgrade"
	RuleSiteBatchDisable    = "site.batch_disable"
	RuleNodeBatchDisable    = "node.batch_disable"
	RuleStreamBatchDelete   = "stream.batch_delete"
	RuleUserDelete          = "user.delete"
	maxInspectedBody        = 1 << 20
	headerApprovalReason    = "X-Approval-Reason"
	headerApprovalGroup     = "X-Approval-Group"
	headerApprovalExecution = "X-Cdnca-Approval-Execution"
)

var (
	rolloutActionPath = regexp.MustCompile(`^/v1/admin/control-upgrade-rollouts/[^/]+/(start|rollback)$`)
	streamPath        = regexp.MustCompile(`^/v1/streams/[0-9a-fA-F-]{36}$`)
	userPath          = regexp.MustCompile(`^/v1/admin/users/[0-9a-fA-F-]{36}$`)
)

// Catalog lists every managed operation in display order (Q7).
var Catalog = []Rule{
	{Name: RuleSiteBatchDelete, Default: true, TargetPath: "/site/list", match: func(method, path string, body []byte) bool {
		return method == http.MethodPost && path == "/v1/sites/batch-action" && jsonField(body, "action") == "delete"
	}},
	{Name: RuleCacheWholeSite, Default: true, TargetPath: "/site/cache-clean", match: func(method, path string, body []byte) bool {
		return method == http.MethodPost && path == "/v1/admin/cache-operations" && jsonField(body, "target_type") == "whole_site"
	}},
	{Name: RuleFirewallPolicy, Default: true, TargetPath: "/config/firewall-action", match: func(method, path string, _ []byte) bool {
		return method == http.MethodPut && (path == "/v1/firewall/policy" || path == "/v1/firewall-actions/policy") ||
			method == http.MethodPost && (path == "/v1/firewall/policy/recover" || path == "/v1/firewall-actions/policy/recover")
	}},
	{Name: RuleControlUpgrade, Default: true, TargetPath: "/sys/op", match: func(method, path string, _ []byte) bool {
		return method == http.MethodPost && (path == "/v1/admin/control-upgrade-plan/issue" || rolloutActionPath.MatchString(path))
	}},
	{Name: RuleSiteBatchDisable, TargetPath: "/site/list", match: func(method, path string, body []byte) bool {
		return method == http.MethodPost && path == "/v1/sites/batch-action" && jsonField(body, "action") == "disable"
	}},
	{Name: RuleNodeBatchDisable, TargetPath: "/node/list", match: func(method, path string, body []byte) bool {
		return method == http.MethodPost && path == "/v1/nodes/batch-admin-state" && jsonField(body, "admin_state") == "disabled"
	}},
	{Name: RuleStreamBatchDelete, Grouped: true, TargetPath: "/stream/list", match: func(method, path string, _ []byte) bool {
		return method == http.MethodDelete && streamPath.MatchString(path)
	}},
	{Name: RuleUserDelete, TargetPath: "/sys/user", match: func(method, path string, _ []byte) bool {
		return method == http.MethodDelete && userPath.MatchString(path)
	}},
}

// DefaultRules are the rules checked when the center is turned on the first time.
func DefaultRules() []string {
	var names []string
	for _, rule := range Catalog {
		if rule.Default {
			names = append(names, rule.Name)
		}
	}
	return names
}

func lookupRule(name string) (Rule, bool) {
	for _, rule := range Catalog {
		if rule.Name == name {
			return rule, true
		}
	}
	return Rule{}, false
}

// ValidRules reports whether names are distinct catalog entries.
func ValidRules(names []string) bool {
	seen := map[string]bool{}
	for _, name := range names {
		if _, ok := lookupRule(name); !ok || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

// matchRule returns the first enabled rule the request hits. The body is only
// inspected for the methods a rule can match.
func matchRule(enabled []string, method, path string, body []byte) (Rule, bool) {
	for _, name := range enabled {
		rule, ok := lookupRule(name)
		if ok && rule.match(method, path, body) {
			return rule, true
		}
	}
	return Rule{}, false
}

// candidate is a cheap pre-check before reading settings or the body: only
// write methods on the paths some catalog entry names can be held.
func candidate(method, path string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		return false
	}
	switch path {
	case "/v1/sites/batch-action", "/v1/admin/cache-operations", "/v1/firewall/policy", "/v1/firewall-actions/policy",
		"/v1/firewall/policy/recover", "/v1/firewall-actions/policy/recover", "/v1/admin/control-upgrade-plan/issue",
		"/v1/nodes/batch-admin-state":
		return true
	}
	return rolloutActionPath.MatchString(path) || streamPath.MatchString(path) || userPath.MatchString(path)
}

func jsonField(body []byte, key string) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return ""
	}
	var value string
	if json.Unmarshal(fields[key], &value) != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

// readBody reads at most maxInspectedBody bytes and puts the body back.
func readBody(r *http.Request) ([]byte, bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxInspectedBody+1))
	_ = r.Body.Close()
	if err != nil || len(body) > maxInspectedBody {
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, true
}
