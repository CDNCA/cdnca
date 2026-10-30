package edgeconfig

import (
	"strings"
	"testing"
)

// Response rules are validated with the site's access
// settings; reserved headers, bad regexes and inconsistent actions are
// refused.
func TestValidateSiteResponseRules(t *testing.T) {
	valid := func(change func(*SiteResponseRule)) SiteAccess {
		rule := SiteResponseRule{ID: "r1", Statuses: []StatusRange{{From: 500, To: 504}},
			Headers: []ResponseHeaderCondition{{Name: "x-powered-by", Op: ResponseHeaderExists}},
			Action:  ResponseActionHeaders, HeaderActions: []ResponseHeaderAction{{Kind: ResponseHeaderDelete, Name: "x-powered-by"}}}
		change(&rule)
		return SiteAccess{ResponseRules: []SiteResponseRule{rule}}
	}
	for name, access := range map[string]SiteAccess{
		"headers":    valid(func(*SiteResponseRule) {}),
		"any status": valid(func(r *SiteResponseRule) { r.Statuses = nil }),
		"set/add": valid(func(r *SiteResponseRule) {
			r.HeaderActions = []ResponseHeaderAction{{Kind: ResponseHeaderSet, Name: "cache-control", Value: "no-store"}, {Kind: ResponseHeaderAdd, Name: "x-a", Value: "1"}}
		}),
		"equals empty": valid(func(r *SiteResponseRule) { r.Headers = []ResponseHeaderCondition{{Name: "x-a", Op: ResponseHeaderEquals}} }),
		"regex":        valid(func(r *SiteResponseRule) { r.Headers = []ResponseHeaderCondition{{Name: "server", Op: ResponseHeaderRegex, Value: "^(?i)apache"}} }),
		"log":          valid(func(r *SiteResponseRule) { r.Action, r.HeaderActions = ResponseActionLog, nil }),
		"error_page":   valid(func(r *SiteResponseRule) { r.Action, r.HeaderActions, r.Status = ResponseActionErrorPage, nil, 502 }),
		"block":        valid(func(r *SiteResponseRule) { r.Action, r.HeaderActions, r.Status = ResponseActionBlock, nil, 403 }),
	} {
		if err := ValidateSiteAccess(access, []string{"example.com"}, false); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, access := range map[string]SiteAccess{
		"empty list":       {ResponseRules: []SiteResponseRule{}},
		"bad id":           valid(func(r *SiteResponseRule) { r.ID = "-x" }),
		"range reversed":   valid(func(r *SiteResponseRule) { r.Statuses = []StatusRange{{From: 504, To: 500}} }),
		"status 99":        valid(func(r *SiteResponseRule) { r.Statuses = []StatusRange{{From: 99, To: 200}} }),
		"upper name":       valid(func(r *SiteResponseRule) { r.Headers[0].Name = "X-Powered-By" }),
		"unknown op":       valid(func(r *SiteResponseRule) { r.Headers[0].Op = "contains" }),
		"exists value":     valid(func(r *SiteResponseRule) { r.Headers[0].Value = "x" }),
		"bad regex":        valid(func(r *SiteResponseRule) { r.Headers = []ResponseHeaderCondition{{Name: "a", Op: ResponseHeaderRegex, Value: "("}} }),
		"empty regex":      valid(func(r *SiteResponseRule) { r.Headers = []ResponseHeaderCondition{{Name: "a", Op: ResponseHeaderRegex}} }),
		"long regex":       valid(func(r *SiteResponseRule) { r.Headers = []ResponseHeaderCondition{{Name: "a", Op: ResponseHeaderRegex, Value: strings.Repeat("a", 257)}} }),
		"no header action": valid(func(r *SiteResponseRule) { r.HeaderActions = nil }),
		"reserved":         valid(func(r *SiteResponseRule) { r.HeaderActions[0].Name = "content-length" }),
		"reserved hsts":    valid(func(r *SiteResponseRule) { r.HeaderActions[0].Name = "strict-transport-security" }),
		"reserved prefix":  valid(func(r *SiteResponseRule) { r.HeaderActions[0].Name = "x-cdnca-site" }),
		"set no value":     valid(func(r *SiteResponseRule) { r.HeaderActions[0].Kind = ResponseHeaderSet }),
		"control value": valid(func(r *SiteResponseRule) {
			r.HeaderActions = []ResponseHeaderAction{{Kind: ResponseHeaderSet, Name: "x-a", Value: "a\r\nb: c"}}
		}),
		"headers status":  valid(func(r *SiteResponseRule) { r.Status = 403 }),
		"block 200":       valid(func(r *SiteResponseRule) { r.Action, r.HeaderActions, r.Status = ResponseActionBlock, nil, 200 }),
		"page no status":  valid(func(r *SiteResponseRule) { r.Action, r.HeaderActions = ResponseActionErrorPage, nil }),
		"block + headers": valid(func(r *SiteResponseRule) { r.Action, r.Status = ResponseActionBlock, 403 }),
		"unknown action":  valid(func(r *SiteResponseRule) { r.Action = "redirect" }),
		"duplicate id": {ResponseRules: []SiteResponseRule{
			{ID: "a", Action: ResponseActionLog}, {ID: "a", Action: ResponseActionLog}}},
	} {
		if ValidateSiteAccess(access, []string{"example.com"}, false) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if (SiteAccess{ResponseRules: []SiteResponseRule{{ID: "a", Action: ResponseActionLog}}}).Empty() {
		t.Fatal("access with response rules is empty")
	}
}
