package securitypolicy

import (
	"bytes"
	"encoding/json"
	"slices"
)

// storedContent is what an update writes to a policy row besides its
// bookkeeping (revision, updated_by, updated_at).
type storedContent struct {
	Kind          string       `json:"kind"`
	Name          string       `json:"name"`
	Description   string       `json:"description"`
	Enabled       bool         `json:"enabled"`
	DefaultAction string       `json:"default_action"`
	Rules         []Rule       `json:"rules"`
	CCSettings    *CCSettings  `json:"cc_settings"`
	WAFSettings   *WAFSettings `json:"waf_settings"`
}

// sameStoredContent reports whether normalized update fields (rule IDs
// assigned) would store exactly what the policy already holds
// . Both sides are encoded the
// way the row is written, so key order in the stored JSON does not matter;
// any doubt (an encoding difference) reads as changed and is written. The
// matcher / filter versions of reference rules do not count: an edit that
// leaves their expansion as stored (a rename) changes nothing the nodes run.
func sameStoredContent(current Policy, fields PolicyFields) (bool, error) {
	before, err := json.Marshal(storedContent{current.Kind, current.Name, current.Description, current.Enabled,
		current.DefaultAction, withoutCCReferenceVersions(current.Rules), current.CCSettings, current.WAFSettings})
	if err != nil {
		return false, err
	}
	after, err := json.Marshal(storedContent{fields.Kind, fields.Name, fields.Description, fields.Enabled,
		fields.DefaultAction, withoutCCReferenceVersions(fields.Rules), fields.CCSettings, fields.WAFSettings})
	if err != nil {
		return false, err
	}
	return bytes.Equal(before, after), nil
}

func withoutCCReferenceVersions(rules []Rule) []Rule {
	if !hasCCReferences(rules) {
		return rules
	}
	result := slices.Clone(rules)
	for index, rule := range result {
		if rule.CCReference != nil {
			ref := *rule.CCReference
			ref.MatcherVersion, ref.Filter1Version, ref.Filter2Version = 0, 0, 0
			result[index].CCReference = &ref
		}
	}
	return result
}
