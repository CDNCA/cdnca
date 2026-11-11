package edgeconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// String sets.
//
// A string set is a named list of members with a match mode and case
// sensitivity fixed at creation (control plane table security_string_sets,
// migration 652). A rule condition references one set by (id, revision)
// (WAFMatch.StringSets); the members travel once per site object in
// security.string_sets (edgesite.Security.StringSets, the same WAFStringSet
// shape), not inline in every rule, because 256 KiB x several rules would
// pass the 2 MiB site object limit.

// Match modes.
const (
	StringSetExact    = "exact"    // the value equals a member
	StringSetPrefix   = "prefix"   // the value starts with a member (bytes, no path boundary)
	StringSetSuffix   = "suffix"   // the value ends with a member
	StringSetContains = "contains" // the value contains a member
	StringSetWildcard = "wildcard" // the whole value matches a member, * any bytes, ? one byte
)

// StringSetModes are the match modes in display order.
var StringSetModes = []string{StringSetExact, StringSetPrefix, StringSetSuffix, StringSetContains, StringSetWildcard}

// Condition targets: the request values a string set condition reads (the
// cdnca_waf inspect values, decoded; host and ja4 are read directly).
const (
	StringSetTargetHost       = "host"
	StringSetTargetPath       = "path"
	StringSetTargetRequestURI = "request_uri"
	StringSetTargetUserAgent  = "user_agent"
	StringSetTargetReferer    = "referer"
	StringSetTargetHeader     = "header" // Key: the lower-case header name
	StringSetTargetJA4        = "ja4"    // exact, case-sensitive sets of JA4 fingerprints only
)

// StringSetTargets are the condition targets in display order.
var StringSetTargets = []string{StringSetTargetHost, StringSetTargetPath, StringSetTargetRequestURI,
	StringSetTargetUserAgent, StringSetTargetReferer, StringSetTargetHeader, StringSetTargetJA4}

const (
	// MaxStringSetMembers bounds one set's members (wildcard sets:
	// MaxStringSetWildcardMembers, each member is a regular expression).
	MaxStringSetMembers         = 10000
	MaxStringSetWildcardMembers = 2000
	// MaxStringSetMemberBytes bounds one member, MaxStringSetBytes the sum
	// of a set's member bytes (security_string_sets.entries_bytes).
	MaxStringSetMemberBytes = 512
	MaxStringSetBytes       = 256 << 10
	// MaxStringSetWildcardStars bounds the * of one wildcard member.
	MaxStringSetWildcardStars = 3
	// MaxWAFStringSetsPerRule bounds the string set conditions of one rule
	// (like MaxWAFIPListsPerRule); they count toward the 8 conditions.
	MaxWAFStringSetsPerRule = 4
	// MaxSiteStringSets and MaxSiteStringSetBytes bound the distinct sets a
	// site object carries and their member bytes together.
	MaxSiteStringSets     = 16
	MaxSiteStringSetBytes = 512 << 10
	// MaxStringSetsPerScope bounds the sets of one owner scope (as IP lists).
	MaxStringSetsPerScope = 200
)

// RuleOpStringSet is the rule plan operation of a string set condition; its
// value is StringSetConditionSpec. The node resolves the set in the plan's
// string sets by (id, revision) and refuses the whole plan without it.
const RuleOpStringSet = "string_set"

// WAFStringSetRef is a string set condition: a value of Target (Key names
// the header) is (Negate: is not) matched by a member of set SetID at
// Revision. in_string_set holds when any value matches any member;
// not_in_string_set when no value matches.
type WAFStringSetRef struct {
	SetID    string `json:"set_id"`
	Revision int64  `json:"revision"`
	Target   string `json:"target"`
	Key      string `json:"key,omitempty"`
	Negate   bool   `json:"negate,omitempty"`
}

// WAFStringSet is one set's published content: Members are canonical
// (CanonicalStringSetMembers: trimmed, ASCII lower case when not
// CaseSensitive, unique, in byte order).
type WAFStringSet struct {
	ID            string   `json:"id"`
	Revision      int64    `json:"revision"`
	Mode          string   `json:"mode"`
	CaseSensitive bool     `json:"case_sensitive"`
	Members       []string `json:"members"`
}

// String set entry error reasons (the control plane's validation_error
// reason; §7).
const (
	StringSetReasonEmpty         = "empty"
	StringSetReasonTooLong       = "too_long"
	StringSetReasonInvalidUTF8   = "invalid_utf8"
	StringSetReasonControl       = "control_character"
	StringSetReasonWildcardStars = "wildcard_too_many_stars"
	StringSetReasonWildcardOnly  = "wildcard_only_wildcards"
	StringSetReasonCount         = "too_many_entries" // also: no entry at all
	StringSetReasonTooLarge      = "too_large"
)

// StringSetEntryError is a refused string set entry: Index is the input
// position (entries[Index]), -1 for the whole set. It wraps ErrInvalidConfig.
type StringSetEntryError struct {
	Index  int
	Reason string
}

func (err *StringSetEntryError) Error() string {
	if err.Index < 0 {
		return "string set: " + err.Reason
	}
	return fmt.Sprintf("string set entry %d: %s", err.Index, err.Reason)
}

func (err *StringSetEntryError) Unwrap() error { return ErrInvalidConfig }

// ValidStringSetMode reports whether mode is a match mode.
func ValidStringSetMode(mode string) bool { return slices.Contains(StringSetModes, mode) }

// CanonicalStringSetMembers checks and normalizes a set's entries: each is
// trimmed of surrounding white space, then must be 1-512 bytes of valid
// UTF-8 without control characters; a case-insensitive set lower-cases A-Z
// only (as the node's LOWER table); a wildcard member has at most 3 * and is
// not only * and ?. The result is unique and in byte order, 1-10000 members
// (wildcard 1-2000), at most 256 KiB together; size is that byte total.
func CanonicalStringSetMembers(mode string, caseSensitive bool, entries []string) ([]string, int, error) {
	if !ValidStringSetMode(mode) {
		return nil, 0, ErrInvalidConfig
	}
	members := make([]string, 0, len(entries))
	for index, raw := range entries {
		member := strings.TrimSpace(raw)
		if reason := stringSetMemberReason(mode, member); reason != "" {
			return nil, 0, &StringSetEntryError{Index: index, Reason: reason}
		}
		if !caseSensitive {
			member = asciiLower(member)
		}
		members = append(members, member)
	}
	slices.Sort(members)
	members = slices.Compact(members)
	limit := MaxStringSetMembers
	if mode == StringSetWildcard {
		limit = MaxStringSetWildcardMembers
	}
	if len(members) == 0 || len(members) > limit {
		return nil, 0, &StringSetEntryError{Index: -1, Reason: StringSetReasonCount}
	}
	size := 0
	for _, member := range members {
		size += len(member)
	}
	if size > MaxStringSetBytes {
		return nil, 0, &StringSetEntryError{Index: -1, Reason: StringSetReasonTooLarge}
	}
	return members, size, nil
}

func stringSetMemberReason(mode, member string) string {
	switch {
	case member == "":
		return StringSetReasonEmpty
	case len(member) > MaxStringSetMemberBytes:
		return StringSetReasonTooLong
	case !utf8.ValidString(member):
		return StringSetReasonInvalidUTF8
	case strings.IndexFunc(member, unicode.IsControl) >= 0:
		return StringSetReasonControl
	}
	if mode == StringSetWildcard {
		if strings.Count(member, "*") > MaxStringSetWildcardStars {
			return StringSetReasonWildcardStars
		}
		if strings.Trim(member, "*?") == "" {
			return StringSetReasonWildcardOnly
		}
	}
	return ""
}

// asciiLower lower-cases A-Z only (non-ASCII letters compare as they are).
func asciiLower(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, value)
}

// ValidateWAFStringSet checks a published set: identity, mode and members
// already canonical.
func ValidateWAFStringSet(set WAFStringSet) error {
	if !uuidPattern.MatchString(set.ID) || set.Revision < 1 || set.Revision > 1<<53-1 {
		return ErrInvalidConfig
	}
	members, _, err := CanonicalStringSetMembers(set.Mode, set.CaseSensitive, set.Members)
	if err != nil {
		return err
	}
	if !slices.Equal(members, set.Members) {
		return ErrInvalidConfig
	}
	return nil
}

// StringSetTargetAccepts reports whether a condition on target may use set:
// ja4 needs an exact, case-sensitive set of JA4 fingerprints
// (string_set_target_mismatch otherwise); every other target takes any set.
func StringSetTargetAccepts(target string, set WAFStringSet) bool {
	if target != StringSetTargetJA4 {
		return true
	}
	return set.Mode == StringSetExact && set.CaseSensitive && !slices.ContainsFunc(set.Members, func(member string) bool { return !ValidJA4(member) })
}

func normalizeWAFStringSetRefs(values []WAFStringSetRef) ([]WAFStringSetRef, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) == 0 || len(values) > MaxWAFStringSetsPerRule {
		return nil, ErrInvalidConfig
	}
	result := make([]WAFStringSetRef, len(values))
	for index, value := range values {
		if !uuidPattern.MatchString(value.SetID) || value.Revision < 1 || value.Revision > 1<<53-1 ||
			!slices.Contains(StringSetTargets, value.Target) ||
			(value.Target == StringSetTargetHeader) != (value.Key != "") ||
			value.Key != "" && !wafInspectHeaderKey.MatchString(value.Key) {
			return nil, ErrInvalidConfig
		}
		result[index] = value
	}
	return result, nil
}

// StringSetConditionSpec is the rule plan value of one condition: JSON
// {"id","revision","target","key","negate"} (every key present).
func StringSetConditionSpec(value WAFStringSetRef) string {
	return conditionSpec(struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
		Target   string `json:"target"`
		Key      string `json:"key"`
		Negate   bool   `json:"negate"`
	}{value.SetID, value.Revision, value.Target, value.Key, value.Negate})
}

// conditionSpec is the canonical JSON of a rule plan condition value: struct
// field order, compact, no HTML escaping.
func conditionSpec(value any) string {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return strings.TrimSuffix(buffer.String(), "\n")
}
