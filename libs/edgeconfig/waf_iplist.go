package edgeconfig

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// WAFIPList is an "in IP list" rule condition: the client
// address ($remote_addr; an IPv4-mapped IPv6 address as IPv4, like nginx geo)
// is inside one of CIDRs, the published content of the named IP list ListID
// at Revision; Negate inverts it. The control plane expands the list at
// publication time, so a list change reaches the nodes only through a new
// release (republished automatically). Needs CAPABILITY_NAME_WAF v4.
type WAFIPList struct {
	ListID   string   `json:"list_id"`
	Revision int64    `json:"revision"`
	CIDRs    []string `json:"cidrs"`
	Negate   bool     `json:"negate,omitempty"`
}

const (
	// MaxWAFIPListsPerRule bounds the IP list conditions of one rule.
	MaxWAFIPListsPerRule = 4
	// MaxWAFIPListEntries bounds one list's CIDRs.
	MaxWAFIPListEntries = 10000
	// IP list conditions run cdnca_waf.ip_list (lua-resty-ipmatcher).
	ipListLuaFunction = "ip_list"
)

func normalizeWAFIPLists(values []WAFIPList) ([]WAFIPList, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) == 0 || len(values) > MaxWAFIPListsPerRule {
		return nil, ErrInvalidConfig
	}
	result := make([]WAFIPList, len(values))
	for index, value := range values {
		if !uuidPattern.MatchString(value.ListID) || value.Revision < 1 || value.Revision > 1<<53-1 ||
			len(value.CIDRs) == 0 || len(value.CIDRs) > MaxWAFIPListEntries {
			return nil, ErrInvalidConfig
		}
		cidrs := make([]string, len(value.CIDRs))
		for position, raw := range value.CIDRs {
			prefix, err := normalizeCIDR(raw)
			if err != nil || prefix.String() != raw {
				return nil, ErrInvalidConfig
			}
			cidrs[position] = raw
		}
		if !slices.IsSortedFunc(cidrs, compareIPListCIDR) || len(slices.Compact(slices.Clone(cidrs))) != len(cidrs) {
			return nil, ErrInvalidConfig
		}
		result[index] = WAFIPList{ListID: value.ListID, Revision: value.Revision, CIDRs: cidrs, Negate: value.Negate}
	}
	return result, nil
}

// CanonicalIPListCIDRs masks, deduplicates and orders an IP list's entries
// (single addresses become /32 or /128) as WAFIPList.CIDRs must be.
func CanonicalIPListCIDRs(values []string) ([]string, error) {
	cidrs := make([]string, 0, len(values))
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if address, err := netip.ParseAddr(raw); err == nil {
			raw = netip.PrefixFrom(address, address.BitLen()).String()
		}
		prefix, err := normalizeCIDR(raw)
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, prefix.String())
	}
	slices.SortFunc(cidrs, compareIPListCIDR)
	cidrs = slices.Compact(cidrs)
	if len(cidrs) == 0 || len(cidrs) > MaxWAFIPListEntries {
		return nil, ErrInvalidConfig
	}
	return cidrs, nil
}

func compareIPListCIDR(left, right string) int { return strings.Compare(left, right) }

// IPListConditionSpec is the cdnca_waf.ip_list argument of one condition:
// JSON {"id","revision","negate","cidrs"} (the module caches the matcher by
// the whole text, so two revisions never share one).
func IPListConditionSpec(value WAFIPList) string {
	encoded, _ := json.Marshal(struct {
		ID       string   `json:"id"`
		Revision int64    `json:"revision"`
		Negate   bool     `json:"negate"`
		CIDRs    []string `json:"cidrs"`
	}{value.ListID, value.Revision, value.Negate, value.CIDRs})
	return string(encoded)
}

// RenderWAFIPListCondition is the Lua condition of one IP list condition.
func RenderWAFIPListCondition(value WAFIPList) string {
	return "require(" + strconv.Quote(wafInspectLuaModule) + ")." + ipListLuaFunction + "(" + luaLongString(IPListConditionSpec(value)) + ")"
}

// SecurityPoliciesUseIPLists reports whether a rule has an IP list condition
// (the release loads the security Lua directory).
func SecurityPoliciesUseIPLists(policies []SecurityPolicy) bool {
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if rule.Match.IPLists != nil {
				return true
			}
		}
	}
	return false
}
