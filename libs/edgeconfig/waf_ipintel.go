package edgeconfig

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// WAFIPIntel is a request condition on the node's signed IP intelligence
// library (G3, docs/architecture/ip-intel-artifact.md): the client
// address' tags (carrier:* / idc:*), ASN, country, province or city, looked
// up by the Lua module cdnca_iplib (edge/openresty/iplib) in the mmapped
// library. Values are sorted and unique; the condition holds when the
// address has any of them, or, when Negate, none of them (an address the
// library does not know has none). While a node has no library loaded every
// such condition is false, negated or not. A rule using it needs
// CAPABILITY_NAME_IP_INTEL v2.
type WAFIPIntel struct {
	Field  WAFIPIntelField `json:"field"`
	Negate bool            `json:"negate,omitempty"`
	Values []string        `json:"values"`
}

type WAFIPIntelField string

const (
	WAFIPIntelTag      WAFIPIntelField = "tag"
	WAFIPIntelASN      WAFIPIntelField = "asn"
	WAFIPIntelCountry  WAFIPIntelField = "country"
	WAFIPIntelProvince WAFIPIntelField = "province"
	WAFIPIntelCity     WAFIPIntelField = "city"

	// IPIntelLuaModule is edge/openresty/iplib/cdnca_iplib.lua, installed
	// next to cdnca_waf.lua (CCV2LuaPackagePath) and, for the stream
	// subsystem (L4 rules), in /opt/cdnca/l4geo.
	IPIntelLuaModule = "cdnca_iplib"
	// IPIntelCapabilityVersion is CAPABILITY_NAME_IP_INTEL v2 (format v2 library).
	IPIntelCapabilityVersion uint32 = 2
	// MaxWAFIPIntelValues bounds one condition's value set.
	MaxWAFIPIntelValues = 64
	maxWAFIPIntelPerRule = 4
)

// ipIntelTagBits is the frozen tag table of the library format
// (libs/entitlement/ipintel tagDefinitions; control-api checks both agree).
var ipIntelTagBits = map[string]uint8{
	"carrier:cn-telecom": 0, "carrier:cn-unicom": 1, "carrier:cn-mobile": 2, "carrier:cn-cernet": 3,
	"carrier:cn-cstnet": 4, "carrier:cn-drpeng": 5, "carrier:cn-cbn": 6,
	"idc:cn": 16, "idc:global": 17,
}

// IPIntelTagBit returns the library bit of a rule tag name.
func IPIntelTagBit(name string) (uint8, bool) {
	bit, ok := ipIntelTagBits[name]
	return bit, ok
}

// IPIntelTagNames lists the rule tag names in bit order.
func IPIntelTagNames() []string {
	names := make([]string, 0, len(ipIntelTagBits))
	for name := range ipIntelTagBits {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return ipIntelTagBits[names[i]] < ipIntelTagBits[names[j]] })
	return names
}

// ValidIPIntelValue reports whether value is a canonical value of field:
// a tag name, an ASN 1..4294967295, an ISO 3166-1 alpha-2 code, a GB/T 2260
// province code (xx0000) or city code (six digits, not a province code).
func ValidIPIntelValue(field WAFIPIntelField, value string) bool {
	switch field {
	case WAFIPIntelTag:
		_, ok := ipIntelTagBits[value]
		return ok
	case WAFIPIntelCountry:
		return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
	case WAFIPIntelASN:
		number, err := strconv.ParseUint(value, 10, 32)
		return err == nil && number != 0 && strconv.FormatUint(number, 10) == value
	case WAFIPIntelProvince, WAFIPIntelCity:
		number, err := strconv.ParseUint(value, 10, 32)
		if err != nil || len(value) != 6 || number < 110000 || strconv.FormatUint(number, 10) != value {
			return false
		}
		return field == WAFIPIntelProvince && number%10000 == 0 || field == WAFIPIntelCity && number%10000 != 0
	}
	return false
}

// NormalizeWAFIPIntel validates conditions the way the renderer does, so the
// node precheck can independently re-derive the rendered conditions. Values
// are sorted (numbers numerically) and conditions ordered canonically.
func NormalizeWAFIPIntel(values []WAFIPIntel) ([]WAFIPIntel, error) { return normalizeWAFIPIntel(values) }

func normalizeWAFIPIntel(conditions []WAFIPIntel) ([]WAFIPIntel, error) {
	if conditions == nil {
		return nil, nil
	}
	if len(conditions) == 0 || len(conditions) > maxWAFIPIntelPerRule {
		return nil, ErrInvalidConfig
	}
	result := make([]WAFIPIntel, len(conditions))
	for index, condition := range conditions {
		if len(condition.Values) == 0 || len(condition.Values) > MaxWAFIPIntelValues {
			return nil, ErrInvalidConfig
		}
		values := append([]string(nil), condition.Values...)
		for _, value := range values {
			if !ValidIPIntelValue(condition.Field, value) {
				return nil, ErrInvalidConfig
			}
		}
		sort.Slice(values, func(i, j int) bool { return ipIntelValueLess(condition.Field, values[i], values[j]) })
		for position := 1; position < len(values); position++ {
			if values[position] == values[position-1] {
				return nil, ErrInvalidConfig
			}
		}
		result[index] = WAFIPIntel{Field: condition.Field, Negate: condition.Negate, Values: values}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Field != result[j].Field {
			return result[i].Field < result[j].Field
		}
		if result[i].Negate != result[j].Negate {
			return !result[i].Negate
		}
		return strings.Join(result[i].Values, ",") < strings.Join(result[j].Values, ",")
	})
	for index := 1; index < len(result); index++ {
		if slices.Equal(result[index].Values, result[index-1].Values) && result[index].Field == result[index-1].Field &&
			result[index].Negate == result[index-1].Negate {
			return nil, ErrInvalidConfig
		}
	}
	return result, nil
}

func ipIntelValueLess(field WAFIPIntelField, left, right string) bool {
	switch field {
	case WAFIPIntelTag:
		return ipIntelTagBits[left] < ipIntelTagBits[right]
	case WAFIPIntelCountry:
		return left < right
	}
	leftNumber, _ := strconv.ParseUint(left, 10, 32)
	rightNumber, _ := strconv.ParseUint(right, 10, 32)
	return leftNumber < rightNumber
}

// RenderWAFIPIntelCondition is the Lua condition for one normalized
// condition: cdnca_iplib.match("<spec>"), spec as cdnca_iplib parses it
// (tag=<64-bit mask in 16 hex digits>, asn|country|province|city=v1,v2;
// "!=" negates). Spec characters are [a-z0-9A-Z=!,] only.
func RenderWAFIPIntelCondition(condition WAFIPIntel) string {
	return "require(" + strconv.Quote(IPIntelLuaModule) + ").match(" + strconv.Quote(IPIntelConditionSpec(condition)) + ")"
}

// IPIntelConditionSpec is the cdnca_iplib condition spec of one normalized
// condition (RenderWAFIPIntelCondition; L4 guard rules hand it to the stream
// module as data).
func IPIntelConditionSpec(condition WAFIPIntel) string {
	operator := "="
	if condition.Negate {
		operator = "!="
	}
	list := strings.Join(condition.Values, ",")
	if condition.Field == WAFIPIntelTag {
		var mask uint64
		for _, value := range condition.Values {
			mask |= 1 << ipIntelTagBits[value]
		}
		list = fmt.Sprintf("%016x", mask)
	}
	return string(condition.Field) + operator + list
}

// WAFIPIntelCovers reports whether every request matched by conditions
// current is also matched by conditions previous (nil = no condition): each
// previous condition has a current one on the same field and sense whose
// value set is a subset (=) or a superset (!=) of it.
func WAFIPIntelCovers(previous, current []WAFIPIntel) bool {
	for _, want := range previous {
		covered := false
		for _, have := range current {
			if have.Field != want.Field || have.Negate != want.Negate {
				continue
			}
			if !want.Negate && subsetStrings(have.Values, want.Values) || want.Negate && subsetStrings(want.Values, have.Values) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func subsetStrings(values, of []string) bool {
	for _, value := range values {
		if !slices.Contains(of, value) {
			return false
		}
	}
	return true
}

// IPIntelPolicyCondition maps one security policy condition (control-api
// securitypolicy) to its node condition. ok is false when field is not an
// IP intelligence field. Fields: carrier (carrier:* tag names), ip_tag
// (idc:cn / idc:global), asn, country, province, city. Operators: equals /
// not_equals (one value), in / not_in (a set); asn also number_eq (one
// value). control-api (edgeWAFMatch / compileSecurityRuleMatches) and the
// agent precheck both use it, so they derive the same condition.
func IPIntelPolicyCondition(field, operator, key string, values []string) (WAFIPIntel, bool, error) {
	var target WAFIPIntelField
	prefix := ""
	switch field {
	case "carrier":
		target, prefix = WAFIPIntelTag, "carrier:"
	case "ip_tag":
		target, prefix = WAFIPIntelTag, "idc:"
	case "asn":
		target = WAFIPIntelASN
	case "country":
		target = WAFIPIntelCountry
	case "province":
		target = WAFIPIntelProvince
	case "city":
		target = WAFIPIntelCity
	default:
		return WAFIPIntel{}, false, nil
	}
	condition := WAFIPIntel{Field: target, Values: append([]string(nil), values...)}
	single := false
	switch operator {
	case "equals":
		single = true
	case "number_eq":
		single = target == WAFIPIntelASN
		if !single {
			return WAFIPIntel{}, true, ErrInvalidConfig
		}
	case "not_equals":
		single, condition.Negate = true, true
	case "in":
	case "not_in":
		condition.Negate = true
	default:
		return WAFIPIntel{}, true, ErrInvalidConfig
	}
	if key != "" || len(values) == 0 || single && len(values) != 1 {
		return WAFIPIntel{}, true, ErrInvalidConfig
	}
	for _, value := range values {
		if !strings.HasPrefix(value, prefix) || !ValidIPIntelValue(target, value) {
			return WAFIPIntel{}, true, ErrInvalidConfig
		}
	}
	normalized, err := normalizeWAFIPIntel([]WAFIPIntel{condition})
	if err != nil {
		return WAFIPIntel{}, true, err
	}
	return normalized[0], true, nil
}

// SecurityPoliciesUseIPIntel reports whether any rule of one site's /
// listener's bound security policies has an IP intelligence condition (a
// release that needs CAPABILITY_NAME_IP_INTEL v2).
func SecurityPoliciesUseIPIntel(policies []SecurityPolicy) bool {
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if rule.Match.IPIntel != nil {
				return true
			}
		}
	}
	return false
}

// SpecUsesIPIntel is SecurityPoliciesUseIPIntel over every site.
func SpecUsesIPIntel(sites []Site) bool {
	for _, site := range sites {
		if SecurityPoliciesUseIPIntel(site.SecurityPolicies) {
			return true
		}
	}
	return false
}
