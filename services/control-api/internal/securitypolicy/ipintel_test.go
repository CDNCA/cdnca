package securitypolicy

import (
	"errors"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

// G3-c: WAF rules may match the client address' carrier / IDC tag, ASN,
// country, province and city (node IP intelligence library).
func TestNormalizeAcceptsIPIntelWAFConditions(t *testing.T) {
	for name, test := range map[string]struct {
		condition Condition
		values    []string
	}{
		"carrier set":  {Condition{Field: "carrier", Operator: "in", Values: []string{"Carrier:CN-Unicom", "carrier:cn-telecom"}}, []string{"carrier:cn-telecom", "carrier:cn-unicom"}},
		"idc":          {Condition{Field: "ip_tag", Operator: "equals", Values: []string{"idc:global"}}, []string{"idc:global"}},
		"not idc":      {Condition{Field: "ip_tag", Operator: "not_in", Values: []string{"idc:cn", "idc:global"}}, []string{"idc:cn", "idc:global"}},
		"asn":          {Condition{Field: "asn", Operator: "number_eq", Values: []string{"13335"}}, []string{"13335"}},
		"asn set":      {Condition{Field: "asn", Operator: "in", Values: []string{"4134", "4837"}}, []string{"4134", "4837"}},
		"country":      {Condition{Field: "country", Operator: "not_equals", Values: []string{"cn"}}, []string{"CN"}},
		"province":     {Condition{Field: "province", Operator: "in", Values: []string{"440000", "110000"}}, []string{"110000", "440000"}},
		"city":         {Condition{Field: "city", Operator: "equals", Values: []string{"440300"}}, []string{"440300"}},
		"county-level": {Condition{Field: "city", Operator: "equals", Values: []string{"429004"}}, []string{"429004"}},
	} {
		t.Run(name, func(t *testing.T) {
			fields := validFields(test.condition)
			fields.Kind = KindWAF
			if err := normalizePublishableFields(&fields, false); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got := fields.Rules[0].Conditions[0].Values; !slices.Equal(got, test.values) {
				t.Fatalf("values = %v, want %v", got, test.values)
			}
		})
	}
}

func TestNormalizeRejectsInvalidIPIntelConditions(t *testing.T) {
	for name, test := range map[string]struct {
		kind      string
		condition Condition
	}{
		"carrier with idc tag": {KindWAF, Condition{Field: "carrier", Operator: "equals", Values: []string{"idc:cn"}}},
		"ip_tag with carrier":  {KindWAF, Condition{Field: "ip_tag", Operator: "equals", Values: []string{"carrier:cn-telecom"}}},
		"unknown carrier":      {KindWAF, Condition{Field: "carrier", Operator: "equals", Values: []string{"carrier:cn-other"}}},
		"carrier prefix op":    {KindWAF, Condition{Field: "carrier", Operator: "prefix", Values: []string{"carrier:"}}},
		"province is a city":   {KindWAF, Condition{Field: "province", Operator: "equals", Values: []string{"440300"}}},
		"city is a province":   {KindWAF, Condition{Field: "city", Operator: "equals", Values: []string{"440000"}}},
		"asn range on node":    {KindWAF, Condition{Field: "asn", Operator: "number_gte", Values: []string{"100"}}},
		"CC carrier":           {KindCC, Condition{Field: "carrier", Operator: "equals", Values: []string{"carrier:cn-telecom"}}},
		"region with letters":  {KindWAF, Condition{Field: "city", Operator: "equals", Values: []string{"44030a"}}},
	} {
		t.Run(name, func(t *testing.T) {
			fields := validFields(test.condition)
			fields.Kind = test.kind
			if test.kind == KindCC {
				fields.Rules[0].Action = ActionRateLimit
				fields.Rules[0].ActionConfig = ActionConfig{RateLimit: &RateLimitConfig{
					Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 10, ResponseAction: "reject_429",
				}}
			}
			if err := normalizePublishableFields(&fields, false); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

// The node renderer (libs/edgeconfig) keeps its own copy of the frozen tag
// table of the library format (libs/entitlement/ipintel); they must agree
// bit for bit, and the capability version is the format's.
func TestIPIntelTagTableMatchesLibraryFormat(t *testing.T) {
	definitions := ipintel.TagDefinitions()
	names := edgeconfig.IPIntelTagNames()
	if len(definitions) != len(names) {
		t.Fatalf("edgeconfig tags %v, library tags %v", names, definitions)
	}
	for index, definition := range definitions {
		bit, ok := edgeconfig.IPIntelTagBit(definition.Name)
		if !ok || bit != definition.Bit || names[index] != definition.Name {
			t.Fatalf("tag %+v: edgeconfig bit %d,%v name %s", definition, bit, ok, names[index])
		}
	}
	if edgeconfig.IPIntelCapabilityVersion != ipintel.CapabilityVersion {
		t.Fatalf("capability version %d != format %d", edgeconfig.IPIntelCapabilityVersion, ipintel.CapabilityVersion)
	}
}
