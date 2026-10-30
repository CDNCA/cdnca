package node

import (
	"context"
	"errors"
	"slices"
	"testing"
)

type fakeIPLocationSource struct {
	library *IPLocationLibrary
	answers map[string]*NodeIPLocation
}

func (source fakeIPLocationSource) Library(context.Context) (IPLocationLibrary, bool) {
	if source.library == nil {
		return IPLocationLibrary{}, false
	}
	return *source.library, true
}

func (source fakeIPLocationSource) Locate(_ context.Context, addresses []string) map[string]*NodeIPLocation {
	result := map[string]*NodeIPLocation{}
	for _, address := range addresses {
		result[address] = source.answers[address]
	}
	return result
}

var (
	shanghai = NodeIPLocation{Country: "中国", Province: "上海市", City: "上海市", ISP: "中国电信", CountryCode: "CN"}
	tokyo    = NodeIPLocation{Country: "日本", CountryCode: "JP"}
)

func TestNodeAddressesResolveOrder(t *testing.T) {
	v4, v6 := "192.0.2.10", "2001:0db8::10"
	got := nodeAddresses(&v4, &v6, []string{"198.51.100.1", "192.0.2.10", "bad"})
	if want := []string{"192.0.2.10", "2001:db8::10", "198.51.100.1"}; !slices.Equal(got, want) {
		t.Fatalf("nodeAddresses() = %v, want %v", got, want)
	}
	if got := nodeAddresses(nil, nil, nil); len(got) != 0 {
		t.Fatalf("no addresses = %v", got)
	}
}

func TestResolveIPLocationFirstPlacedAddress(t *testing.T) {
	library := &IPLocationLibrary{Revision: 7, Version: "2026.10.27"}
	source := fakeIPLocationSource{library: library, answers: map[string]*NodeIPLocation{"198.51.100.1": &tokyo}}
	outcome, address, location, got := resolveIPLocation(context.Background(), source, []string{"192.0.2.10", "198.51.100.1"})
	if outcome != IPLocationResolved || address != "198.51.100.1" || location != tokyo || got != *library {
		t.Fatalf("resolve = %s %s %#v %#v", outcome, address, location, got)
	}
	outcome, _, location, _ = resolveIPLocation(context.Background(), source, []string{"192.0.2.10"})
	if outcome != IPLocationUnresolved || location != (NodeIPLocation{}) {
		t.Fatalf("unplaced = %s %#v", outcome, location)
	}
	outcome, _, _, _ = resolveIPLocation(context.Background(), fakeIPLocationSource{}, []string{"192.0.2.10"})
	if outcome != IPLocationNoLibrary {
		t.Fatalf("no library = %s", outcome)
	}
}

func TestIPLocationDue(t *testing.T) {
	addresses := []string{"192.0.2.10"}
	revision, other := int64(7), int64(6)
	resolved, unresolved, noLibrary := IPLocationResolved, IPLocationUnresolved, IPLocationNoLibrary
	library := IPLocationLibrary{Revision: 7}
	for name, test := range map[string]struct {
		resolved   []string
		revision   *int64
		outcome    *string
		hasLibrary bool
		want       bool
	}{
		"never resolved (existing node after upgrade)": {nil, nil, nil, true, true},
		"same addresses and library":                   {addresses, &revision, &resolved, true, false},
		"unresolved with same library: not retried":     {addresses, &revision, &unresolved, true, false},
		"address changed":                               {[]string{"192.0.2.11"}, &revision, &resolved, true, true},
		"secondary IP added":                            {nil, &revision, &resolved, true, true},
		"library updated":                               {addresses, &other, &resolved, true, true},
		"library arrived":                               {addresses, &revision, &noLibrary, true, true},
		"still no library":                              {addresses, &revision, &noLibrary, false, false},
		"library gone":                                  {addresses, &revision, &resolved, false, true},
	} {
		got := ipLocationDue(addresses, test.resolved, test.revision, test.outcome, library, test.hasLibrary)
		if got != test.want {
			t.Errorf("%s: due = %v, want %v", name, got, test.want)
		}
	}
}

func TestEffectiveIPLocationKeepsManualFields(t *testing.T) {
	stored := NodeIPLocation{Country: "中国", Province: "浙江", City: "杭州", ISP: "BGP", CountryCode: "CN"}
	got := effectiveIPLocation([]string{"city", "isp"}, stored, shanghai)
	want := NodeIPLocation{Country: "中国", Province: "上海市", City: "杭州", ISP: "BGP", CountryCode: "CN"}
	if got != want {
		t.Fatalf("effective = %#v, want %#v", got, want)
	}
	if got := effectiveIPLocation(nil, stored, NodeIPLocation{}); got != (NodeIPLocation{}) {
		t.Fatalf("no manual fields follow the automatic (unresolved) values: %#v", got)
	}
}

func TestApplyIPLocationWriteMarksAndRestores(t *testing.T) {
	before := DefaultNodeManagementSettings()
	before.IPLocation = shanghai

	// an administrator corrects the city: it becomes manual
	after := before
	after.IPLocation.City = "杭州"
	after.IPLocationManual = []string{"city"}
	applyIPLocationWrite(before, &after, shanghai)
	if after.IPLocation.City != "杭州" || !slices.Equal(after.IPLocationManual, []string{"city"}) {
		t.Fatalf("manual city = %#v %v", after.IPLocation, after.IPLocationManual)
	}

	// a manual field cannot be faked for the others: they stay automatic
	forged := before
	forged.IPLocation.Country = "美国"
	forged.IPLocationManual = []string{}
	applyIPLocationWrite(before, &forged, shanghai)
	if forged.IPLocation != shanghai || forged.IPLocationManual != nil {
		t.Fatalf("non-manual fields = %#v %v", forged.IPLocation, forged.IPLocationManual)
	}

	// 恢复自动: dropping the field from the list takes the automatic value
	manual := after
	restored := manual
	restored.IPLocationManual = []string{}
	applyIPLocationWrite(manual, &restored, shanghai)
	if restored.IPLocation != shanghai || restored.IPLocationManual != nil {
		t.Fatalf("restored = %#v %v", restored.IPLocation, restored.IPLocationManual)
	}

	// an older caller without ip_location_manual: what it changed is manual,
	// what was manual stays manual
	legacy := manual
	legacy.IPLocationManual = nil
	legacy.IPLocation.ISP = "联通"
	applyIPLocationWrite(manual, &legacy, shanghai)
	if legacy.IPLocation.ISP != "联通" || legacy.IPLocation.City != "杭州" ||
		!slices.Equal(legacy.IPLocationManual, []string{"city", "isp"}) {
		t.Fatalf("legacy = %#v %v", legacy.IPLocation, legacy.IPLocationManual)
	}
	// and a tab that resubmits the settings unchanged keeps everything
	other := legacy
	other.IPLocationManual = nil
	applyIPLocationWrite(legacy, &other, tokyo)
	if other.IPLocation.City != "杭州" || other.IPLocation.ISP != "联通" || other.IPLocation.CountryCode != "JP" {
		t.Fatalf("resubmitted = %#v %v", other.IPLocation, other.IPLocationManual)
	}
}

func TestNormalizeIPLocationManual(t *testing.T) {
	settings := DefaultNodeManagementSettings()
	settings.IPLocationManual = []string{"isp", "country", "isp"}
	if err := normalizeManagementSettings(&settings); err != nil ||
		!slices.Equal(settings.IPLocationManual, []string{"country", "isp"}) {
		t.Fatalf("normalized = %v %v", settings.IPLocationManual, err)
	}
	settings.IPLocationManual = []string{"asn"}
	if err := normalizeManagementSettings(&settings); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown field error = %v", err)
	}
}
