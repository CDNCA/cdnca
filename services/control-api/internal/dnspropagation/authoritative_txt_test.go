package dnspropagation

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// zoneSource serves one zone with two authorities and per-authority TXT values.
type zoneSource struct {
	zone      string
	values    map[string][]string
	discovers []string
}

func (source *zoneSource) Discover(_ context.Context, _ string, zone string) (Delegation, error) {
	source.discovers = append(source.discovers, zone)
	if zone != source.zone {
		return Delegation{}, errInvalidWireResponse
	}
	return Delegation{Zone: zone, Authorities: []Resolver{{ID: "192.0.2.1:53", Name: "ns1." + zone},
		{ID: "192.0.2.2:53", Name: "ns2." + zone}}}, nil
}

func (source *zoneSource) Observe(_ context.Context, _ string, resolver Resolver, name string,
	types []dnscheck.RecordType) (Observation, error) {
	if name != "_acme-challenge.www.example.com." || len(types) != 1 || types[0] != dnscheck.RecordTXT {
		return Observation{}, ErrInvalidInput
	}
	values, ok := source.values[resolver.ID]
	if !ok {
		return Observation{}, errors.New("timeout")
	}
	return Observation{Status: ResponseAnswer, Records: []RRSet{{Type: dnscheck.RecordTXT, Values: values}}}, nil
}

func TestAuthoritativeTXTRequiresEveryAuthority(t *testing.T) {
	const name, value = "_acme-challenge.www.example.com", "token-value"
	for _, test := range []struct {
		label  string
		values map[string][]string
		want   bool
	}{
		{"all authorities serve it", map[string][]string{"192.0.2.1:53": {"other", value}, "192.0.2.2:53": {value}}, true},
		{"one authority lags", map[string][]string{"192.0.2.1:53": {value}, "192.0.2.2:53": {"stale"}}, false},
		{"one authority unreachable", map[string][]string{"192.0.2.1:53": {value}}, false},
	} {
		t.Run(test.label, func(t *testing.T) {
			source := &zoneSource{zone: "example.com.", values: test.values}
			checker, err := NewAuthoritativeTXT(source)
			if err != nil {
				t.Fatal(err)
			}
			visible, err := checker.TXTVisible(t.Context(), name, value)
			if err != nil || visible != test.want {
				t.Fatalf("TXTVisible() = %v, %v; want %v", visible, err, test.want)
			}
			// The zone cut is found by walking up from the record name.
			if len(source.discovers) != 3 || source.discovers[2] != "example.com." {
				t.Fatalf("discover walk = %v", source.discovers)
			}
		})
	}
}

func TestAuthoritativeTXTNeverUsesTopLevelDomain(t *testing.T) {
	source := &zoneSource{zone: "com.", values: map[string][]string{}}
	checker, _ := NewAuthoritativeTXT(source)
	visible, err := checker.TXTVisible(t.Context(), "_acme-challenge.www.example.com.", "token")
	if err != nil || visible {
		t.Fatalf("TXTVisible() = %v, %v", visible, err)
	}
	for _, zone := range source.discovers {
		if zone == "com." {
			t.Fatalf("discovered a TLD as the zone: %v", source.discovers)
		}
	}
}
