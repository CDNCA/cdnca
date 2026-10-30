package spec

import (
	"errors"
	"reflect"
	"testing"
)

func TestAutoDefenseCapsNormalizeAndValidate(t *testing.T) {
	got, err := AutoDefenseCaps{MaxLevel: 5, ModulesAllowed: []string{"waf", "bot", "cc", "scan"}}.Normalize()
	if err != nil || !reflect.DeepEqual(got.ModulesAllowed, []string{"bot", "cc", "scan", "waf"}) {
		t.Fatalf("normalize: %+v %v", got, err)
	}
	if got, err := (AutoDefenseCaps{}).Normalize(); err != nil || got.ModulesAllowed == nil {
		t.Fatalf("empty caps must normalize to an empty list: %+v %v", got, err)
	}
	for _, bad := range []AutoDefenseCaps{
		{MaxLevel: -1}, {MaxLevel: 6}, {ModulesAllowed: []string{"l4"}}, {ModulesAllowed: []string{"cc", "cc"}},
		{ModulesAllowed: []string{"waf", "cc"}}, {ModulesAllowed: []string{""}},
	} {
		if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v accepted", bad)
		}
	}
	if _, err := (AutoDefenseCaps{ModulesAllowed: []string{"cc", "cc"}}).Normalize(); err == nil {
		t.Error("normalize kept duplicate modules")
	}
}

func TestMinAutoDefenseCapsTakesStrictest(t *testing.T) {
	a := &AutoDefenseCaps{MaxLevel: 4, ModulesAllowed: []string{"bot", "cc", "waf"}}
	b := &AutoDefenseCaps{MaxLevel: 2, ModulesAllowed: []string{"cc", "scan", "waf"}}
	got := MinAutoDefenseCaps(a, b)
	if want := (&AutoDefenseCaps{MaxLevel: 2, ModulesAllowed: []string{"cc", "waf"}}); !reflect.DeepEqual(got, want) {
		t.Fatalf("min: got %+v want %+v", got, want)
	}
	if MinAutoDefenseCaps(nil, nil) != nil {
		t.Fatal("nil and nil must stay unconstrained")
	}
	if got := MinAutoDefenseCaps(nil, b); !reflect.DeepEqual(got, b) || got == b {
		t.Fatalf("nil side must yield a copy of the other: %+v", got)
	}
	if got := MinAutoDefenseCaps(a, nil); !reflect.DeepEqual(got, a) || got == a {
		t.Fatalf("nil side must yield a copy of the other: %+v", got)
	}
	none := &AutoDefenseCaps{MaxLevel: 5, ModulesAllowed: []string{}}
	if got := MinAutoDefenseCaps(a, none); got.MaxLevel != 4 || len(got.ModulesAllowed) != 0 || got.ModulesAllowed == nil {
		t.Fatalf("no modules on one hop must allow none: %+v", got)
	}
	// Path of three hops folds left to the same strictest result.
	c := &AutoDefenseCaps{MaxLevel: 3, ModulesAllowed: []string{"waf"}}
	if got := MinAutoDefenseCaps(MinAutoDefenseCaps(a, b), c); got.MaxLevel != 2 || !reflect.DeepEqual(got.ModulesAllowed, []string{"waf"}) {
		t.Fatalf("path fold: %+v", got)
	}
}
