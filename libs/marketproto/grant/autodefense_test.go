package grant

import (
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
)

func TestGrantAutoDefenseCapsAndSitePauseRoundTrip(t *testing.T) {
	public, private := testKey(t)
	g := validGrant()
	g.AutoDefenseCaps = &spec.AutoDefenseCaps{MaxLevel: 3, ModulesAllowed: []string{"cc", "waf"}}
	g.SitePause = &SitePause{Enabled: true, AfterActions: 3}
	signed, err := Sign(g, "market-2026-10", private)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Keyring{"market-2026-10": public}.Verify(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, g) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, g)
	}
}

func TestGrantRejectsBadAutoDefenseCapsAndSitePause(t *testing.T) {
	_, private := testKey(t)
	for name, mutate := range map[string]func(*Grant){
		"level above 5":  func(g *Grant) { g.AutoDefenseCaps = &spec.AutoDefenseCaps{MaxLevel: 6} },
		"negative level": func(g *Grant) { g.AutoDefenseCaps = &spec.AutoDefenseCaps{MaxLevel: -1} },
		"l4 module":      func(g *Grant) { g.AutoDefenseCaps = &spec.AutoDefenseCaps{MaxLevel: 2, ModulesAllowed: []string{"l4"}} },
		"unsorted modules": func(g *Grant) {
			g.AutoDefenseCaps = &spec.AutoDefenseCaps{MaxLevel: 2, ModulesAllowed: []string{"waf", "cc"}}
		},
		"duplicate modules": func(g *Grant) {
			g.AutoDefenseCaps = &spec.AutoDefenseCaps{MaxLevel: 2, ModulesAllowed: []string{"cc", "cc"}}
		},
		"pause n 0":   func(g *Grant) { g.SitePause = &SitePause{Enabled: true, AfterActions: 0} },
		"pause n 101": func(g *Grant) { g.SitePause = &SitePause{AfterActions: 101} },
	} {
		g := validGrant()
		mutate(&g)
		if _, err := Sign(g, "market-2026-10", private); err == nil {
			t.Errorf("%s: signed an invalid grant", name)
		}
	}
	g := validGrant()
	g.AutoDefenseCaps = &spec.AutoDefenseCaps{MaxLevel: 0, ModulesAllowed: []string{}}
	g.SitePause = &SitePause{AfterActions: 1}
	if err := g.Validate(); err != nil {
		t.Fatalf("boundary values rejected: %v", err)
	}
	g.SitePause.AfterActions = 100
	if err := g.Validate(); err != nil {
		t.Fatalf("N=100 rejected: %v", err)
	}
}

func TestSitePauseExceededIsNPlusOne(t *testing.T) {
	p := SitePause{Enabled: true, AfterActions: 3}
	if p.Exceeded(3) || !p.Exceeded(4) {
		t.Fatal("exceeding N must mean the N+1st action")
	}
	p.Enabled = false
	if p.Exceeded(100) {
		t.Fatal("switched off pause must never trigger")
	}
}

func TestCombineSitePauseAlongPath(t *testing.T) {
	on3, on5, off2 := &SitePause{Enabled: true, AfterActions: 3}, &SitePause{Enabled: true, AfterActions: 5}, &SitePause{AfterActions: 2}
	for name, tc := range map[string]struct {
		a, b *SitePause
		want *SitePause
	}{
		"both nil":           {nil, nil, nil},
		"nil and on":         {nil, on5, on5},
		"on and nil":         {on3, nil, on3},
		"both on, smaller N": {on5, on3, on3},
		"off N ignored":      {off2, on5, on5},
		"on wins over off":   {on3, off2, on3},
		"both off":           {off2, &SitePause{AfterActions: 7}, off2},
	} {
		got := CombineSitePause(tc.a, tc.b)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v want %+v", name, got, tc.want)
		}
		if got != nil && (got == tc.a || got == tc.b) {
			t.Errorf("%s: result aliases an input", name)
		}
	}
}
