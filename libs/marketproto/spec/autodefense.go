package spec

import (
	"fmt"
	"slices"
)

// AutoDefenseCaps is what a supplier allows the sites on its supply to do
// with automatic defence (ADR 0012 §19.2, U7): only the highest mitigation
// level and which site modules may run automatically. Everything else stays
// the site owner's choice within the ADR 0010 platform ranges.
//
// A grant without caps (nil) is unconstrained: level up to L5, every module.
type AutoDefenseCaps struct {
	// MaxLevel caps the site's effective max_level: 0 observe only,
	// 1 challenge, 2 rate limit, 3 temporary ban, 4 kernel ban, 5 XDP.
	MaxLevel int `json:"max_level"`
	// ModulesAllowed are the site modules (cc, waf, scan, bot) that may run in
	// auto mode; a module not listed stays manual on this supply (suggest,
	// which only displays, is always allowed).
	// Sorted and unique; empty means no module may run automatically.
	ModulesAllowed []string `json:"modules_allowed"`
}

const MaxAutoDefenseLevel = 5

// AutoDefenseModules are the site-level overlay modules of the autodefense
// contract §4 (l4 is per node and port group, never per site).
var AutoDefenseModules = []string{"bot", "cc", "scan", "waf"}

// Normalize sorts the modules and validates.
func (c AutoDefenseCaps) Normalize() (AutoDefenseCaps, error) {
	c.ModulesAllowed = slices.Clone(c.ModulesAllowed)
	slices.Sort(c.ModulesAllowed)
	if c.ModulesAllowed == nil {
		c.ModulesAllowed = []string{}
	}
	return c, c.Validate()
}

func (c AutoDefenseCaps) Validate() error {
	if c.MaxLevel < 0 || c.MaxLevel > MaxAutoDefenseLevel {
		return fmt.Errorf("%w: autodefense max_level must be 0..%d", ErrInvalid, MaxAutoDefenseLevel)
	}
	for i, m := range c.ModulesAllowed {
		if !slices.Contains(AutoDefenseModules, m) || (i > 0 && c.ModulesAllowed[i-1] >= m) {
			return fmt.Errorf("%w: modules_allowed must be sorted, unique bot/cc/scan/waf", ErrInvalid)
		}
	}
	return nil
}

// Allows reports whether module may run automatically under c.
func (c AutoDefenseCaps) Allows(module string) bool {
	_, ok := slices.BinarySearch(c.ModulesAllowed, module)
	return ok
}

// MinAutoDefenseCaps combines two hops along a supply path: the lower level
// and the modules both allow. nil (unconstrained) yields the other side.
func MinAutoDefenseCaps(a, b *AutoDefenseCaps) *AutoDefenseCaps {
	switch {
	case a == nil && b == nil:
		return nil
	case a == nil:
		out := *b
		out.ModulesAllowed = slices.Clone(b.ModulesAllowed)
		return &out
	case b == nil:
		return MinAutoDefenseCaps(b, a)
	}
	out := AutoDefenseCaps{MaxLevel: min(a.MaxLevel, b.MaxLevel), ModulesAllowed: []string{}}
	for _, m := range a.ModulesAllowed {
		if b.Allows(m) {
			out.ModulesAllowed = append(out.ModulesAllowed, m)
		}
	}
	return &out
}
