package siteconf

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
)

func TestAutoDefenseBlockIsCanonicalAndOptional(t *testing.T) {
	a, b := sample(), sample()
	a.AutoDefense = json.RawMessage(`{"mode":"protect","modules":[{"name":"waf","mode":"auto"},{"name":"cc","mode":"auto","items":[{"field":"cc.per_ip_requests","low":10,"high":100},{"field":"cc.challenge","value":1}]}]}`)
	b.AutoDefense = json.RawMessage(`{"modules":[{"mode":"auto","name":"cc","items":[{"value":1,"field":"cc.challenge"},{"high":100,"low":10,"field":"cc.per_ip_requests"}]},{"mode":"auto","name":"waf","items":[]}],"mode":"protect"}`)
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := b.Normalize(); err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() {
		t.Fatalf("same intent, different digest:\n%s\n%s", a.AutoDefense, b.AutoDefense)
	}
	ad, err := a.DecodeAutoDefense()
	if err != nil || ad.Modules[0].Name != "cc" || ad.Modules[0].Items[0].Field != "cc.challenge" {
		t.Fatalf("decode %+v %v", ad, err)
	}
	none := sample()
	none.AutoDefense = json.RawMessage(`null`)
	if err := none.Normalize(); err != nil || none.AutoDefense != nil {
		t.Fatalf("null block = %s %v", none.AutoDefense, err)
	}
	if ad, err := none.DecodeAutoDefense(); ad != nil || err != nil {
		t.Fatalf("absent block decoded to %+v %v", ad, err)
	}
}

func TestAutoDefenseBlockRejects(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown field":      `{"mode":"protect","geo":"cn"}`,
		"bad mode":           `{"mode":"on"}`,
		"missing mode":       `{"sensitivity":"low"}`,
		"bad sensitivity":    `{"mode":"observe","sensitivity":"max"}`,
		"level 6":            `{"mode":"protect","max_level":6}`,
		"level -1":           `{"mode":"protect","max_level":-1}`,
		"l4 module":          `{"mode":"protect","modules":[{"name":"l4","mode":"auto"}]}`,
		"duplicate module":   `{"mode":"protect","modules":[{"name":"cc","mode":"auto"},{"name":"cc","mode":"manual"}]}`,
		"bad module mode":    `{"mode":"protect","modules":[{"name":"cc","mode":"on"}]}`,
		"foreign field":      `{"mode":"protect","modules":[{"name":"cc","mode":"auto","items":[{"field":"waf.tier","value":1}]}]}`,
		"empty item":         `{"mode":"protect","modules":[{"name":"cc","mode":"auto","items":[{"field":"cc.challenge"}]}]}`,
		"low above high":     `{"mode":"protect","modules":[{"name":"cc","mode":"auto","items":[{"field":"cc.per_ip_requests","low":9,"high":8}]}]}`,
		"duplicate item":     `{"mode":"protect","modules":[{"name":"cc","mode":"auto","items":[{"field":"cc.challenge","value":1},{"field":"cc.challenge","value":2}]}]}`,
		"bad field":          `{"mode":"protect","modules":[{"name":"waf","mode":"auto","items":[{"field":"waf.Tier","value":1}]}]}`,
		"trailing value":     `{"mode":"protect"}{}`,
		"unknown item field": `{"mode":"protect","modules":[{"name":"cc","mode":"auto","items":[{"field":"cc.challenge","value":1,"lock":true}]}]}`,
	} {
		c := sample()
		c.AutoDefense = json.RawMessage(raw)
		if err := c.Normalize(); err == nil {
			t.Errorf("%s: accepted %s", name, raw)
		}
	}
	c := sample()
	c.AutoDefense = json.RawMessage(`{"mode":"protect","modules":[{"name":"waf","mode":"auto","items":[{"field":"waf.group:sqli","value":1},{"field":"waf.tighten:crs-strict","value":0}]}]}`)
	if err := c.Normalize(); err != nil {
		t.Fatalf("parameterised fields rejected: %v", err)
	}
}

func TestAutoDefenseClampToCaps(t *testing.T) {
	level := func(n int) *int { return &n }
	for name, tc := range map[string]struct {
		ad       AutoDefense
		caps     *spec.AutoDefenseCaps
		level    *int
		modes    []string
		blockers []string
	}{
		"nil caps unchanged": {
			ad:    AutoDefense{Mode: "protect", Modules: []AutoDefenseModule{{Name: "cc", Mode: "auto"}}},
			modes: []string{"auto"},
		},
		"automatic level locked to cap": {
			ad: AutoDefense{Mode: "protect"}, caps: &spec.AutoDefenseCaps{MaxLevel: 3, ModulesAllowed: []string{}},
			level: level(3), blockers: []string{"max_level:3"},
		},
		"locked level above cap lowered": {
			ad: AutoDefense{Mode: "protect", MaxLevel: level(5)}, caps: &spec.AutoDefenseCaps{MaxLevel: 2, ModulesAllowed: []string{}},
			level: level(2), blockers: []string{"max_level:2"},
		},
		"locked level within cap kept": {
			ad: AutoDefense{Mode: "protect", MaxLevel: level(1)}, caps: &spec.AutoDefenseCaps{MaxLevel: 2, ModulesAllowed: []string{}},
			level: level(1),
		},
		"cap 5 leaves automatic level": {
			ad: AutoDefense{Mode: "protect"}, caps: &spec.AutoDefenseCaps{MaxLevel: 5, ModulesAllowed: []string{"cc"}},
		},
		"disallowed auto module to manual, suggest kept": {
			ad: AutoDefense{Mode: "protect", Modules: []AutoDefenseModule{
				{Name: "bot", Mode: "suggest"}, {Name: "cc", Mode: "auto"}, {Name: "waf", Mode: "auto"}}},
			caps:     &spec.AutoDefenseCaps{MaxLevel: 5, ModulesAllowed: []string{"cc"}},
			modes:    []string{"suggest", "auto", "manual"},
			blockers: []string{"module:waf"},
		},
	} {
		ad := tc.ad
		blockers := ad.Clamp(tc.caps)
		var details []string
		for _, b := range blockers {
			if b.Code != BlockerAutoDefenseCapped {
				t.Errorf("%s: blocker code %q", name, b.Code)
			}
			details = append(details, b.Detail)
		}
		if !reflect.DeepEqual(details, tc.blockers) {
			t.Errorf("%s: blockers %v want %v", name, details, tc.blockers)
		}
		if !reflect.DeepEqual(ad.MaxLevel, tc.level) {
			t.Errorf("%s: max_level %v want %v", name, ad.MaxLevel, tc.level)
		}
		var modes []string
		for _, m := range ad.Modules {
			modes = append(modes, m.Mode)
		}
		if !reflect.DeepEqual(modes, tc.modes) {
			t.Errorf("%s: modes %v want %v", name, modes, tc.modes)
		}
	}
	var nilAD *AutoDefense
	if nilAD.Clamp(&spec.AutoDefenseCaps{}) != nil {
		t.Error("nil block must not report blockers")
	}
}
