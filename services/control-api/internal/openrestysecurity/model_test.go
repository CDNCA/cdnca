package openrestysecurity

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestObservedDefaultsAndRecommendedWAFLimits(t *testing.T) {
	config := DefaultGlobalConfig()
	want := map[string]string{
		"cc_enable": "true", "block_time": "3600", "white_time": "21600", "default_block_way": `"exit"`,
		"ipset_auto_enable": "true", "site_block_qps": "200", "block_page_num_limit": "200",
		"block_page_not_counted": "true", "default_page_rule": `"10003"`, "waf_enable": "false",
	}
	for field, expected := range want {
		if string(config[field]) != expected {
			t.Fatalf("%s = %s, want %s", field, config[field], expected)
		}
	}
	var limits WAFResourceLimits
	if err := json.Unmarshal(config["waf_resource_limits"], &limits); err != nil {
		t.Fatal(err)
	}
	if limits != RecommendedWAFResourceLimits() {
		t.Fatalf("limits = %+v", limits)
	}
}

func TestWAFResourceLimitBoundariesAndRelationships(t *testing.T) {
	valid := mustConfig(map[string]any{"waf_resource_limits": RecommendedWAFResourceLimits()})
	if err := ValidateConfig(valid, false); err != nil {
		t.Fatalf("valid limits: %v", err)
	}
	tests := map[string]WAFResourceLimits{
		"leaves above parameter": func() WAFResourceLimits {
			value := RecommendedWAFResourceLimits()
			value.JSONMaxLeaves = 2049
			return value
		}(),
		"parameter above request": func() WAFResourceLimits {
			value := RecommendedWAFResourceLimits()
			value.CandidatePerParam = 4096
			value.CandidatePerRequest = 2048
			return value
		}(),
		"JSON body above scan": func() WAFResourceLimits {
			value := RecommendedWAFResourceLimits()
			value.JSONBodyBytes = 4 * 1024 * 1024
			value.BodyScanBytes = 1024 * 1024
			return value
		}(),
		"depth below minimum": func() WAFResourceLimits {
			value := RecommendedWAFResourceLimits()
			value.JSONMaxDepth = 15
			return value
		}(),
		"scan above maximum": func() WAFResourceLimits {
			value := RecommendedWAFResourceLimits()
			value.BodyScanBytes = 64*1024*1024 + 1
			return value
		}(),
	}
	for name, limits := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateConfig(mustConfig(map[string]any{"waf_resource_limits": limits}), false); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestEffectiveUsesNodeOverRegionOverGlobal(t *testing.T) {
	global := mustConfig(map[string]any{"cc_enable": false, "block_time": 3600})
	region := mustConfig(map[string]any{"cc_enable": true, "block_time": 1800})
	node := mustConfig(map[string]any{"block_time": 60})
	effective, err := Effective(global, region, node)
	if err != nil {
		t.Fatal(err)
	}
	if string(effective["cc_enable"]) != "true" || string(effective["block_time"]) != "60" {
		t.Fatalf("effective = %s", mustJSON(effective))
	}
}

func TestSecretIsWriteOnly(t *testing.T) {
	input := mustConfig(map[string]any{"key": "secret-value", "cc_enable": true})
	config, secret, err := StripSecret(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := config["key"]; ok || secret == nil || *secret != "secret-value" {
		t.Fatalf("config=%s secret=%v", mustJSON(config), secret)
	}
}

func TestApplyOverridePatchRemovesFieldsWithoutMutatingBase(t *testing.T) {
	base := mustConfig(map[string]any{"cc_enable": true, "icmp_drop": true})
	patch := mustConfig(map[string]any{"cc_enable": false})
	result, err := ApplyOverridePatch(base, patch, []string{"icmp_drop"})
	if err != nil {
		t.Fatal(err)
	}
	if string(result["cc_enable"]) != "false" {
		t.Fatalf("result=%s", mustJSON(result))
	}
	if _, exists := result["icmp_drop"]; exists {
		t.Fatalf("removed field persisted: %s", mustJSON(result))
	}
	if _, exists := base["icmp_drop"]; !exists {
		t.Fatalf("base was mutated: %s", mustJSON(base))
	}
}

func TestApplyOverridePatchRejectsAmbiguousRemovedFields(t *testing.T) {
	base := mustConfig(map[string]any{"cc_enable": true, "icmp_drop": true})
	for name, test := range map[string]struct {
		patch   Config
		removed []string
	}{
		"empty patch":       {patch: Config{}, removed: []string{"icmp_drop"}},
		"empty removal":     {patch: mustConfig(map[string]any{"cc_enable": false}), removed: []string{}},
		"unknown removal":   {patch: mustConfig(map[string]any{"cc_enable": false}), removed: []string{"resolver"}},
		"duplicate removal": {patch: mustConfig(map[string]any{"cc_enable": false}), removed: []string{"icmp_drop", "icmp_drop"}},
		"patch overlap":     {patch: mustConfig(map[string]any{"icmp_drop": false}), removed: []string{"icmp_drop"}},
		"missing removal":   {patch: mustConfig(map[string]any{"cc_enable": false}), removed: []string{"custom_black"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ApplyOverridePatch(base, test.patch, test.removed); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestApplyOverridePatchAllowsWriteOnlyKeyRemoval(t *testing.T) {
	base := mustConfig(map[string]any{"cc_enable": true})
	result, err := ApplyOverridePatch(base, mustConfig(map[string]any{"cc_enable": false}), []string{"key"})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := result["key"]; exists || string(result["cc_enable"]) != "false" {
		t.Fatalf("result=%s", mustJSON(result))
	}
}

func TestWhiteTimeMinimum(t *testing.T) {
	if err := ValidateConfig(mustConfig(map[string]any{"white_time": 599}), false); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v", err)
	}
	if err := ValidateConfig(mustConfig(map[string]any{"white_time": 600}), false); err != nil {
		t.Fatalf("error = %v", err)
	}
}

func mustJSON(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// fix-fwregion: every effective field names the layer it came from.
func TestEffectiveSources(t *testing.T) {
	region := Config{"auto_switch": json.RawMessage(`{"enable":true,"qps_50x":0,"qps_total":50,"rule":"10003","seconds":300}`),
		"waf_enable": json.RawMessage(`true`)}
	node := Config{"auto_switch": json.RawMessage(`{"enable":false,"qps_50x":0,"qps_total":0,"rule":"","seconds":0}`)}
	sources := EffectiveSources(Config{"block_time": json.RawMessage(`600`)}, region, node)
	if sources["auto_switch"] != ScopeNode || sources["waf_enable"] != ScopeRegion || sources["block_time"] != ScopeGlobal ||
		sources["cc_enable"] != ScopeGlobal {
		t.Fatalf("sources = %v", sources)
	}
	// A field nobody sets has no source; a default one is global.
	if sources := EffectiveSources(nil, nil, nil); sources["cc_enable"] != ScopeGlobal || sources["auto_switch"] != "" {
		t.Fatalf("defaults = %v", sources)
	}
}
