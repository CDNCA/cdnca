package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateDynamicRouting(t *testing.T) {
	base := fileConfig{DeploymentRoot: "/var/lib/edge/deployment"}
	if err := base.validateDynamicRouting(); err == nil || !strings.Contains(err.Error(), "only node runtime") {
		t.Fatalf("disabled dynamic routing accepted: %v", err)
	}
	if !defaultFileConfig().DynamicRouting.Enabled {
		t.Fatal("dynamic routing is not on by default")
	}
	enabled := base
	enabled.DynamicRouting = dynamicRoutingSettings{Enabled: true, CacheMaxBytes: new(int64(1 << 30))}
	if err := enabled.validateDynamicRouting(); err != nil {
		t.Fatalf("enabled: %v", err)
	}
	// D13-b: drain and upgrade run on the dynamic routing manager
	withDrain := enabled
	withDrain.DrainRuntime.Enabled, withDrain.Upgrade.Enabled = true, true
	if err := withDrain.validateDynamicRouting(); err != nil {
		t.Fatalf("drain and upgrade: %v", err)
	}
	state, shared := dynamicRoutingRoots(enabled)
	if state != filepath.Join("/var/lib/edge", "dynroute", "state") || shared != filepath.Join("/var/lib/edge", "dynroute", "shared") {
		t.Fatalf("roots %s %s", state, shared)
	}
	for name, mutate := range map[string]func(*fileConfig){
		"relative":   func(c *fileConfig) { c.DynamicRouting.StateRoot = "state" },
		"tiny cache": func(c *fileConfig) { c.DynamicRouting.CacheMaxBytes = new(int64(1 << 20)) },
	} {
		value := enabled
		mutate(&value)
		if err := value.validateDynamicRouting(); err == nil || !strings.Contains(err.Error(), "dynamic_routing") {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}

// The installed native profile runs workers as cdnca-runtime (the worker
// group of every worker readable file); other profiles keep the default.
func TestDynamicRoutingGlobalsFollowTheNativeProfile(t *testing.T) {
	config := fileConfig{}
	if got := dynamicRoutingGlobals(config); got != "" {
		t.Fatalf("non-native globals %q", got)
	}
	config.OpenResty.SystemdService = "cdnca-openresty-native.service"
	if got := dynamicRoutingGlobals(config); got != "user cdnca-runtime cdnca-runtime;" {
		t.Fatalf("native globals %q", got)
	}
}
