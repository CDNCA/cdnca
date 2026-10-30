package main

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicyhttp"
)

func TestLoadURLAuthRuntimeConfigFromEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		environment []string
		enabled     bool
		errorText   string
	}{
		{name: "missing is disabled"},
		{name: "false is disabled", environment: []string{urlAuthRuntimeEnabledEnv + "=false"}},
		{name: "true is enabled", environment: []string{urlAuthRuntimeEnabledEnv + "=true"}, enabled: true},
		{name: "empty is disabled", environment: []string{urlAuthRuntimeEnabledEnv + "="}},
		{name: "uppercase is rejected", environment: []string{urlAuthRuntimeEnabledEnv + "=TRUE"}, errorText: "must be true or false"},
		{name: "whitespace is rejected", environment: []string{urlAuthRuntimeEnabledEnv + "= true"}, errorText: "must be true or false"},
		{name: "duplicate is rejected", environment: []string{urlAuthRuntimeEnabledEnv + "=false", urlAuthRuntimeEnabledEnv + "=true"}, errorText: "must be defined exactly once"},
		{name: "enabled unknown field is rejected", environment: []string{urlAuthRuntimeEnabledEnv + "=true", "URL_AUTH_POLICY_RUNTIME_KEY=unsafe"}, errorText: "unsupported environment structure"},
		{name: "disabled unknown field is ignored", environment: []string{urlAuthRuntimeEnabledEnv + "=false", "URL_AUTH_POLICY_RUNTIME_KEY=unsafe"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config, err := loadURLAuthRuntimeConfigFromEnv(test.environment)
			if test.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.errorText) {
					t.Fatalf("error = %v, want containing %q", err, test.errorText)
				}
				return
			}
			if err != nil {
				t.Fatalf("load config: %v", err)
			}
			if config.Enabled != test.enabled {
				t.Fatalf("enabled = %t, want %t", config.Enabled, test.enabled)
			}
		})
	}
}

func TestBuildURLAuthHandlerFactory(t *testing.T) {
	t.Parallel()

	if factory := buildURLAuthHandlerFactory(urlAuthRuntimeConfig{}, urlauthpolicyhttp.RuntimeDependencies{}); factory != nil {
		t.Fatal("disabled runtime returned a handler factory")
	}

	factory := buildURLAuthHandlerFactory(
		urlAuthRuntimeConfig{Enabled: true},
		urlauthpolicyhttp.RuntimeDependencies{},
	)
	if factory == nil {
		t.Fatal("enabled runtime did not return a handler factory")
	}
	if handler, err := factory(); err == nil || handler != nil {
		t.Fatalf("factory = (%v, %v), want fail-closed invalid dependency error", handler, err)
	}
}
