package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoadCustomRBACRuntimeConfigFromEnv(t *testing.T) {
	t.Parallel()

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
	tests := []struct {
		name        string
		environment []string
		enabled     bool
		errorText   string
	}{
		{name: "missing is disabled"},
		{name: "false is disabled", environment: []string{customRBACRuntimeEnabledEnv + "=false"}},
		{name: "true is enabled", environment: []string{customRBACRuntimeEnabledEnv + "=true", customRBACCursorKeyBase64Env + "=" + key}, enabled: true},
		{name: "missing key", environment: []string{customRBACRuntimeEnabledEnv + "=true"}, errorText: "is required"},
		{name: "short key", environment: []string{customRBACRuntimeEnabledEnv + "=true", customRBACCursorKeyBase64Env + "=" + base64.StdEncoding.EncodeToString(make([]byte, 31))}, errorText: "must encode 32 to 128 bytes"},
		{name: "unpadded key", environment: []string{customRBACRuntimeEnabledEnv + "=true", customRBACCursorKeyBase64Env + "=" + strings.TrimRight(key, "=")}, errorText: "must encode 32 to 128 bytes"},
		{name: "uppercase enabled", environment: []string{customRBACRuntimeEnabledEnv + "=TRUE", customRBACCursorKeyBase64Env + "=" + key}, errorText: "must be true or false"},
		{name: "duplicate enabled", environment: []string{customRBACRuntimeEnabledEnv + "=true", customRBACRuntimeEnabledEnv + "=true", customRBACCursorKeyBase64Env + "=" + key}, errorText: "must be defined exactly once"},
		{name: "duplicate key", environment: []string{customRBACRuntimeEnabledEnv + "=true", customRBACCursorKeyBase64Env + "=" + key, customRBACCursorKeyBase64Env + "=" + key}, errorText: "must be defined exactly once"},
		{name: "enabled unknown field", environment: []string{customRBACRuntimeEnabledEnv + "=true", customRBACCursorKeyBase64Env + "=" + key, "CUSTOM_RBAC_RUNTIME_MODE=unsafe"}, errorText: "unsupported environment structure"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config, err := loadCustomRBACRuntimeConfigFromEnv(test.environment)
			defer config.clearSecrets()
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

func TestBuildAndClearCustomRBACHandlerFactory(t *testing.T) {
	t.Parallel()

	disabled := customRBACRuntimeConfig{}
	factory, err := buildAndClearCustomRBACHandlerFactory(&disabled, customRBACRuntimeDependencies{})
	if err != nil || factory != nil {
		t.Fatalf("disabled factory = (%v, %v), want (nil, nil)", factory, err)
	}

	config := customRBACRuntimeConfig{Enabled: true, CursorKey: bytes.Repeat([]byte{0x42}, 32)}
	factory, err = buildAndClearCustomRBACHandlerFactory(&config, customRBACRuntimeDependencies{})
	if err != nil || factory == nil {
		t.Fatalf("build factory = (%v, %v)", factory, err)
	}
	if config.CursorKey != nil {
		t.Fatal("source cursor key was not cleared")
	}
	if handler, err := factory(); err == nil || handler != nil {
		t.Fatalf("factory = (%v, %v), want fail-closed dependency error", handler, err)
	}
}
