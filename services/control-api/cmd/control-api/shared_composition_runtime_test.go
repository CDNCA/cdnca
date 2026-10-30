package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSharedCompositionDNSUsesConfiguredCredentialKeyring(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte("newConfiguredDNSCredentialCipher(cfg)")) {
		t.Fatal("control-api main does not use the complete DNS credential keyring")
	}
}

func TestLoadAnalyticsRealtimeRuntimeConfigIsStrict(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
	tests := []struct {
		name, errorText string
		environment     []string
		enabled         bool
	}{
		{name: "missing is disabled"},
		{name: "false is disabled", environment: []string{analyticsRealtimeRuntimeEnabledEnv + "=false"}},
		{name: "coverage finalizer sibling config is ignored", environment: []string{
			realtimeCoverageRuntimeEnabledEnv + "=true",
			realtimeCoverageRuntimePollIntervalEnv + "=30s",
			realtimeCoverageRuntimeGraceEnv + "=2m",
			realtimeCoverageRuntimeMaxWindowsEnv + "=64",
		}},
		{name: "disabled rejects cursor", environment: []string{analyticsRealtimeRuntimeEnabledEnv + "=false", analyticsRealtimeCursorKeyBase64Env + "=" + key}, errorText: "disabled"},
		{name: "enabled", environment: []string{analyticsRealtimeRuntimeEnabledEnv + "=true", analyticsRealtimeCursorKeyBase64Env + "=" + key, analyticsRealtimeQueryTimeoutEnv + "=4s", analyticsRealtimeMaxResponseBytesEnv + "=65536"}, enabled: true},
		{name: "missing cursor", environment: []string{analyticsRealtimeRuntimeEnabledEnv + "=true"}, errorText: "required"},
		{name: "unknown field", environment: []string{analyticsRealtimeRuntimeEnabledEnv + "=true", analyticsRealtimeCursorKeyBase64Env + "=" + key, "ANALYTICS_REALTIME_MODE=unsafe"}, errorText: "unsupported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := loadAnalyticsRealtimeRuntimeConfigFromEnv(test.environment)
			defer config.clearSecrets()
			if test.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.errorText) {
					t.Fatalf("error = %v, want containing %q", err, test.errorText)
				}
				return
			}
			if err != nil || config.Enabled != test.enabled {
				t.Fatalf("config = (%+v,%v), want enabled=%t", config, err, test.enabled)
			}
		})
	}
}

func TestBuildAndClearAnalyticsRealtimeHandlerFactory(t *testing.T) {
	disabled := analyticsRealtimeRuntimeConfig{}
	factory, err := buildAndClearAnalyticsRealtimeHandlerFactory(&disabled, nil, nil)
	if err != nil || factory != nil {
		t.Fatalf("disabled factory = (%v,%v), want nil,nil", factory, err)
	}
	missing := analyticsRealtimeRuntimeConfig{Enabled: true, CursorKey: bytes.Repeat([]byte{0x42}, 32)}
	if factory, err = buildAndClearAnalyticsRealtimeHandlerFactory(&missing, nil, nil); err == nil || factory != nil {
		t.Fatalf("missing dependency factory = (%v,%v), want fail closed", factory, err)
	}
	configured := analyticsRealtimeRuntimeConfig{Enabled: true, CursorKey: bytes.Repeat([]byte{0x43}, 32)}
	runtime := &analyticsQueryRuntime{store: &analytics.Client{}}
	poolConfig, err := pgxpool.ParseConfig("postgres://analytics-realtime-runtime.invalid/control")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	factory, err = buildAndClearAnalyticsRealtimeHandlerFactory(&configured, runtime, pool)
	if err != nil || factory == nil {
		t.Fatalf("configured factory = (%v,%v)", factory, err)
	}
	if configured.CursorKey != nil {
		t.Fatal("source cursor key was not cleared")
	}
}
