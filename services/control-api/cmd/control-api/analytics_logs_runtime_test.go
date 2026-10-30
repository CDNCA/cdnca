package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOpenAnalyticsLogsRuntimeDisabledHasNoDependencies(t *testing.T) {
	called := false
	handler, err := openAnalyticsLogsRuntime(config.Config{}, nil, nil, nil,
		func(analyticslog.RuntimeConfig, analyticslog.HTTPDependencies) (http.Handler, error) {
			called = true
			return nil, errors.New("disabled factory must not run")
		})
	if err != nil || handler != nil || called {
		t.Fatalf("disabled analytics logs runtime = (%T, %v), factory called=%t", handler, err, called)
	}
}

func TestLoadAnalyticsLogsCursorKeyringDisabledDoesNotReadSecrets(t *testing.T) {
	called := false
	ring, err := loadAnalyticsLogsCursorKeyring(false, func(string) (string, bool) {
		called = true
		return "must-not-read", true
	})
	if err != nil || called || ring.ActiveKID != "" || len(ring.Keys) != 0 {
		t.Fatalf("disabled keyring = (%#v, %v), lookup called=%t", ring, err, called)
	}
}

func TestLoadAnalyticsLogsCursorKeyringStrictConfiguration(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 31))
	long := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 65))
	nine := `{"a":"` + valid + `","b":"` + valid + `","c":"` + valid + `","d":"` + valid +
		`","e":"` + valid + `","f":"` + valid + `","g":"` + valid + `","h":"` + valid + `","i":"` + valid + `"}`
	tests := []struct {
		name   string
		values map[string]string
	}{
		{name: "missing active", values: map[string]string{"ANALYTICS_LOGS_CURSOR_KEYS_JSON": `{"active":"` + valid + `"}`}},
		{name: "missing keys", values: map[string]string{"ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID": "active"}},
		{name: "duplicate key", values: map[string]string{
			"ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID": "active",
			"ANALYTICS_LOGS_CURSOR_KEYS_JSON":     `{"active":"` + valid + `","active":"` + valid + `"}`,
		}},
		{name: "unknown active", values: map[string]string{
			"ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID": "unknown",
			"ANALYTICS_LOGS_CURSOR_KEYS_JSON":     `{"active":"` + valid + `"}`,
		}},
		{name: "noncanonical base64", values: map[string]string{
			"ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID": "active",
			"ANALYTICS_LOGS_CURSOR_KEYS_JSON":     `{"active":"` + strings.TrimRight(valid, "=") + `"}`,
		}},
		{name: "unknown json shape", values: map[string]string{
			"ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID": "active",
			"ANALYTICS_LOGS_CURSOR_KEYS_JSON":     `{"active":{"key":"` + valid + `"}}`,
		}},
		{name: "short key", values: map[string]string{
			"ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID": "active",
			"ANALYTICS_LOGS_CURSOR_KEYS_JSON":     `{"active":"` + short + `"}`,
		}},
		{name: "long key", values: map[string]string{
			"ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID": "active",
			"ANALYTICS_LOGS_CURSOR_KEYS_JSON":     `{"active":"` + long + `"}`,
		}},
		{name: "too many keys", values: map[string]string{
			"ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID": "a",
			"ANALYTICS_LOGS_CURSOR_KEYS_JSON":     nine,
		}},
		{name: "trailing json", values: map[string]string{
			"ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID": "active",
			"ANALYTICS_LOGS_CURSOR_KEYS_JSON":     `{"active":"` + valid + `"}{}`,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lookup := func(name string) (string, bool) {
				value, ok := test.values[name]
				return value, ok
			}
			if ring, err := loadAnalyticsLogsCursorKeyring(true, lookup); err == nil || ring.ActiveKID != "" || len(ring.Keys) != 0 {
				t.Fatalf("invalid keyring = (%#v, %v)", ring, err)
			}
		})
	}
}

func TestOpenAnalyticsLogsRuntimeEnabledWithoutCursorKeyringFailsClosed(t *testing.T) {
	cfg := validAnalyticsQueryConfig()
	cfg.APIKeyPepper = bytes.Repeat([]byte{0x41}, 32)
	t.Setenv("ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID", "")
	t.Setenv("ANALYTICS_LOGS_CURSOR_KEYS_JSON", "")
	called := false
	handler, err := openAnalyticsLogsRuntime(cfg, nil, nil, nil,
		func(analyticslog.RuntimeConfig, analyticslog.HTTPDependencies) (http.Handler, error) {
			called = true
			return http.NotFoundHandler(), nil
		})
	if handler != nil || err == nil || called {
		t.Fatalf("missing cursor keyring = (%T, %v), factory called=%t", handler, err, called)
	}
}

func TestOpenAnalyticsLogsRuntimeBuildsOfficialDependencies(t *testing.T) {
	cfg := validAnalyticsLogsConfig(t)
	pool, identityService, tokens := analyticsLogsRuntimeDependencies(t)
	called := false
	var capturedKeys map[string][]byte
	handler, err := openAnalyticsLogsRuntime(cfg, pool, identityService, tokens,
		func(runtimeConfig analyticslog.RuntimeConfig, dependencies analyticslog.HTTPDependencies) (http.Handler, error) {
			called = true
			capturedKeys = runtimeConfig.HTTP.Client.CursorKeyring.Keys
			if runtimeConfig.HTTP.Client.CursorKeyring.ActiveKID != "runtime-active" || len(capturedKeys) != 1 ||
				len(capturedKeys["runtime-active"]) != 32 {
				t.Fatalf("analytics logs cursor keyring metadata = (%q, %d, %d)",
					runtimeConfig.HTTP.Client.CursorKeyring.ActiveKID, len(capturedKeys), len(capturedKeys["runtime-active"]))
			}
			if !runtimeConfig.Enabled || runtimeConfig.HTTP.Client.Endpoint != cfg.ClickHouseURL ||
				runtimeConfig.HTTP.Client.Database != cfg.ClickHouseDatabase ||
				runtimeConfig.HTTP.Client.Username != cfg.ClickHouseUsername ||
				runtimeConfig.HTTP.Client.Password != cfg.ClickHousePassword ||
				runtimeConfig.HTTP.Client.QueryTimeout != cfg.AnalyticsQueryTimeout ||
				runtimeConfig.HTTP.Client.MaxResponseBytes != cfg.AnalyticsQueryMaxResponse ||
				runtimeConfig.HTTP.Handler.QueryTimeout != cfg.AnalyticsHandlerTimeout ||
				runtimeConfig.HTTP.Handler.MaxResponseBytes != cfg.AnalyticsHandlerMaxResponse {
				t.Fatalf("analytics logs runtime config = %#v", runtimeConfig)
			}
			if dependencies.Pool != pool || dependencies.Identity != identityService ||
				dependencies.APIKeys == nil || dependencies.IAM == nil || !dependencies.IAM.Configured() {
				t.Fatalf("analytics logs dependencies = %#v", dependencies)
			}
			return http.NotFoundHandler(), nil
		})
	if err != nil || handler == nil || !called {
		t.Fatalf("enabled analytics logs runtime = (%T, %v), factory called=%t", handler, err, called)
	}
	if len(capturedKeys) != 0 {
		t.Fatalf("temporary runtime cursor keys were not cleared: %d", len(capturedKeys))
	}
}

func TestOpenAnalyticsLogsRuntimePassesConnectTimeout(t *testing.T) {
	cfg := validAnalyticsLogsConfig(t)
	cfg.AnalyticsConnectTimeout = 137 * time.Millisecond
	pool, identityService, tokens := analyticsLogsRuntimeDependencies(t)
	handler, err := openAnalyticsLogsRuntime(cfg, pool, identityService, tokens,
		func(runtimeConfig analyticslog.RuntimeConfig, _ analyticslog.HTTPDependencies) (http.Handler, error) {
			if runtimeConfig.HTTP.ConnectTimeout != cfg.AnalyticsConnectTimeout {
				t.Fatalf("analytics logs connect timeout = %s, want %s",
					runtimeConfig.HTTP.ConnectTimeout, cfg.AnalyticsConnectTimeout)
			}
			return http.NotFoundHandler(), nil
		})
	if err != nil || handler == nil {
		t.Fatalf("analytics logs runtime = (%T, %v)", handler, err)
	}
}

func TestOpenAnalyticsLogsRuntimeDefaultFactoryBuilds(t *testing.T) {
	cfg := validAnalyticsLogsConfig(t)
	pool, identityService, tokens := analyticsLogsRuntimeDependencies(t)
	handler, err := openAnalyticsLogsRuntime(cfg, pool, identityService, tokens, nil)
	if err != nil || handler == nil {
		t.Fatalf("default analytics logs runtime = (%T, %v)", handler, err)
	}
}

func TestOpenAnalyticsLogsRuntimeFailsClosed(t *testing.T) {
	cfg := validAnalyticsLogsConfig(t)
	pool, identityService, tokens := analyticsLogsRuntimeDependencies(t)
	factoryErr := errors.New("analytics logs factory failed")
	var typedNil *analyticsLogsNilHandler
	var typedNilFunc analyticsLogsNilHandlerFunc
	for _, test := range []struct {
		name    string
		factory analyticsLogsHandlerFactory
	}{
		{name: "factory error", factory: func(analyticslog.RuntimeConfig, analyticslog.HTTPDependencies) (http.Handler, error) {
			return nil, factoryErr
		}},
		{name: "nil handler", factory: func(analyticslog.RuntimeConfig, analyticslog.HTTPDependencies) (http.Handler, error) {
			return nil, nil
		}},
		{name: "typed nil handler", factory: func(analyticslog.RuntimeConfig, analyticslog.HTTPDependencies) (http.Handler, error) {
			return typedNil, nil
		}},
		{name: "typed nil function handler", factory: func(analyticslog.RuntimeConfig, analyticslog.HTTPDependencies) (http.Handler, error) {
			return typedNilFunc, nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, err := openAnalyticsLogsRuntime(cfg, pool, identityService, tokens, test.factory)
			if handler != nil || err == nil {
				t.Fatalf("failed analytics logs runtime = (%T, %v)", handler, err)
			}
			if strings.Contains(err.Error(), cfg.ClickHousePassword) {
				t.Fatalf("analytics logs initialization error leaked ClickHouse password: %v", err)
			}
		})
	}
}

func TestOpenAnalyticsLogsRuntimeRejectsInvalidCredentialDependencies(t *testing.T) {
	cfg := validAnalyticsLogsConfig(t)
	pool, identityService, tokens := analyticsLogsRuntimeDependencies(t)
	cfg.APIKeyPepper = []byte("short")
	called := false
	handler, err := openAnalyticsLogsRuntime(cfg, pool, identityService, tokens,
		func(analyticslog.RuntimeConfig, analyticslog.HTTPDependencies) (http.Handler, error) {
			called = true
			return http.NotFoundHandler(), nil
		})
	if handler != nil || err == nil || called {
		t.Fatalf("invalid credential dependencies = (%T, %v), factory called=%t", handler, err, called)
	}
}

type analyticsLogsNilHandler struct{}

func (*analyticsLogsNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

type analyticsLogsNilHandlerFunc func(http.ResponseWriter, *http.Request)

func (handler analyticsLogsNilHandlerFunc) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler(writer, request)
}

func validAnalyticsLogsConfig(t *testing.T) config.Config {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
	t.Setenv("ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID", "runtime-active")
	t.Setenv("ANALYTICS_LOGS_CURSOR_KEYS_JSON", `{"runtime-active":"`+key+`"}`)
	cfg := validAnalyticsQueryConfig()
	cfg.APIKeyPepper = []byte("analytics-logs-api-key-pepper-32-bytes")
	return cfg
}

func analyticsLogsRuntimeDependencies(
	t *testing.T,
) (*pgxpool.Pool, *identity.Service, *identity.TokenManager) {
	t.Helper()
	poolConfig, err := pgxpool.ParseConfig("postgres://analytics:analytics@127.0.0.1:1/analytics?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager("analytics-logs-access-token-secret", validAnalyticsQueryConfig().AnalyticsQueryTimeout)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, validAnalyticsQueryConfig().AnalyticsHandlerTimeout)
	if err != nil {
		t.Fatal(err)
	}
	return pool, identityService, tokens
}
