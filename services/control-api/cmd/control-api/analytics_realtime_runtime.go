package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtimehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	analyticsRealtimeRuntimeEnabledEnv   = "ANALYTICS_REALTIME_RUNTIME_ENABLED"
	analyticsRealtimeCursorKeyBase64Env  = "ANALYTICS_REALTIME_CURSOR_KEY_BASE64"
	analyticsRealtimeQueryTimeoutEnv     = "ANALYTICS_REALTIME_QUERY_TIMEOUT"
	analyticsRealtimeMaxResponseBytesEnv = "ANALYTICS_REALTIME_MAX_RESPONSE_BYTES"
)

type analyticsRealtimeRuntimeConfig struct {
	Enabled   bool
	CursorKey []byte
	Handler   analyticsrealtimehttp.Config
}

func loadAnalyticsRealtimeRuntimeConfig() (analyticsRealtimeRuntimeConfig, error) {
	return loadAnalyticsRealtimeRuntimeConfigFromEnv(os.Environ())
}

func loadAnalyticsRealtimeRuntimeConfigFromEnv(environment []string) (analyticsRealtimeRuntimeConfig, error) {
	known := map[string]bool{
		analyticsRealtimeRuntimeEnabledEnv: true, analyticsRealtimeCursorKeyBase64Env: true,
		analyticsRealtimeQueryTimeoutEnv: true, analyticsRealtimeMaxResponseBytesEnv: true,
	}
	values := make(map[string]string, len(known))
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if !known[name] {
			if strings.HasPrefix(name, realtimeCoverageRuntimePrefix) {
				continue
			}
			if strings.HasPrefix(name, "ANALYTICS_REALTIME_") {
				return analyticsRealtimeRuntimeConfig{}, errors.New("analytics realtime runtime contains unsupported environment structure")
			}
			continue
		}
		if _, exists := values[name]; exists {
			return analyticsRealtimeRuntimeConfig{}, errors.New(name + " must be defined exactly once")
		}
		values[name] = value
	}
	enabled, err := strictCustomRBACRuntimeBool(values[analyticsRealtimeRuntimeEnabledEnv], analyticsRealtimeRuntimeEnabledEnv)
	if err != nil {
		return analyticsRealtimeRuntimeConfig{}, err
	}
	if !enabled {
		for _, name := range []string{analyticsRealtimeCursorKeyBase64Env, analyticsRealtimeQueryTimeoutEnv, analyticsRealtimeMaxResponseBytesEnv} {
			if values[name] != "" {
				return analyticsRealtimeRuntimeConfig{}, errors.New("analytics realtime runtime is disabled but configuration was provided")
			}
		}
		return analyticsRealtimeRuntimeConfig{}, nil
	}
	encoded := values[analyticsRealtimeCursorKeyBase64Env]
	key, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded)
	if encoded == "" || strings.TrimSpace(encoded) != encoded || decodeErr != nil || len(key) < 32 || len(key) > 128 ||
		base64.StdEncoding.EncodeToString(key) != encoded {
		clear(key)
		return analyticsRealtimeRuntimeConfig{}, errors.New(analyticsRealtimeCursorKeyBase64Env + " is required and must encode 32 to 128 bytes using canonical padded base64")
	}
	config := analyticsRealtimeRuntimeConfig{Enabled: true, CursorKey: key}
	if raw := values[analyticsRealtimeQueryTimeoutEnv]; raw != "" {
		config.Handler.QueryTimeout, err = time.ParseDuration(raw)
		if err != nil || config.Handler.QueryTimeout <= 0 {
			config.clearSecrets()
			return analyticsRealtimeRuntimeConfig{}, errors.New(analyticsRealtimeQueryTimeoutEnv + " must be a positive duration")
		}
	}
	if raw := values[analyticsRealtimeMaxResponseBytesEnv]; raw != "" {
		config.Handler.MaxResponseBytes, err = strconv.Atoi(raw)
		if err != nil || config.Handler.MaxResponseBytes <= 0 {
			config.clearSecrets()
			return analyticsRealtimeRuntimeConfig{}, errors.New(analyticsRealtimeMaxResponseBytesEnv + " must be a positive integer")
		}
	}
	return config, nil
}

func (config *analyticsRealtimeRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	clear(config.CursorKey)
	config.CursorKey = nil
}

func buildAndClearAnalyticsRealtimeHandlerFactory(
	config *analyticsRealtimeRuntimeConfig,
	runtime *analyticsQueryRuntime,
	pool *pgxpool.Pool,
) (httpapi.AnalyticsRealtimeHandlerFactory, error) {
	if config == nil {
		return nil, errors.New("analytics realtime runtime configuration is unavailable")
	}
	defer config.clearSecrets()
	if !config.Enabled {
		return nil, nil
	}
	client, ok := runtime.QueryStore().(*analytics.Client)
	if !ok || client == nil || pool == nil || len(config.CursorKey) < 32 || len(config.CursorKey) > 128 {
		return nil, errors.New("analytics realtime production dependencies are required")
	}
	coverage, err := analytics.NewPostgresRealtimeExpectedCountReader(pool)
	if err != nil {
		return nil, errors.New("initialize analytics realtime coverage authority")
	}
	source, err := analytics.NewRealtimeV2Source(client, coverage)
	if err != nil {
		return nil, errors.New("initialize analytics realtime source")
	}
	service, err := analyticsrealtime.NewService(source, analyticsrealtime.Config{CursorKey: bytes.Clone(config.CursorKey), Now: time.Now})
	if err != nil {
		return nil, errors.New("initialize analytics realtime service")
	}
	handlerConfig := config.Handler
	return func(authenticate analyticsrealtimehttp.Authenticator) (http.Handler, error) {
		return analyticsrealtimehttp.NewHandler(service, authenticate, handlerConfig)
	}, nil
}
