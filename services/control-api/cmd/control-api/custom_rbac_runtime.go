package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanagerhttp"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	customRBACRuntimeEnabledEnv  = "CUSTOM_RBAC_RUNTIME_ENABLED"
	customRBACCursorKeyBase64Env = "CUSTOM_RBAC_CURSOR_KEY_BASE64"
)

type customRBACRuntimeConfig struct {
	Enabled   bool
	CursorKey []byte
	Handler   rbacmanagerhttp.HandlerConfig
}

type customRBACRuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	StepUp   rbacmanager.StepUpVerifier
}

func loadCustomRBACRuntimeConfig() (customRBACRuntimeConfig, error) {
	return loadCustomRBACRuntimeConfigFromEnv(os.Environ())
}

func loadCustomRBACRuntimeConfigFromEnv(environment []string) (customRBACRuntimeConfig, error) {
	values := make(map[string]string, 2)
	duplicates := make(map[string]bool, 2)
	unknown := false
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		switch name {
		case customRBACRuntimeEnabledEnv, customRBACCursorKeyBase64Env:
			if _, exists := values[name]; exists {
				duplicates[name] = true
			}
			values[name] = value
		default:
			unknown = unknown || strings.HasPrefix(name, "CUSTOM_RBAC_RUNTIME_") ||
				strings.HasPrefix(name, "CUSTOM_RBAC_CURSOR_")
		}
	}
	if duplicates[customRBACRuntimeEnabledEnv] {
		return customRBACRuntimeConfig{}, errors.New(customRBACRuntimeEnabledEnv + " must be defined exactly once")
	}
	enabled, err := strictCustomRBACRuntimeBool(values[customRBACRuntimeEnabledEnv], customRBACRuntimeEnabledEnv)
	if err != nil || !enabled {
		return customRBACRuntimeConfig{}, err
	}
	if duplicates[customRBACCursorKeyBase64Env] {
		return customRBACRuntimeConfig{}, errors.New(customRBACCursorKeyBase64Env + " must be defined exactly once")
	}
	if unknown {
		return customRBACRuntimeConfig{}, errors.New("custom RBAC runtime contains unsupported environment structure")
	}
	encoded := values[customRBACCursorKeyBase64Env]
	if encoded == "" || strings.TrimSpace(encoded) != encoded {
		return customRBACRuntimeConfig{}, errors.New(customRBACCursorKeyBase64Env + " is required and must not contain surrounding whitespace")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) < 32 || len(key) > 128 || base64.StdEncoding.EncodeToString(key) != encoded {
		clear(key)
		return customRBACRuntimeConfig{}, errors.New(customRBACCursorKeyBase64Env + " must encode 32 to 128 bytes using canonical padded base64")
	}
	return customRBACRuntimeConfig{Enabled: true, CursorKey: key}, nil
}

func (config *customRBACRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	clear(config.CursorKey)
	config.CursorKey = nil
}

func buildAndClearCustomRBACHandlerFactory(
	config *customRBACRuntimeConfig,
	dependencies customRBACRuntimeDependencies,
) (httpapi.MountedHandlerFactory, error) {
	if config == nil {
		return nil, errors.New("custom RBAC runtime configuration is unavailable")
	}
	defer config.clearSecrets()
	if !config.Enabled {
		return nil, nil
	}
	if len(config.CursorKey) < 32 || len(config.CursorKey) > 128 {
		return nil, errors.New("custom RBAC runtime configuration is incomplete")
	}
	key := bytes.Clone(config.CursorKey)
	handlerConfig := config.Handler
	return func() (http.Handler, error) {
		return rbacmanagerhttp.NewRuntimeHandler(
			rbacmanagerhttp.RuntimeConfig{Enabled: true, CursorKey: key, Handler: handlerConfig},
			rbacmanagerhttp.RuntimeDependencies{
				Pool: dependencies.Pool, Identity: dependencies.Identity, StepUp: dependencies.StepUp,
			},
		)
	}, nil
}

func strictCustomRBACRuntimeBool(value, name string) (bool, error) {
	switch value {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, errors.New(name + " must be true or false")
	}
}
