package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemcleanup"
	"github.com/cdnca/cdnca/services/control-api/internal/systemcleanuphttp"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettingshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/systemothersettings"
	"github.com/cdnca/cdnca/services/control-api/internal/systemothersettingshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/systemsettings"
	"github.com/cdnca/cdnca/services/control-api/internal/systemsettingshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettingshttp"
	"github.com/jackc/pgx/v5/pgxpool"
)

const systemSettingsRuntimeEnabledEnv = "SYSTEM_SETTINGS_RUNTIME_ENABLED"

type systemSettingsRuntimeConfig struct{ Enabled bool }

func loadSystemSettingsRuntimeConfig() (systemSettingsRuntimeConfig, error) {
	value := ""
	seen := false
	for _, entry := range os.Environ() {
		name, candidate, ok := strings.Cut(entry, "=")
		if !ok || name != systemSettingsRuntimeEnabledEnv {
			continue
		}
		if seen {
			return systemSettingsRuntimeConfig{}, errors.New(systemSettingsRuntimeEnabledEnv + " must be defined exactly once")
		}
		seen = true
		value = candidate
	}
	switch value {
	case "":
		return systemSettingsRuntimeConfig{Enabled: true}, nil
	case "false":
		return systemSettingsRuntimeConfig{}, nil
	case "true":
		return systemSettingsRuntimeConfig{Enabled: true}, nil
	default:
		return systemSettingsRuntimeConfig{}, errors.New(systemSettingsRuntimeEnabledEnv + " must be true or false")
	}
}

func buildSystemSettingsHandlerFactory(config systemSettingsRuntimeConfig, pool *pgxpool.Pool, identityService *identity.Service) (httpapi.MountedHandlerFactory, error) {
	if !config.Enabled {
		return nil, nil
	}
	if pool == nil || identityService == nil || !identityService.Configured() {
		return nil, errors.New("system settings runtime dependencies are incomplete")
	}
	return func() (http.Handler, error) {
		service, err := systemsettings.NewService(pool, audit.New(pool), time.Now)
		if err != nil {
			return nil, err
		}
		handler, err := systemsettingshttp.New(service, func(request *http.Request, rawSession string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(request.Context()), rawSession)
		})
		if err != nil {
			return nil, err
		}
		// PA-19: the enabled ui_page plugin origins join the CSP lookup.
		return handler.WithPluginOrigins(pluginUIOrigins(pool)), nil
	}, nil
}

func buildSystemCleanupSettingsHandlerFactory(config systemSettingsRuntimeConfig, pool *pgxpool.Pool, identityService *identity.Service) (httpapi.MountedHandlerFactory, error) {
	if !config.Enabled {
		return nil, nil
	}
	if pool == nil || identityService == nil || !identityService.Configured() {
		return nil, errors.New("system cleanup settings runtime dependencies are incomplete")
	}
	return func() (http.Handler, error) {
		service, err := systemcleanup.NewService(pool, audit.New(pool), time.Now)
		if err != nil {
			return nil, err
		}
		return systemcleanuphttp.New(service, func(request *http.Request, rawSession string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(request.Context()), rawSession)
		})
	}, nil
}

func buildSystemUserSettingsHandlerFactory(config systemSettingsRuntimeConfig, pool *pgxpool.Pool, identityService *identity.Service) (httpapi.MountedHandlerFactory, error) {
	if !config.Enabled {
		return nil, nil
	}
	if pool == nil || identityService == nil || !identityService.Configured() {
		return nil, errors.New("system user settings runtime dependencies are incomplete")
	}
	return func() (http.Handler, error) {
		service, err := systemusersettings.NewService(pool, audit.New(pool), time.Now)
		if err != nil {
			return nil, err
		}
		return systemusersettingshttp.New(service, func(request *http.Request, rawSession string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(request.Context()), rawSession)
		})
	}, nil
}

func buildSystemMailSettingsHandlerFactory(config systemSettingsRuntimeConfig, pool *pgxpool.Pool, identityService *identity.Service, cipher systemmailsettings.SecretCipher, sendTest systemmailsettings.TestSender, modules systemmailsettings.ModuleGate) (httpapi.MountedHandlerFactory, error) {
	if !config.Enabled {
		return nil, nil
	}
	if pool == nil || identityService == nil || !identityService.Configured() {
		return nil, errors.New("system mail settings runtime dependencies are incomplete")
	}
	return func() (http.Handler, error) {
		service, err := systemmailsettings.NewService(pool, audit.New(pool), time.Now)
		if err != nil {
			return nil, err
		}
		if cipher != nil {
			service.WithSecretCipher(cipher)
		}
		service.WithModuleGate(modules)
		handler, err := systemmailsettingshttp.New(service, func(request *http.Request, rawSession string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(request.Context()), rawSession)
		})
		if err != nil {
			return nil, err
		}
		return handler.WithTestSender(sendTest), nil
	}, nil
}

func buildSystemOtherSettingsHandlerFactory(config systemSettingsRuntimeConfig, pool *pgxpool.Pool, identityService *identity.Service) (httpapi.MountedHandlerFactory, error) {
	if !config.Enabled {
		return nil, nil
	}
	if pool == nil || identityService == nil || !identityService.Configured() {
		return nil, errors.New("system other settings runtime dependencies are incomplete")
	}
	return func() (http.Handler, error) {
		service, err := systemothersettings.NewService(pool, audit.New(pool), time.Now)
		if err != nil {
			return nil, err
		}
		return systemothersettingshttp.New(service, func(request *http.Request, rawSession string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(request.Context()), rawSession)
		})
	}, nil
}
