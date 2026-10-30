package main

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicyhttp"
)

const urlAuthRuntimeEnabledEnv = "URL_AUTH_POLICY_RUNTIME_ENABLED"

type urlAuthRuntimeConfig struct {
	Enabled bool
	Handler urlauthpolicyhttp.HandlerConfig
}

func loadURLAuthRuntimeConfig() (urlAuthRuntimeConfig, error) {
	return loadURLAuthRuntimeConfigFromEnv(os.Environ())
}

func loadURLAuthRuntimeConfigFromEnv(environment []string) (urlAuthRuntimeConfig, error) {
	var value string
	found := false
	unknown := false
	for _, entry := range environment {
		name, candidate, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if name != urlAuthRuntimeEnabledEnv {
			unknown = unknown || strings.HasPrefix(name, "URL_AUTH_POLICY_RUNTIME_")
			continue
		}
		if found {
			return urlAuthRuntimeConfig{}, errors.New(urlAuthRuntimeEnabledEnv + " must be defined exactly once")
		}
		value = candidate
		found = true
	}

	switch value {
	case "", "false":
		return urlAuthRuntimeConfig{}, nil
	case "true":
		if unknown {
			return urlAuthRuntimeConfig{}, errors.New("URL auth policy runtime contains unsupported environment structure")
		}
		return urlAuthRuntimeConfig{Enabled: true}, nil
	default:
		return urlAuthRuntimeConfig{}, errors.New(urlAuthRuntimeEnabledEnv + " must be true or false")
	}
}

func buildURLAuthHandlerFactory(
	config urlAuthRuntimeConfig,
	dependencies urlauthpolicyhttp.RuntimeDependencies,
) httpapi.MountedHandlerFactory {
	if !config.Enabled {
		return nil
	}
	return func() (http.Handler, error) {
		return urlauthpolicyhttp.NewRuntimeHandler(
			urlauthpolicyhttp.RuntimeConfig{Enabled: true, Handler: config.Handler},
			dependencies,
		)
	}
}
