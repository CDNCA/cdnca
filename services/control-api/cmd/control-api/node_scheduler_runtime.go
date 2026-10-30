package main

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeschedulerhttp"
)

const nodeSchedulerRuntimeEnabledEnv = "NODE_SCHEDULING_RUNTIME_ENABLED"

type nodeSchedulerRuntimeConfig struct {
	Enabled bool
}

func loadNodeSchedulerRuntimeConfig() (nodeSchedulerRuntimeConfig, error) {
	return loadNodeSchedulerRuntimeConfigFromEnv(os.Environ())
}

func loadNodeSchedulerRuntimeConfigFromEnv(environment []string) (nodeSchedulerRuntimeConfig, error) {
	var value string
	found := false
	unknown := false
	for _, entry := range environment {
		name, candidate, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if name != nodeSchedulerRuntimeEnabledEnv {
			unknown = unknown || strings.HasPrefix(name, "NODE_SCHEDULING_RUNTIME_")
			continue
		}
		if found {
			return nodeSchedulerRuntimeConfig{}, errors.New(nodeSchedulerRuntimeEnabledEnv + " must be defined exactly once")
		}
		value = candidate
		found = true
	}

	switch value {
	case "", "false":
		return nodeSchedulerRuntimeConfig{}, nil
	case "true":
		if unknown {
			return nodeSchedulerRuntimeConfig{}, errors.New("node scheduling runtime contains unsupported environment structure")
		}
		return nodeSchedulerRuntimeConfig{Enabled: true}, nil
	default:
		return nodeSchedulerRuntimeConfig{}, errors.New(nodeSchedulerRuntimeEnabledEnv + " must be true or false")
	}
}

func buildNodeSchedulerHandlerFactory(
	config nodeSchedulerRuntimeConfig,
	dependencies nodeschedulerhttp.RuntimeDependencies,
) httpapi.MountedHandlerFactory {
	if !config.Enabled {
		return nil
	}
	return func() (http.Handler, error) {
		return newNodeSchedulerRuntimeHandler(dependencies)
	}
}

// newNodeSchedulerRuntimeHandler intentionally only assembles the slice. The
// shared router owner mounts it after reviewing the dedicated OpenAPI fragment.
func newNodeSchedulerRuntimeHandler(dependencies nodeschedulerhttp.RuntimeDependencies) (http.Handler, error) {
	return nodeschedulerhttp.NewRuntimeHandler(dependencies)
}
