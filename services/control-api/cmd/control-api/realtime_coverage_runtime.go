package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	realtimeCoverageRuntimePrefix          = "ANALYTICS_REALTIME_COVERAGE_FINALIZER_"
	realtimeCoverageRuntimeEnabledEnv      = realtimeCoverageRuntimePrefix + "ENABLED"
	realtimeCoverageRuntimePollIntervalEnv = realtimeCoverageRuntimePrefix + "POLL_INTERVAL"
	realtimeCoverageRuntimeGraceEnv        = realtimeCoverageRuntimePrefix + "FINALIZATION_GRACE"
	realtimeCoverageRuntimeMaxWindowsEnv   = realtimeCoverageRuntimePrefix + "MAXIMUM_WINDOWS"
)

var realtimeCoverageRuntimeEnvironment = []string{
	realtimeCoverageRuntimeEnabledEnv,
	realtimeCoverageRuntimePollIntervalEnv,
	realtimeCoverageRuntimeGraceEnv,
	realtimeCoverageRuntimeMaxWindowsEnv,
}

var errRealtimeCoverageRuntimeInvalid = errors.New("analytics realtime coverage finalizer runtime is invalid")

type realtimeCoverageRuntimeConfig struct {
	Enabled           bool
	PollInterval      time.Duration
	FinalizationGrace time.Duration
	MaximumWindows    int
	RetryInterval     time.Duration
}

type realtimeCoverageFinalizerCore interface {
	Run(context.Context) error
}

type realtimeCoverageProductionRuntime struct {
	core          realtimeCoverageFinalizerCore
	retryInterval time.Duration
	logger        *slog.Logger
}

func loadRealtimeCoverageRuntimeConfig() (realtimeCoverageRuntimeConfig, error) {
	return loadRealtimeCoverageRuntimeConfigFromEnv(os.Environ())
}

func loadRealtimeCoverageRuntimeConfigFromEnv(environment []string) (realtimeCoverageRuntimeConfig, error) {
	known := make(map[string]struct{}, len(realtimeCoverageRuntimeEnvironment))
	for _, name := range realtimeCoverageRuntimeEnvironment {
		known[name] = struct{}{}
	}
	values := make(map[string]string, len(realtimeCoverageRuntimeEnvironment))
	counts := make(map[string]int, len(realtimeCoverageRuntimeEnvironment))
	unknown := make([]string, 0)
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(name, realtimeCoverageRuntimePrefix) {
			continue
		}
		if _, ok := known[name]; !ok {
			unknown = append(unknown, name)
			continue
		}
		counts[name]++
		values[name] = value
	}
	if len(unknown) != 0 {
		sort.Strings(unknown)
		return realtimeCoverageRuntimeConfig{}, errors.New("unsupported analytics realtime coverage finalizer environment variable: " + unknown[0])
	}
	for _, name := range realtimeCoverageRuntimeEnvironment {
		if counts[name] > 1 {
			return realtimeCoverageRuntimeConfig{}, errors.New(name + " must be defined at most once")
		}
	}
	enabled, err := realtimeCoverageRuntimeBool(values[realtimeCoverageRuntimeEnabledEnv])
	if err != nil || !enabled {
		return realtimeCoverageRuntimeConfig{}, err
	}
	config := realtimeCoverageRuntimeConfig{
		Enabled: true, PollInterval: 30 * time.Second, FinalizationGrace: 2 * time.Minute, MaximumWindows: 64,
	}
	if config.PollInterval, err = realtimeCoverageRuntimeDuration(
		values, realtimeCoverageRuntimePollIntervalEnv, config.PollInterval, 10*time.Millisecond, time.Hour,
	); err != nil {
		return realtimeCoverageRuntimeConfig{}, err
	}
	if config.FinalizationGrace, err = realtimeCoverageRuntimeDuration(
		values, realtimeCoverageRuntimeGraceEnv, config.FinalizationGrace, time.Second, time.Hour,
	); err != nil {
		return realtimeCoverageRuntimeConfig{}, err
	}
	if config.MaximumWindows, err = realtimeCoverageRuntimeInteger(
		values, realtimeCoverageRuntimeMaxWindowsEnv, config.MaximumWindows, 1, 1000,
	); err != nil {
		return realtimeCoverageRuntimeConfig{}, err
	}
	config.RetryInterval = min(config.PollInterval, 5*time.Second)
	return config, nil
}

func buildRealtimeCoverageProductionRuntime(
	config realtimeCoverageRuntimeConfig,
	pool *pgxpool.Pool,
	analyticsRuntime *analyticsQueryRuntime,
	logger *slog.Logger,
) (*realtimeCoverageProductionRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if pool == nil || analyticsRuntime == nil || analyticsRuntime.QueryStore() == nil {
		return nil, errors.New("analytics realtime coverage finalizer dependencies are incomplete")
	}
	client, ok := analyticsRuntime.QueryStore().(*analytics.Client)
	if !ok || client == nil {
		return nil, errors.New("analytics realtime coverage finalizer ClickHouse client is unavailable")
	}
	store, err := analytics.NewPostgresRealtimeCoverageStore(pool)
	if err != nil {
		return nil, err
	}
	connections, err := analytics.NewClickHouseRealtimeConnectionEvidenceReader(client)
	if err != nil {
		return nil, err
	}
	finalizer, err := analytics.NewRealtimeCoverageFinalizer(store, connections, analytics.RealtimeCoverageFinalizerConfig{
		PollInterval: config.PollInterval, FinalizationGrace: config.FinalizationGrace, MaximumWindows: config.MaximumWindows,
	})
	if err != nil {
		return nil, err
	}
	return newRealtimeCoverageProductionRuntime(finalizer, config.RetryInterval, logger)
}

func newRealtimeCoverageProductionRuntime(
	core realtimeCoverageFinalizerCore,
	retryInterval time.Duration,
	logger *slog.Logger,
) (*realtimeCoverageProductionRuntime, error) {
	if core == nil || retryInterval <= 0 || retryInterval > time.Hour || logger == nil {
		return nil, errRealtimeCoverageRuntimeInvalid
	}
	return &realtimeCoverageProductionRuntime{core: core, retryInterval: retryInterval, logger: logger}, nil
}

func (runtime *realtimeCoverageProductionRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.core == nil || runtime.logger == nil || ctx == nil {
		return errRealtimeCoverageRuntimeInvalid
	}
	for {
		err := runtime.core.Run(ctx)
		if ctx.Err() != nil {
			return nil
		}
		runtime.logger.Warn("analytics realtime coverage finalizer retrying", "error", err)
		timer := time.NewTimer(runtime.retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func realtimeCoverageRuntimeBool(value string) (bool, error) {
	switch value {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, errors.New(realtimeCoverageRuntimeEnabledEnv + " must be true or false")
	}
}

func realtimeCoverageRuntimeDuration(
	values map[string]string,
	name string,
	fallback, minimum, maximum time.Duration,
) (time.Duration, error) {
	value, exists := values[name]
	if !exists {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < minimum || parsed > maximum || strings.TrimSpace(value) != value {
		return 0, errors.New(name + " is invalid")
	}
	return parsed, nil
}

func realtimeCoverageRuntimeInteger(
	values map[string]string,
	name string,
	fallback, minimum, maximum int,
) (int, error) {
	value, exists := values[name]
	if !exists {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum || strconv.Itoa(parsed) != value {
		return 0, errors.New(name + " is invalid")
	}
	return parsed, nil
}
