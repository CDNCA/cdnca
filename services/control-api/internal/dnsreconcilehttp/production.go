package dnsreconcilehttp

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultDatabaseProbeTimeout = 3 * time.Second

// NewProductionHandler assembles the PostgreSQL-backed job store and durable
// DNS runtime. It does not mount routes into the shared control-api server.
func NewProductionHandler(
	ctx context.Context,
	config ProductionConfig,
	dependencies ProductionDependencies,
) (*Handler, error) {
	if ctx == nil || !productionDependenciesReady(dependencies) {
		return nil, ErrInvalidConfig
	}
	if config.DatabaseProbeTimeout == 0 {
		config.DatabaseProbeTimeout = defaultDatabaseProbeTimeout
	}
	if config.DatabaseProbeTimeout <= 0 || config.DatabaseProbeTimeout > 30*time.Second {
		return nil, ErrInvalidConfig
	}
	config.Runtime = runtimeDefaults(config.Runtime)
	if !runtimeConfigValid(config.Runtime) || !productionTimeoutsValid(config.HTTP, config.Runtime) {
		return nil, ErrInvalidConfig
	}
	if config.HTTP.CommandTimeout == 0 {
		config.HTTP.CommandTimeout = defaultCommandTimeout
	}
	probeContext, cancel := context.WithTimeout(ctx, config.DatabaseProbeTimeout)
	defer cancel()
	if err := dependencies.Pool.Ping(probeContext); err != nil {
		return nil, ErrInvalidConfig
	}
	store, err := dnsreconcile.NewPostgresStore(dependencies.Pool, dependencies.Jobs, config.Runtime.Now)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	runtime, err := dnsreconcile.NewRuntime(config.Runtime, dnsreconcile.RuntimeDependencies{
		Store: store, CheckerResolver: dependencies.CheckerResolver,
		ProviderResolver: dependencies.ProviderResolver, Entitlement: dependencies.Entitlement,
	})
	if err != nil || !runtime.Configured() {
		return nil, ErrInvalidConfig
	}
	return NewHandler(Dependencies{
		Sessions: dependencies.Sessions, IAM: dependencies.IAM,
		Domain: runtime, Workloads: dependencies.Workloads,
	}, config.HTTP)
}

func productionTimeoutsValid(httpConfig Config, runtimeConfig dnsreconcile.RuntimeConfig) bool {
	commandTimeout := httpConfig.CommandTimeout
	if commandTimeout == 0 {
		commandTimeout = defaultCommandTimeout
	}
	return commandTimeout > runtimeConfig.OverallTimeout && commandTimeout <= runtimeConfig.CommitLeaseDuration
}

func productionDependenciesReady(dependencies ProductionDependencies) bool {
	if !poolConfigured(dependencies.Pool) || dependencies.Jobs == nil ||
		isNil(dependencies.CheckerResolver) || isNil(dependencies.ProviderResolver) ||
		isNil(dependencies.Entitlement) || isNil(dependencies.Sessions) ||
		isNil(dependencies.IAM) || isNil(dependencies.Workloads) {
		return false
	}
	return true
}

func poolConfigured(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	config := pool.Config()
	return config != nil && config.ConnConfig != nil && config.MaxConns > 0 && config.MaxConns <= 20
}

func runtimeDefaults(config dnsreconcile.RuntimeConfig) dnsreconcile.RuntimeConfig {
	if config.ProviderAttempts == 0 {
		config.ProviderAttempts = 3
	}
	if config.ProviderTimeout == 0 {
		config.ProviderTimeout = 5 * time.Second
	}
	if config.PollAttempts == 0 {
		config.PollAttempts = 20
	}
	if config.RequiredConsecutive == 0 {
		config.RequiredConsecutive = 3
	}
	if config.InitialBackoff == 0 {
		config.InitialBackoff = time.Second
	}
	if config.MaximumBackoff == 0 {
		config.MaximumBackoff = 30 * time.Second
	}
	if config.OverallTimeout == 0 {
		config.OverallTimeout = 15 * time.Minute
	}
	if config.ApplyLeaseDuration == 0 {
		config.ApplyLeaseDuration = 16 * time.Minute
	}
	if config.CommitLeaseDuration == 0 {
		config.CommitLeaseDuration = 16 * time.Minute
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return config
}

func runtimeConfigValid(config dnsreconcile.RuntimeConfig) bool {
	return config.ProviderAttempts >= 1 && config.ProviderAttempts <= 3 &&
		config.ProviderTimeout > 0 && config.ProviderTimeout <= 30*time.Second &&
		config.PollAttempts >= 1 && config.PollAttempts <= 20 &&
		config.RequiredConsecutive >= 1 && config.RequiredConsecutive <= 5 &&
		config.RequiredConsecutive <= config.PollAttempts &&
		config.InitialBackoff > 0 && config.MaximumBackoff >= config.InitialBackoff &&
		config.MaximumBackoff <= 30*time.Second && config.OverallTimeout >= config.ProviderTimeout &&
		config.OverallTimeout <= 15*time.Minute && config.JitterFraction >= 0 && config.JitterFraction <= 0.5 &&
		config.ApplyLeaseDuration > config.OverallTimeout && config.ApplyLeaseDuration <= time.Hour &&
		config.CommitLeaseDuration > config.OverallTimeout && config.CommitLeaseDuration <= time.Hour && config.Now != nil
}
