package main

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/cdnca/cdnca/services/control-api/internal/sitestatusrecovery"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type siteStatusRecoveryRuntimeConfig struct {
	Enabled bool
	Runtime sitestatusrecovery.RuntimeConfig
}

type siteStatusRecoveryRuntimeDependencies struct {
	Pool  *pgxpool.Pool
	Clock func() time.Time
}

type siteStatusRecoveryProductionRuntime struct {
	core *sitestatusrecovery.Runtime
}

func siteStatusRecoveryRuntimeConfigFromControlConfig(
	source config.Config,
) (siteStatusRecoveryRuntimeConfig, error) {
	if !source.SiteStatusRecoveryEnabled {
		if source.SiteStatusRecoveryTenantID != uuid.Nil || source.SiteStatusRecoveryWorkerID != "" ||
			source.SiteStatusRecoveryBatchSize != 0 || source.SiteStatusRecoveryLeaseDuration != 0 ||
			source.SiteStatusRecoveryPollInterval != 0 || source.SiteStatusRecoveryOperationTimeout != 0 ||
			source.SiteStatusRecoveryReportTimeout != 0 {
			return siteStatusRecoveryRuntimeConfig{}, errors.New("disabled site status recovery runtime configuration is not empty")
		}
		return siteStatusRecoveryRuntimeConfig{}, nil
	}
	if source.ShutdownPeriod < source.SiteStatusRecoveryOperationTimeout {
		return siteStatusRecoveryRuntimeConfig{}, errors.New("site status recovery operation timeout exceeds shutdown period")
	}
	return siteStatusRecoveryRuntimeConfig{Enabled: true, Runtime: sitestatusrecovery.RuntimeConfig{
		TenantID: source.SiteStatusRecoveryTenantID, WorkerID: source.SiteStatusRecoveryWorkerID,
		BatchSize: source.SiteStatusRecoveryBatchSize, LeaseDuration: source.SiteStatusRecoveryLeaseDuration,
		PollInterval:     source.SiteStatusRecoveryPollInterval,
		OperationTimeout: source.SiteStatusRecoveryOperationTimeout,
		ReportTimeout:    source.SiteStatusRecoveryReportTimeout,
	}}, nil
}

func openSiteStatusRecoveryRuntime(
	config siteStatusRecoveryRuntimeConfig,
	dependencies siteStatusRecoveryRuntimeDependencies,
) (*siteStatusRecoveryProductionRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if !siteStatusRecoveryRuntimePoolConfigured(dependencies.Pool) {
		return nil, errors.New("site status recovery runtime PostgreSQL pool is required")
	}
	clock := dependencies.Clock
	if clock == nil {
		clock = time.Now
	}
	jobs, err := jobstate.NewStore(dependencies.Pool, clock)
	if err != nil {
		return nil, err
	}
	core, err := sitestatusrecovery.NewRuntime(config.Runtime, sitestatusrecovery.RuntimeDependencies{
		JobState: jobs, Recovery: site.NewStoreWithClock(dependencies.Pool, clock, nil),
	})
	if err != nil {
		return nil, err
	}
	return &siteStatusRecoveryProductionRuntime{core: core}, nil
}

func siteStatusRecoveryRuntimePoolConfigured(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	config := pool.Config()
	return config != nil && config.MaxConns > 0
}

func (runtime *siteStatusRecoveryProductionRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.core == nil {
		return sitestatusrecovery.ErrInvalidRuntime
	}
	return runtime.core.Run(ctx)
}

func (runtime *siteStatusRecoveryProductionRuntime) Ready() error {
	if runtime == nil || runtime.core == nil {
		return sitestatusrecovery.ErrInvalidRuntime
	}
	return runtime.core.Ready()
}

func (runtime *siteStatusRecoveryProductionRuntime) Close(ctx context.Context) error {
	if runtime == nil || runtime.core == nil {
		return sitestatusrecovery.ErrInvalidRuntime
	}
	return runtime.core.Close(ctx)
}
