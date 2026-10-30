package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementusage"
	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/cdnca/cdnca/services/control-api/internal/platformpolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newEntitlementUsageReporter reports the thirteen quota values to the license
// service on each new lease and at least hourly (fix-usagereport).
func newEntitlementUsageReporter(cfg config.Config, pool *pgxpool.Pool, analyticsRuntime *analyticsQueryRuntime,
	policyState *platformpolicy.State,
) (*entitlementsync.UsageReporter, error) {
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
		return nil, errors.New("CONTROL_INSTALLATION_ID must be a canonical UUID")
	}
	privateKey, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, err
	}
	client, err := entitlementsync.NewClient(cfg.LicenseServiceURL, nil)
	if err != nil {
		return nil, err
	}
	collector := entitlementusage.Collector{
		Pool: pool,
		ExcludeBlocked: func(ctx context.Context) (bool, error) {
			return openrestysecurity.BlockPageNotCounted(ctx, pool)
		},
		ReleaseChannels: func() int {
			snapshot, _ := policyState.Snapshot()
			return len(snapshot.Policy.AllowedReleaseChannels)
		},
	}
	if clickHouse, ok := analyticsRuntime.QueryStore().(*analytics.Client); ok && clickHouse != nil {
		collector.Traffic = clickHouse
	} else {
		slog.Warn("entitlement usage is not reported: monthly_traffic_bytes needs ANALYTICS_QUERY_ENABLED=true")
	}
	return entitlementsync.NewUsageReporter(entitlementsync.UsageReporterConfig{
		Client:         client,
		Store:          entitlementsync.NewPostgresStore(pool, nil),
		State:          entitlementsync.NewPostgresUsageState(pool),
		InstallationID: installationID,
		PrivateKey:     privateKey,
		Collect:        collector.Collect,
		Logger:         slog.Default(),
		BackoffMax:     cfg.EntitlementSyncBackoffMax,
	})
}
