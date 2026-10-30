package main

import (
	"context"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/ccstatshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsecurityhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ccStatsRuntime is the CC page API half of the CC rule statistics,
// reading ClickHouse with the query identity. The cc_stats
// reports are ingested by the auto defense report router (the only consumer
// of the report stream, see main.go RegisterReportHandler).
type ccStatsRuntime struct {
	handler httpapi.MountedHandlerFactory
	// market serves relayed market attack logs (ML-21) from the same reader.
	market httpapi.MountedHandlerFactory
}

func openCCStatsRuntime(cfg config.Config, pool *pgxpool.Pool, authenticate func(context.Context, string) (identity.AuthenticatedSession, error)) (*ccStatsRuntime, error) {
	runtime := &ccStatsRuntime{}
	if cfg.AnalyticsQueryEnabled {
		reader, err := securityanalytics.NewClickHouse(cfg.ClickHouseURL, cfg.ClickHouseDatabase, cfg.ClickHouseUsername,
			cfg.ClickHousePassword, 10*time.Second)
		if err != nil {
			return nil, err
		}
		handler, err := ccstatshttp.NewHandler(ccstatshttp.Dependencies{Reader: reader, AuthenticateSession: authenticate,
			SiteExists: func(ctx context.Context, tenant, site uuid.UUID) (bool, error) {
				var exists bool
				err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sites WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL)`,
					tenant, site).Scan(&exists)
				return exists, err
			}})
		if err != nil {
			return nil, err
		}
		runtime.handler = func() (http.Handler, error) { return handler, nil }
		market, err := marketsecurityhttp.NewHandler(reader, authenticate)
		if err != nil {
			return nil, err
		}
		runtime.market = func() (http.Handler, error) { return market, nil }
	}
	return runtime, nil
}
