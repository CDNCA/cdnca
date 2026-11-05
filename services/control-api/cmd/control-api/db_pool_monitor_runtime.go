package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/cdnca/cdnca/libs/dbpoolmon"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/poolmon"
	"github.com/jackc/pgx/v5/pgxpool"
)

// startDBPoolMonitor samples the serve pool every 10
// seconds until ctx ends and notifies the platform when requests queue for
// connections; the maintenance page reads it through the returned handler
// factory (nil without a configured identity service).
func startDBPoolMonitor(ctx context.Context, pool *pgxpool.Pool, identityService *identity.Service) (httpapi.MountedHandlerFactory, error) {
	store, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	monitor := poolmon.New(controlInstanceName(), dbpoolmon.FromPool(pool), database.Residents,
		poolmon.NewPGNotifier(pool.Config().ConnConfig, store), slog.Default().With("component", "db_pool_monitor"))
	go func() { _ = monitor.Run(ctx) }()
	if identityService == nil || !identityService.Configured() {
		return nil, nil
	}
	return func() (http.Handler, error) {
		return poolmon.NewHandler(monitor, func(request *http.Request, raw string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(request.Context(), raw)
		}), nil
	}, nil
}

// controlInstanceName names this control-api in pool alerts: the host name,
// stable across restarts so a restart closes the alerts its previous
// process left.
func controlInstanceName() string {
	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}
	return "control-api"
}
