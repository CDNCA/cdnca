package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/domainblocklist"
	"github.com/cdnca/cdnca/services/control-api/internal/domainownership"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrusthttp"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildDomainTrustRuntime wires the domain blocklist and ownership endpoints.
func buildDomainTrustRuntime(_ context.Context, pool *pgxpool.Pool, identityService *identity.Service,
	_ *slog.Logger) (httpapi.MountedHandlerFactory, error) {
	verifier, err := domainownership.NewDefaultNetworkVerifier()
	if err != nil {
		return nil, err
	}
	notifier, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	ownership, err := domainownership.NewService(pool, audit.New(pool), verifier, notifier, time.Now)
	if err != nil {
		return nil, err
	}
	blocklist, err := domainblocklist.NewService(pool, time.Now)
	if err != nil {
		return nil, err
	}
	handler, err := domaintrusthttp.NewHandler(ownership, blocklist, identityService.AuthenticateSession)
	if err != nil {
		return nil, err
	}
	return func() (http.Handler, error) { return handler, nil }, nil
}
