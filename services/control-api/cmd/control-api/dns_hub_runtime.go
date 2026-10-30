package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnshubhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildDNSHubRuntime serves 用户端「域名解析」(ADR 0020 §3, community
// edition). nil (logged) without the DNS credential cipher: the routes then
// stay unmounted (404), as every other DNS-provider feature.
func buildDNSHubRuntime(pool *pgxpool.Pool, identityService *identity.Service,
	cipher *dnsacme.AESGCMCredentialCipher) (httpapi.MountedHandlerFactory, error) {
	if !configuredRuntimePool(pool) || identityService == nil {
		return nil, nil
	}
	if cipher == nil {
		slog.Warn("DNS hub is not served: the DNS credential cipher is not configured")
		return nil, nil
	}
	hub, err := dnsproviderremotesource.NewHub(dnsproviderremotesource.New(pool, cipher),
		dnsproviderremote.NewHubRemote(), audit.New(pool), time.Now)
	if err != nil {
		return nil, err
	}
	handler, err := dnshubhttp.NewHandler(hub, identityService.AuthenticateSession)
	if err != nil {
		return nil, err
	}
	return func() (http.Handler, error) { return handler, nil }, nil
}
