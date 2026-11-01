package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnshubhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildDNSHubRuntime serves 用户端「域名解析」(ADR 0020 §3, community
// edition). nil (logged) without the DNS credential cipher: the routes then
// stay unmounted (404), as every other DNS-provider feature.
func buildDNSHubRuntime(pool *pgxpool.Pool, identityService *identity.Service,
	cipher *dnsacme.AESGCMCredentialCipher, apiKeys *apikey.Service) (httpapi.MountedHandlerFactory, error) {
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
	// plugapi-S1: tenant API keys (key scopes ∩ the owner's live RBAC) call
	// the hub like a session; nil apiKeys keeps it session-only.
	var authenticateAPIKey dnshubhttp.AuthenticateAPIKeyFunc
	if apiKeys != nil {
		authenticateAPIKey = func(ctx context.Context, raw string) (identity.Principal, uuid.UUID, error) {
			principal, keyID, _, err := apiKeys.AuthenticateWithKeyID(ctx, raw)
			return principal, keyID, err
		}
	}
	handler, err := dnshubhttp.NewHandler(hub, identityService.AuthenticateSession, authenticateAPIKey)
	if err != nil {
		return nil, err
	}
	return func() (http.Handler, error) { return handler, nil }, nil
}
