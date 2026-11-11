package main

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/statuspage"
	"github.com/cdnca/cdnca/services/control-api/internal/statuspagehttp"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildStatusPageHandlerFactory starts the status page sampler for the life
// of ctx and returns the handler of its routes. The public route is rate
// limited by the client address behind the trusted proxies, the same
// resolution API keys use.
func buildStatusPageHandlerFactory(ctx context.Context, pool *pgxpool.Pool, identityService *identity.Service,
	trustedProxyCIDRs []string, maxProxyHops int) (httpapi.MountedHandlerFactory, error) {
	service, err := statuspage.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		return nil, err
	}
	resolver, err := accountrecoverycontext.NewSourceIPResolver(trustedProxyCIDRs, maxProxyHops)
	if err != nil {
		return nil, err
	}
	go service.Run(ctx)
	return func() (http.Handler, error) {
		return statuspagehttp.New(service, func(request *http.Request, rawSession string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(request.Context()), rawSession)
		}, func(request *http.Request) string {
			if address, err := resolver.ResolveSourceIP(request); err == nil {
				return address.String()
			}
			host, _, _ := net.SplitHostPort(request.RemoteAddr)
			return host
		})
	}, nil
}
