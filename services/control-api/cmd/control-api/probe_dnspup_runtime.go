package main

import (
	"context"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodednspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildProbeDNSPupRuntime is the official plugin module.probe.dnspup: the
// admin page API (with the node monitoring settings) and the probe source
// the origin failover, aggregated edge and node availability runners ask
// each round. Secrets use the DNS credential keyring; the
// lease is read with the installation's trusted keys (nil cipher or trust:
// no page, the runners keep their node / control plane sources).
func buildProbeDNSPupRuntime(pool *pgxpool.Pool, identityService *identity.Service, cipher *dnsacme.AESGCMCredentialCipher,
	trust *entitlementguard.TrustStore,
) (func(context.Context) dnspupprobe.Runtime, httpapi.MountedHandlerFactory, error) {
	if cipher == nil || trust == nil {
		return nil, nil, nil
	}
	alerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, nil, err
	}
	features := entitlementguard.NewGuard(pool, time.Now, trust)
	service, err := dnspupprobe.New(dnspupprobe.Config{Pool: pool, Cipher: cipher, Features: features, Alerts: alerts})
	if err != nil {
		return nil, nil, err
	}
	nodes, err := nodednspupprobe.NewStore(pool, features, time.Now)
	if err != nil {
		return nil, nil, err
	}
	factory := func() (http.Handler, error) {
		return dnspupprobe.NewHandler(service, identityService.AuthenticateSession, nodes)
	}
	return service.Runtime, factory, nil
}
