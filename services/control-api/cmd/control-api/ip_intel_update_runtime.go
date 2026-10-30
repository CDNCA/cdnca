package main

import (
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/artifactsetdist"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/ipintelupdate"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildIPIntelUpdateRuntime is the official plugin module.ipintel.dnspup
// (PA-16): the admin page API and the pull worker. Secrets use the DNS
// credential keyring; the lease is read with the installation's trusted
// keys (nil trust: no feature, the plugin stays inert). A published local
// library wakes the node artifact set distributor.
func buildIPIntelUpdateRuntime(pool *pgxpool.Pool, identityService *identity.Service, cipher *dnsacme.AESGCMCredentialCipher,
	trust *entitlementguard.TrustStore, nodeArtifactSets *artifactsetdist.Distributor,
) (*ipintelupdate.Service, httpapi.MountedHandlerFactory, error) {
	if cipher == nil || trust == nil {
		return nil, nil, nil
	}
	guard := entitlementguard.NewGuard(pool, time.Now, trust)
	service, err := ipintelupdate.New(ipintelupdate.Config{Pool: pool, Cipher: cipher, Features: guard,
		Publisher: artifactsync.NewStore(pool, time.Now).WithFeatures(guard),
		OnPublished: func() {
			if nodeArtifactSets != nil {
				nodeArtifactSets.Wake()
			}
		}})
	if err != nil {
		return nil, nil, err
	}
	factory := func() (http.Handler, error) {
		return ipintelupdate.NewHandler(service, identityService.AuthenticateSession)
	}
	return service, factory, nil
}
