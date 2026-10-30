package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/cdnca/cdnca/services/control-api/internal/nodesshinstall"
	"github.com/jackc/pgx/v5/pgxpool"
)

const nodeSSHInstallInterval = 5 * time.Second

// buildNodeSSHInstallRuntime wires SSH remote node install: SSH secrets use the DNS credential keyring; the registration key is
// derived from the API key pepper exactly like the console install command.
// Without a pepper the jobs fail with registration_unavailable.
func buildNodeSSHInstallRuntime(pool *pgxpool.Pool, identityService *identity.Service,
	cipher *dnsacme.AESGCMCredentialCipher, trust *entitlementguard.TrustStore, pepper []byte,
) (*nodesshinstall.Service, httpapi.MountedHandlerFactory, error) {
	nodes := node.NewService(node.NewStoreWithClock(pool, time.Now, trust))
	if len(pepper) >= 32 {
		if err := nodes.ConfigureRegistration(pepper); err != nil {
			return nil, nil, err
		}
	}
	service, err := nodesshinstall.New(nodesshinstall.Config{Pool: pool, Cipher: cipher, Registration: nodes,
		Logger: slog.Default().With("component", "node_ssh_install")})
	if err != nil {
		return nil, nil, err
	}
	return service, func() (http.Handler, error) {
		return nodesshinstall.NewHandler(service, func(ctx context.Context, raw string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(ctx), raw)
		})
	}, nil
}
