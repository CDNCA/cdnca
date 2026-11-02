package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/cdnca/cdnca/services/control-api/internal/nodesshinstall"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const nodeSSHInstallInterval = 5 * time.Second

// buildNodeSSHInstallRuntime wires SSH remote node install: SSH secrets use the DNS credential keyring; the registration key is
// derived from the API key pepper exactly like the console install command.
// Without a pepper the jobs fail with registration_unavailable.
func buildNodeSSHInstallRuntime(pool *pgxpool.Pool, identityService *identity.Service,
	cipher *dnsacme.AESGCMCredentialCipher, trust *entitlementguard.TrustStore, pepper []byte, controllerSSHCIDRs []string,
) (*nodesshinstall.Service, httpapi.MountedHandlerFactory, error) {
	nodes := node.NewService(node.NewStoreWithClock(pool, time.Now, trust))
	if len(pepper) >= 32 {
		if err := nodes.ConfigureRegistration(pepper); err != nil {
			return nil, nil, err
		}
	}
	// the controller's SSH egress for "only the controller may
	// SSH" (CDNCA_NODE_SSH_CONTROLLER_CIDRS); empty: detected below.
	access, err := nodesshinstall.NewAccessConfig(controllerSSHCIDRs)
	if err != nil {
		return nil, nil, err
	}
	service, err := nodesshinstall.New(nodesshinstall.Config{Pool: pool, Cipher: cipher, Registration: nodes, Access: access,
		Logger: slog.Default().With("component", "node_ssh_install")})
	if err != nil {
		return nil, nil, err
	}
	// Without CDNCA_NODE_SSH_CONTROLLER_CIDRS the egress is the
	// host's public address (the co-located Gateway's, else its interfaces').
	gatewayAddress := os.Getenv("CDNCA_GATEWAY_LOCAL_ADDRESS")
	service.UseEgressDetector(func(context.Context) []string {
		return nodesshinstall.DetectEgress(gatewayAddress, net.InterfaceAddrs)
	})
	// the management root pin of a self-signed console.
	service.UseControlCA(nodesshinstall.RuntimeControlCA(nativebackup.Layout{Root: "/"}.Path(nativebackup.WebRuntimeConfigFile)))
	return service, func() (http.Handler, error) {
		authenticate := func(ctx context.Context, raw string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(ctx), raw)
		}
		install, err := nodesshinstall.NewHandler(service, authenticate)
		if err != nil {
			return nil, err
		}
		terminal, err := nodesshinstall.NewTerminalHandler(service, authenticate)
		if err != nil {
			return nil, err
		}
		mux := http.NewServeMux()
		for _, pattern := range nodesshinstall.Patterns {
			mux.Handle(pattern, install)
		}
		for _, pattern := range nodesshinstall.TerminalPatterns {
			mux.Handle(pattern, terminal)
		}
		return mux, nil
	}, nil
}

// buildNodeSSHAccessDelivery wires the "only the controller may SSH"
// delivery worker over edge NATS; without it
// the wanted state is recorded but stays pending (logged once).
func buildNodeSSHAccessDelivery(service *nodesshinstall.Service, connection natsRuntimeConnection) (runtimeWorker, error) {
	edgeNATS, _ := connection.(*nats.Conn)
	if service == nil || edgeNATS == nil {
		slog.Warn("node SSH access restriction cannot be sent: edge NATS is not configured")
		return nil, nil
	}
	transport, err := nodesshinstall.NewAccessNATS(edgeNATS, 5*time.Second)
	if err != nil {
		return nil, err
	}
	delivery, err := nodesshinstall.NewAccessDelivery(nodesshinstall.AccessDeliveryConfig{Store: service, Transport: transport,
		Prober: nodesshinstall.NewDialer(nil), Interval: 15 * time.Second, Logger: slog.Default().With("component", "node_ssh_access")})
	if err != nil {
		return nil, err
	}
	service.OnAccessChange(delivery.Wake)
	return delivery, nil
}
