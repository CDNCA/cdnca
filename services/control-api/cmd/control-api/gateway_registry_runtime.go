package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/controlgrpc"
	"github.com/cdnca/cdnca/services/control-api/internal/controlinternal"
	"github.com/cdnca/cdnca/services/control-api/internal/gatewayregistry"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Gateway registry (ADR 0013 GW-06/GW-08). Enabled when the signing CA files
// are configured (install-control.sh writes them on every installation):
//
//	CDNCA_GATEWAY_CLIENT_CA_CERT_FILE / _KEY_FILE  Gateway client CA (ControlInternal trusts it)
//	CDNCA_GATEWAY_ROOT_CA_CERT_FILE / _KEY_FILE    installation root CA (Gateway server names)
//	NODE_CA_CERTIFICATE_CHAIN_FILE                 handed to bound Gateways (node client CA)
//
// CDNCA_CONTROL_INTERNAL_REMOTE_ADDR (e.g. 0.0.0.0:9446) binds the listener
// standalone Gateways reach. What a bound Gateway is told to connect to is
// CDNCA_GATEWAY_REMOTE_CONTROL_ADDRESS
// (host:port of the ControlInternal listener reachable by Gateways) with
// CDNCA_GATEWAY_REMOTE_CONTROL_SERVER_NAME, CDNCA_GATEWAY_REMOTE_REDIS_URL,
// CDNCA_GATEWAY_REMOTE_NATS_URL and CDNCA_GATEWAY_REMOTE_TELEMETRY_NATS_URL.
// Unset: the management page works and binding is refused.
//
// CDNCA_GATEWAY_LOCAL_ADDRESS / _SERVER_NAME / _ENROLLMENT_ADDRESS (written
// by install-control.sh --mode all|control from --gateway-host and the node
// channel ports) put the co-located Gateway on the node endpoint list after
// the online standalone Gateways (K1): set together or not at all.
type gatewayRegistryRuntimeConfig struct {
	clientCACert, clientCAKey string
	rootCACert, rootCAKey     string
	nodeCAFile                string
	installationID            string
	endpoints                 gatewayregistry.RemoteEndpoints
	localGateway              gatewayregistry.Entrypoint
}

func loadGatewayRegistryRuntimeConfig(lookup func(string) string, installationID, nodeCAFile string) (gatewayRegistryRuntimeConfig, bool, error) {
	c := gatewayRegistryRuntimeConfig{
		clientCACert: strings.TrimSpace(lookup("CDNCA_GATEWAY_CLIENT_CA_CERT_FILE")),
		clientCAKey:  strings.TrimSpace(lookup("CDNCA_GATEWAY_CLIENT_CA_KEY_FILE")),
		rootCACert:   strings.TrimSpace(lookup("CDNCA_GATEWAY_ROOT_CA_CERT_FILE")),
		rootCAKey:    strings.TrimSpace(lookup("CDNCA_GATEWAY_ROOT_CA_KEY_FILE")),
		nodeCAFile:   strings.TrimSpace(nodeCAFile), installationID: strings.TrimSpace(installationID),
		endpoints: gatewayregistry.RemoteEndpoints{
			ControlInternalAddress:    strings.TrimSpace(lookup("CDNCA_GATEWAY_REMOTE_CONTROL_ADDRESS")),
			ControlInternalServerName: strings.TrimSpace(lookup("CDNCA_GATEWAY_REMOTE_CONTROL_SERVER_NAME")),
			RedisURL:                  strings.TrimSpace(lookup("CDNCA_GATEWAY_REMOTE_REDIS_URL")),
			NATSURL:                   strings.TrimSpace(lookup("CDNCA_GATEWAY_REMOTE_NATS_URL")),
			TelemetryNATSURL:          strings.TrimSpace(lookup("CDNCA_GATEWAY_REMOTE_TELEMETRY_NATS_URL")),
		},
	}
	files := []string{c.clientCACert, c.clientCAKey, c.rootCACert, c.rootCAKey}
	set := 0
	for _, file := range files {
		if file != "" {
			set++
		}
	}
	if set == 0 {
		return c, false, nil
	}
	if set != len(files) || c.nodeCAFile == "" {
		return c, false, errors.New("CDNCA_GATEWAY_CLIENT_CA_* and CDNCA_GATEWAY_ROOT_CA_* must be set together with NODE_CA_CERTIFICATE_CHAIN_FILE")
	}
	if id, err := uuid.Parse(c.installationID); err != nil || id.String() != c.installationID {
		return c, false, errors.New("the Gateway registry requires a canonical CONTROL_INSTALLATION_ID")
	}
	e := c.endpoints
	remote := []string{e.ControlInternalAddress, e.ControlInternalServerName, e.RedisURL, e.NATSURL, e.TelemetryNATSURL}
	filled := 0
	for _, value := range remote {
		if value != "" {
			filled++
		}
	}
	if filled != 0 && filled != len(remote) {
		return c, false, errors.New("CDNCA_GATEWAY_REMOTE_* must be set together")
	}
	local, err := gatewayregistry.LocalGatewayEndpoint(strings.TrimSpace(lookup("CDNCA_GATEWAY_LOCAL_ADDRESS")),
		strings.TrimSpace(lookup("CDNCA_GATEWAY_LOCAL_SERVER_NAME")), strings.TrimSpace(lookup("CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS")))
	if err != nil {
		return c, false, errors.New("CDNCA_GATEWAY_LOCAL_ADDRESS, _SERVER_NAME and _ENROLLMENT_ADDRESS must be set together as host:port, host and host:port")
	}
	c.localGateway = local
	return c, true, nil
}

func buildGatewayRegistryRuntime(pool *pgxpool.Pool, installationID, nodeCAFile string) (*gatewayregistry.Service, error) {
	c, enabled, err := loadGatewayRegistryRuntimeConfig(os.Getenv, installationID, nodeCAFile)
	if err != nil || !enabled {
		return nil, err
	}
	client, err := gatewayregistry.LoadCA(c.clientCACert, c.clientCAKey)
	if err != nil {
		return nil, fmt.Errorf("load Gateway client CA: %w", err)
	}
	root, err := gatewayregistry.LoadCA(c.rootCACert, c.rootCAKey)
	if err != nil {
		return nil, fmt.Errorf("load installation root CA: %w", err)
	}
	rootPEM, err := os.ReadFile(c.rootCACert)
	if err != nil {
		return nil, err
	}
	nodePEM, err := os.ReadFile(c.nodeCAFile)
	if err != nil {
		return nil, err
	}
	return gatewayregistry.New(gatewayregistry.Config{Pool: pool, Signer: gatewayregistry.Signer{Client: client, Server: root},
		RootCAPEM: string(rootPEM), NodeCAPEM: string(nodePEM), InstallationID: c.installationID, Endpoints: c.endpoints,
		LocalGateway: c.localGateway})
}

func gatewayRegistryHandlerFactory(service *gatewayregistry.Service, identityService *identity.Service) httpapi.MountedHandlerFactory {
	if service == nil || identityService == nil {
		return nil
	}
	return func() (http.Handler, error) {
		return gatewayregistry.NewHandler(service, identityService.AuthenticateSession)
	}
}

// attachControlInternalRemote opens the ControlInternal listener for
// standalone Gateways when CDNCA_CONTROL_INTERNAL_REMOTE_ADDR is set (GW-09,
// install-control.sh --mode control / "open Gateway access"): same TLS policy,
// only bound Gateways' binding addresses (and loopback) are accepted.
// CDNCA_GATEWAY_ACCESS_FILE receives the same list for the host firewall.
func attachControlInternalRemote(ctx context.Context, server *controlgrpc.Server, registry *gatewayregistry.Service) error {
	address := strings.TrimSpace(os.Getenv("CDNCA_CONTROL_INTERNAL_REMOTE_ADDR"))
	if address == "" {
		return nil
	}
	if registry == nil {
		return errors.New("CDNCA_CONTROL_INTERNAL_REMOTE_ADDR requires the Gateway registry (CDNCA_GATEWAY_*_CA_* files)")
	}
	allowed := withGatewayAccessFile(registry.AllowedSourceIPs, strings.TrimSpace(os.Getenv("CDNCA_GATEWAY_ACCESS_FILE")))
	return server.AttachRemote(ctx, controlgrpc.RemoteConfig{ListenAddress: address, AllowedSources: allowed})
}

// controlInternalGateways adapts the registry to ControlInternal (nil-safe).
type controlInternalGateways struct{ service *gatewayregistry.Service }

func (g controlInternalGateways) AuthorizeGateway(ctx context.Context, id uuid.UUID, serial string, digest [32]byte) (bool, error) {
	return g.service.AuthorizeGateway(ctx, id, serial, digest)
}

func (g controlInternalGateways) MarkReady(ctx context.Context, id uuid.UUID, version string) error {
	return g.service.MarkReady(ctx, id, version)
}

func (g controlInternalGateways) Renew(ctx context.Context, id uuid.UUID, kind string, csr []byte) (controlinternal.GatewayCertificate, error) {
	renewed, err := g.service.Renew(ctx, id, kind, csr)
	return controlinternal.GatewayCertificate{PEM: renewed.CertificatePEM, NotAfter: renewed.NotAfter, RenewAt: renewed.RenewAt}, err
}

func (g controlInternalGateways) Settings(ctx context.Context) (controlinternal.GatewaySettings, error) {
	published, err := g.service.Publish(ctx)
	if err != nil {
		return controlinternal.GatewaySettings{}, err
	}
	result := controlinternal.GatewaySettings{EndpointsVersion: published.EndpointsVersion}
	for _, item := range published.TrustedProxies {
		result.TrustedProxies = append(result.TrustedProxies, controlinternal.GatewayTrustedProxy{CIDR: item.CIDR, Header: item.Header})
	}
	for _, item := range published.Endpoints {
		result.Endpoints = append(result.Endpoints, controlinternal.GatewayEndpoint{Address: item.Address, ServerName: item.ServerName,
			Transport: item.Transport, TunnelHost: item.TunnelHost, EnrollmentAddress: item.EnrollmentAddress})
	}
	return result, nil
}

func controlInternalGatewayRegistry(service *gatewayregistry.Service) controlinternal.GatewayRegistry {
	if service == nil {
		return nil
	}
	return controlInternalGateways{service: service}
}
