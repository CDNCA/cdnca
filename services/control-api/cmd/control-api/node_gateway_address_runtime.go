package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodegatewayaddr"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// buildNodeGatewayAddressRuntime wires 维护升级 → 节点设置「更换主控连接地址」
// (fix-nodegw): the admin API always mounts (reads work everywhere); writes
// need the edge publication signer and edge NATS (else
// gateway_address_unavailable) and an MFA step-up (else step_up_required).
func buildNodeGatewayAddressRuntime(pool *pgxpool.Pool, identityService *identity.Service, signer *edgePublishArtifactSigner,
	connection natsRuntimeConnection, stepUp nodegatewayaddr.StepUpConsumer) (runtimeWorker, httpapi.MountedHandlerFactory, error) {
	if !configuredRuntimePool(pool) || identityService == nil {
		return nil, nil, nil
	}
	store := nodegatewayaddr.NewStore(pool, time.Now)
	handler := &nodegatewayaddr.Handler{Store: store, Authenticate: identityService.AuthenticateSession,
		Ready: func() bool { return false }}
	if stepUp != nil {
		handler.StepUp = nodegatewayaddr.PlatformStepUp{Pool: pool, Consumer: stepUp}
	}
	var worker runtimeWorker
	edgeNATS, _ := connection.(*nats.Conn)
	if signer != nil && edgeNATS != nil {
		transport, err := nodegatewayaddr.NewNATS(edgeNATS, 5*time.Second)
		if err != nil {
			return nil, nil, err
		}
		distributor, err := nodegatewayaddr.NewDistributor(nodegatewayaddr.DistributorConfig{Store: store, Transport: transport,
			KeyID: signer.KeyID(), Sign: signer.Sign, Interval: 30 * time.Second, Logger: slog.Default()})
		if err != nil {
			return nil, nil, err
		}
		handler.Ready = func() bool { return true }
		handler.OnChange = distributor.Wake
		worker = distributor
	} else {
		slog.Warn("node gateway address changes cannot be sent: the edge publication signer or edge NATS is not configured")
	}
	return worker, func() (http.Handler, error) { return handler, nil }, nil
}
