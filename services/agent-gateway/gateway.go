package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxCSRBytes = 64 << 10

const terminalCommandReceiptVersion = 1

const terminalCommandReceiptConfirmationVersion = 1

const terminalCommandReceiptConfirmationWireVersion = 1

const terminalCommandReceiptConfirmationIndexVersion = 1

const edgeUpgradeStatusPubAckAPIVersion uint32 = 1

const edgeUpgradeStatusAckReceiptAPIVersion uint32 = 1

const firewallControlAPIVersion uint32 = 1

type terminalCommandReceiptStore interface {
	loadTerminalCommandReceipt(context.Context, string, deploymentKey) (*terminalCommandReceipt, error)
	saveTerminalCommandReceipt(context.Context, *terminalCommandReceipt) (*terminalCommandReceipt, error)
	deleteTerminalCommandReceipt(context.Context, *terminalCommandReceipt) error
	loadTerminalCommandReceiptConfirmation(context.Context, string, deploymentKey) (*terminalCommandReceiptConfirmation, error)
	listTerminalCommandReceiptConfirmations(context.Context, string, int) ([]*terminalCommandReceiptConfirmation, error)
	saveTerminalCommandReceiptConfirmation(context.Context, *terminalCommandReceiptConfirmation) (*terminalCommandReceiptConfirmation, error)
	deleteTerminalCommandReceiptConfirmation(context.Context, *terminalCommandReceiptConfirmation) error
}

type terminalCommandDeliveryReceipt interface {
	terminalCommandDeliveryIdentity() (string, error)
}

type terminalCommandReceipt struct {
	Version            int    `json:"version"`
	NodeID             string `json:"node_id"`
	DeploymentID       string `json:"deployment_id"`
	Attempt            uint32 `json:"attempt"`
	ConfigVersionID    string `json:"config_version_id"`
	CommandEventID     string `json:"command_event_id"`
	StatusEventID      string `json:"status_event_id"`
	TransitionSequence uint64 `json:"transition_sequence"`
	CommandSHA256      string `json:"command_sha256"`
	StatusSHA256       string `json:"status_sha256"`
	ArtifactSetSHA256  string `json:"artifact_set_sha256"`
	CommandDeliveryID  string `json:"command_delivery_id"`
	PublishedStream    string `json:"published_stream,omitempty"`
	PublishedSequence  uint64 `json:"published_sequence,omitempty"`
	PersistedUnixNano  int64  `json:"persisted_unix_nano"`
}

type terminalCommandReceiptConfirmation struct {
	Version                  int                    `json:"version"`
	Receipt                  terminalCommandReceipt `json:"receipt"`
	SessionEpoch             uint64                 `json:"session_epoch"`
	ReceiptStreamSequence    uint64                 `json:"receipt_stream_sequence"`
	AgentReceiptPersisted    bool                   `json:"agent_receipt_persisted,omitempty"`
	HeartbeatBarrierSequence uint64                 `json:"heartbeat_barrier_sequence,omitempty"`
	HeartbeatBarrierEventID  string                 `json:"heartbeat_barrier_event_id,omitempty"`
}

type terminalCommandReceiptConfirmationWire struct {
	Version          int                                `json:"version"`
	Confirmation     terminalCommandReceiptConfirmation `json:"confirmation"`
	PreviousSequence uint64                             `json:"previous_sequence,omitempty"`
}

type terminalCommandReceiptConfirmationIndexEntry struct {
	DeploymentID    string `json:"deployment_id"`
	Attempt         uint32 `json:"attempt"`
	ConfigVersionID string `json:"config_version_id"`
}

func (e terminalCommandReceiptConfirmationIndexEntry) deploymentKey() deploymentKey {
	return deploymentKey{deploymentID: e.DeploymentID, attempt: e.Attempt, configVersion: e.ConfigVersionID}
}

type terminalCommandReceiptConfirmationIndex struct {
	Version          int                                            `json:"version"`
	NodeID           string                                         `json:"node_id"`
	Entries          []terminalCommandReceiptConfirmationIndexEntry `json:"entries"`
	PreviousSequence uint64                                         `json:"previous_sequence,omitempty"`
}

func (c *terminalCommandReceiptConfirmation) deploymentKey() deploymentKey {
	if c == nil {
		return deploymentKey{}
	}
	return c.Receipt.deploymentKey()
}

func (r *terminalCommandReceipt) deploymentKey() deploymentKey {
	if r == nil {
		return deploymentKey{}
	}
	return deploymentKey{deploymentID: r.DeploymentID, attempt: r.Attempt, configVersion: r.ConfigVersionID}
}

type Gateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	config           Config
	control          ControlPlane
	sessions         SessionCoordinator
	commands         CommandBus
	firewall         FirewallCommandBus
	drain            DrainCommandBus
	nodeMonitoring   NodeMonitoringBus
	signerTrust      SignerTrustBus
	installationBan  InstallationBanBus
	securityBans     SecurityBanBus
	siteDrops        SiteDropBus
	gatewayAddresses GatewayAddressBus
	sched302         Sched302Bus
	autoDefense      AutoDefenseBus
	marketProbes     MarketProbeBus
	l4Live           L4LiveBus
	portTransitions  PortTransitionCommandBus
	portManager      *PortTransitionManager
	receipts         terminalCommandReceiptStore
	overlays         OverlayCommandBus
	cache            CacheCommandBus
	upgrades         UpgradeCommandBus
	upgradeReceipts  upgradeStatusAckStore
	revocation       *RevocationCheckpointCache
	heartbeats       HeartbeatSink
	telemetry        *telemetryService
	endpoints        *NodeEndpoints
	disableState     *GatewayDrain
	now              func() time.Time
}

func New(config Config, control ControlPlane, sessions SessionCoordinator) (*Gateway, error) {
	return newGateway(config, control, sessions, nil, nil)
}

func NewWithCommandBus(config Config, control ControlPlane, sessions SessionCoordinator, commands CommandBus) (*Gateway, error) {
	if commands == nil {
		return nil, fmt.Errorf("command bus is required")
	}
	return newGateway(config, control, sessions, commands, nil)
}

func NewWithDurableMessaging(
	config Config,
	control ControlPlane,
	sessions SessionCoordinator,
	commands CommandBus,
	heartbeats HeartbeatSink,
) (*Gateway, error) {
	if commands == nil || heartbeats == nil {
		return nil, fmt.Errorf("command bus and heartbeat sink are required")
	}
	return newGateway(config, control, sessions, commands, heartbeats)
}

func NewWithOverlayMessaging(
	config Config,
	control ControlPlane,
	sessions SessionCoordinator,
	commands CommandBus,
	overlays OverlayCommandBus,
	heartbeats HeartbeatSink,
) (*Gateway, error) {
	if overlays == nil {
		return nil, fmt.Errorf("overlay command bus is required")
	}
	gateway, err := NewWithDurableMessaging(config, control, sessions, commands, heartbeats)
	if err != nil {
		return nil, err
	}
	gateway.overlays = overlays
	return gateway, nil
}

func NewWithCacheMessaging(
	config Config,
	control ControlPlane,
	sessions SessionCoordinator,
	commands CommandBus,
	cache CacheCommandBus,
	heartbeats HeartbeatSink,
) (*Gateway, error) {
	if cache == nil {
		return nil, fmt.Errorf("cache command bus is required")
	}
	gateway, err := NewWithDurableMessaging(config, control, sessions, commands, heartbeats)
	if err != nil {
		return nil, err
	}
	gateway.cache = cache
	return gateway, nil
}

func newGateway(config Config, control ControlPlane, sessions SessionCoordinator, commands CommandBus, heartbeats HeartbeatSink) (*Gateway, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if control == nil || sessions == nil {
		return nil, fmt.Errorf("control plane and session coordinator are required")
	}
	gateway := &Gateway{
		config: config, control: control, sessions: sessions, commands: commands,
		heartbeats: heartbeats, now: time.Now,
	}
	if receipts, ok := commands.(terminalCommandReceiptStore); ok {
		gateway.receipts = receipts
	}
	if firewall, ok := commands.(FirewallCommandBus); ok {
		gateway.firewall = firewall
	}
	if drain, ok := commands.(DrainCommandBus); ok {
		gateway.drain = drain
	}
	return gateway, nil
}

func (g *Gateway) ConfigureNodeMonitoring(bus NodeMonitoringBus) error {
	if g == nil || bus == nil || g.nodeMonitoring != nil {
		return fmt.Errorf("node monitoring bus is invalid or already configured")
	}
	g.nodeMonitoring = bus
	return nil
}

func (g *Gateway) ConfigurePortTransitions(bus PortTransitionCommandBus, manager *PortTransitionManager) error {
	if g == nil || bus == nil || manager == nil || g.portTransitions != nil || g.portManager != nil {
		return fmt.Errorf("gateway port transition dependencies are invalid or already configured")
	}
	g.portTransitions = bus
	g.portManager = manager
	return nil
}

// ConfigureRevocationCheckpointCache installs the signed certificate
// revocation facts used to gate commands on established sessions. A revoked
// session stays connected for heartbeats and status, but receives no new
// deployment command.
func (g *Gateway) ConfigureRevocationCheckpointCache(cache *RevocationCheckpointCache) error {
	if g == nil || cache == nil {
		return fmt.Errorf("revocation checkpoint cache is required")
	}
	if g.revocation != nil {
		return fmt.Errorf("revocation checkpoint cache is already configured")
	}
	g.revocation = cache
	return nil
}

func (g *Gateway) Enroll(ctx context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	if disabled, _ := g.disableState.Disabled(); disabled {
		return nil, status.Error(codes.Unavailable, "gateway is disabled; enroll through another gateway")
	}
	if err := g.validateEnrollment(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	authorizeCtx, cancel := context.WithTimeout(ctx, g.config.ControlDecisionTimeout)
	authorization, err := g.control.AuthorizeEnrollment(authorizeCtx, &controlv1.AuthorizeEnrollmentRequest{
		Request:                      request.Request,
		EnrollmentToken:              request.EnrollmentToken,
		CertificateSigningRequestDer: request.CertificateSigningRequestDer,
		MachineFingerprintSha256:     request.MachineFingerprintSha256,
		SupportedProtocolVersions:    request.SupportedProtocolVersions,
		Capabilities:                 enrollmentCapabilities(request.Capabilities),
		GatewayInstanceId:            g.config.GatewayInstanceID,
		PeerIp:                       peerIP(ctx),
		ArtifactEncryptionPublicKey:  request.ArtifactEncryptionPublicKey,
	})
	cancel()
	if err != nil {
		return nil, rpcError(err)
	}
	if authorization == nil || authorization.AuthorizationId == "" || authorization.NodeId == "" || authorization.SelectedProtocolVersion == nil {
		return nil, status.Error(codes.Internal, "control plane returned an incomplete enrollment authorization")
	}
	if _, ok := negotiateVersion(
		&commonv1.ProtocolVersionRange{Minimum: authorization.SelectedProtocolVersion, Maximum: authorization.SelectedProtocolVersion},
		request.SupportedProtocolVersions,
		g.config.SupportedVersions,
	); !ok {
		return nil, status.Error(codes.Internal, "control plane selected an unsupported protocol version")
	}
	completeCtx, cancel := context.WithTimeout(ctx, g.config.ControlDecisionTimeout)
	completed, err := g.control.CompleteEnrollment(completeCtx, &controlv1.CompleteEnrollmentRequest{
		Request:           request.Request,
		AuthorizationId:   authorization.AuthorizationId,
		GatewayInstanceId: g.config.GatewayInstanceID,
	})
	cancel()
	if err != nil {
		return nil, rpcError(err)
	}
	if completed == nil || completed.Certificate == nil || completed.NodeId != authorization.NodeId || completed.ArtifactEncryptionKeyId != authorization.ArtifactEncryptionKeyId {
		return nil, status.Error(codes.Internal, "control plane returned an inconsistent enrollment result")
	}
	return &agentv1.EnrollResponse{
		NodeId:                  completed.NodeId,
		SelectedProtocolVersion: authorization.SelectedProtocolVersion,
		Certificate:             completed.Certificate,
		ArtifactEncryptionKeyId: completed.ArtifactEncryptionKeyId,
	}, nil
}

func (g *Gateway) RenewCertificate(ctx context.Context, request *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
	identity, err := authenticatedNode(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || g.validateRequestMetadata(request.Request) != nil || len(request.CertificateSigningRequestDer) == 0 || len(request.CertificateSigningRequestDer) > maxCSRBytes {
		return nil, status.Error(codes.InvalidArgument, "invalid certificate renewal request")
	}
	if request.CurrentSerialNumber == "" || request.CurrentSerialNumber != identity.SerialNumber {
		return nil, status.Error(codes.FailedPrecondition, "current certificate serial does not match the authenticated certificate")
	}
	decisionCtx, cancel := context.WithTimeout(ctx, g.config.ControlDecisionTimeout)
	response, err := g.control.RenewNodeCertificate(decisionCtx, &controlv1.RenewNodeCertificateRequest{
		Request:                      request.Request,
		NodeId:                       identity.NodeID,
		CurrentSerialNumber:          request.CurrentSerialNumber,
		CurrentCertificateSha256:     identity.CertificateSHA256[:],
		CertificateSigningRequestDer: request.CertificateSigningRequestDer,
		GatewayInstanceId:            g.config.GatewayInstanceID,
	})
	cancel()
	if err != nil {
		return nil, rpcError(err)
	}
	if response == nil || response.Certificate == nil {
		return nil, status.Error(codes.Internal, "control plane returned an incomplete certificate")
	}
	return &agentv1.RenewCertificateResponse{Certificate: response.Certificate}, nil
}

// RecoverCertificate forwards a node's signed expired-certificate recovery
// (ADR 0013 GW-02). It is served on the enrollment listener: the node holds no
// valid client certificate, so the control plane verifies the request
// signature itself; the Gateway checks only shape and adds what it observed.
func (g *Gateway) RecoverCertificate(ctx context.Context, request *agentv1.RecoverCertificateRequest) (*agentv1.RecoverCertificateResponse, error) {
	recoverer, ok := g.control.(CertificateRecoveryControlPlane)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "certificate recovery is not available")
	}
	if request == nil || g.validateRequestMetadata(request.Request) != nil || request.Request.SentTime == nil ||
		request.Request.SentTime.CheckValid() != nil || g.validateUUID("node_id", request.NodeId) != nil ||
		len(request.ExpiredCertificateDer) == 0 || len(request.ExpiredCertificateDer) > maxCSRBytes ||
		len(request.CertificateSigningRequestDer) == 0 || len(request.CertificateSigningRequestDer) > maxCSRBytes ||
		len(request.Nonce) != 32 || len(request.Signature) != 64 {
		return nil, status.Error(codes.InvalidArgument, "invalid certificate recovery request")
	}
	decisionCtx, cancel := context.WithTimeout(ctx, g.config.ControlDecisionTimeout)
	response, err := recoverer.RecoverNodeCertificate(decisionCtx, &controlv1.RecoverNodeCertificateRequest{
		Recovery: request, GatewayInstanceId: g.config.GatewayInstanceID, PeerIp: peerIP(ctx),
	})
	cancel()
	if err != nil {
		return nil, rpcError(err)
	}
	if response == nil || response.Certificate == nil {
		return nil, status.Error(codes.Internal, "control plane returned an incomplete certificate")
	}
	return &agentv1.RecoverCertificateResponse{Certificate: response.Certificate}, nil
}

func (g *Gateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	identity, err := authenticatedNode(stream.Context())
	if err != nil {
		return err
	}
	// A disabled Gateway takes no node: the node moves to its next endpoint.
	if disabled, _ := g.disableState.Disabled(); disabled {
		return status.Error(codes.Unavailable, "gateway is disabled; connect to another gateway endpoint")
	}
	receive, _ := pumpConnectRequests(stream)
	first, err := receiveWithTimeout(stream.Context(), receive, g.config.HandshakeTimeout)
	if err != nil {
		return err
	}
	if first.request == nil || first.request.GetHello() == nil {
		return status.Error(codes.FailedPrecondition, "AgentHello must be the first stream payload")
	}
	if err := g.validateStreamMetadata(first.request.Stream); err != nil || first.request.Stream.Sequence != 1 {
		return status.Error(codes.InvalidArgument, "first stream metadata is invalid")
	}
	hello := first.request.GetHello()
	if hello.NodeId != identity.NodeID {
		return status.Error(codes.Unauthenticated, "AgentHello node identity does not match the client certificate")
	}
	if err := g.validateHello(hello); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	activeIdentityCapable, _ := activeConfigIdentityCapabilityFromFeatures(hello.Capabilities.Features)
	ackReceiptCapable, _ := deploymentStatusAckReceiptCapabilityFromFeatures(hello.Capabilities.Features)
	upgradeCapable := hasEdgeUpgradeCapability(hello.Capabilities)
	upgradeStatusPubAckCapable, _ := edgeUpgradeStatusPubAckCapabilityFromFeatures(hello.Capabilities.Features)
	upgradeStatusAckReceiptCapable, _ := edgeUpgradeStatusAckReceiptCapabilityFromFeatures(hello.Capabilities.Features)
	firewallCapable, _ := firewallControlCapabilityFromFeatures(hello.Capabilities.Features)
	drainCapable, _ := drainControlCapabilityFromFeatures(hello.Capabilities.Features)
	nodeMonitoringCapable, _ := nodeMonitoringCapabilityFromFeatures(hello.Capabilities.Features)
	portTransitionCapable, _ := gatewayPortTransitionCapabilityFromFeatures(hello.Capabilities.Features)
	signerTrustCapable, _ := signerTrustCapabilityFromFeatures(hello.Capabilities.Features)
	installationBanCapable, _ := installationBanCapabilityFromFeatures(hello.Capabilities.Features)
	securityBansEnabled := securityBanCapableFromFeatures(hello.Capabilities.Features) && g.securityBans != nil
	sched302Capable := sched302CapabilityFromFeatures(hello.Capabilities.Features)
	autoDefenseCapable, _ := autoDefenseCapabilityFromFeatures(hello.Capabilities.Features)
	siteDropCapable, _ := siteDropCapabilityFromFeatures(hello.Capabilities.Features)
	gatewayAddressCapable, _ := gatewayAddressCapabilityFromFeatures(hello.Capabilities.Features)
	cacheCancelCapable, _ := cacheControlCancelCapabilityFromFeatures(hello.Capabilities.Features)
	marketProbeVersion, _ := marketProbeCapabilityFromFeatures(hello.Capabilities.Features)
	l4LiveVersion, _ := l4LiveCapabilityFromFeatures(hello.Capabilities.Features)
	multiTenantCapable, _ := multiTenantRuntimeCapabilityFromFeatures(hello.Capabilities.Features)
	replay := newMessageReplayWindow(g.config.MessageIDReplayWindow)
	if _, err := replay.accept(first.request, 0); err != nil {
		return status.Error(codes.InvalidArgument, "first stream message could not be recorded")
	}
	authorization, err := g.authorizeConnection(stream.Context(), identity, nil)
	if err != nil {
		return err
	}
	if proof := hello.GatewayPortTransitionProof; proof != nil {
		if !portTransitionCapable || g.portManager == nil || validatePortTransitionProof(proof) != nil {
			return status.Error(codes.FailedPrecondition, "gateway port transition proof is not authorized")
		}
		if err := g.portManager.RecordConnection(proof.TransitionId, proof.Revision, identity.NodeID, certificateIdentityHex(identity)); err != nil {
			return status.Error(codes.FailedPrecondition, "gateway port transition proof conflicts with the authenticated node")
		}
	}
	selected, ok := negotiateVersion(hello.SupportedProtocolVersions, g.config.SupportedVersions, authorization.AcceptedProtocolVersions)
	if !ok {
		errorContext, cancel := context.WithTimeout(stream.Context(), g.config.HandshakeTimeout)
		_ = sendConnectResponse(errorContext, stream, g.protocolErrorResponse(1, commonv1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION, "no mutually supported protocol version"))
		cancel()
		return status.Error(codes.FailedPrecondition, "no mutually supported protocol version")
	}
	if hello.ArtifactEncryptionKeyId != authorization.ArtifactEncryptionKeyId {
		return status.Error(codes.FailedPrecondition, "artifact encryption key does not match node authorization")
	}
	lease, err := g.sessions.Acquire(stream.Context(), identity.NodeID)
	if err != nil {
		return status.Error(codes.Unavailable, "could not acquire the node session")
	}
	defer lease.Release()
	factsConfirmed := false
	// Facts are reported with deployments paused too: capability-gated pushes
	// that ignore the pause (EDGE_SIGNER_TRUST) read the node's latest facts.
	// Upgrade commands still require DeploymentsAllowed below.
	if facts := newGatewaySessionFacts(identity, lease.Epoch(), selected, hello); facts != nil {
		authorization, factsConfirmed, err = g.confirmSessionFacts(stream.Context(), identity, lease, facts, authorization)
		if err != nil {
			return err
		}
	}
	enabledCapabilities := make([]*agentv1.Capability, 0, 6)
	if activeIdentityCapable {
		enabledCapabilities = append(enabledCapabilities, activeConfigIdentityCapability())
	}
	if activeIdentityCapable && ackReceiptCapable && g.receipts != nil {
		enabledCapabilities = append(enabledCapabilities, deploymentStatusAckReceiptCapability())
	}
	multiTenantEnabled := activeIdentityCapable && multiTenantCapable
	if multiTenantEnabled {
		enabledCapabilities = append(enabledCapabilities, multiTenantRuntimeCapability())
	}
	upgradeEnabled := upgradeCapable && factsConfirmed && g.upgrades != nil && authorization.DeploymentsAllowed
	upgradeStatusPubAckEnabled := false
	upgradeStatusAckReceiptEnabled := false
	upgradeInstallationID := ""
	if upgradeEnabled {
		if !canonicalUpgradeUUID(authorization.InstallationId) {
			return status.Error(codes.Internal, "control plane returned an invalid upgrade installation authorization")
		}
		upgradeInstallationID = authorization.InstallationId
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1,
		})
		if upgradeStatusPubAckCapable {
			upgradeStatusPubAckEnabled = true
			enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
				Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK, ApiVersion: edgeUpgradeStatusPubAckAPIVersion,
			})
			if upgradeStatusAckReceiptCapable && g.upgradeReceipts != nil {
				upgradeStatusAckReceiptEnabled = true
				enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
					Name:       agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT,
					ApiVersion: edgeUpgradeStatusAckReceiptAPIVersion,
				})
			}
		}
	}
	if firewallCapable && g.firewall != nil && authorization.DeploymentsAllowed {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL, ApiVersion: firewallControlAPIVersion,
		})
	}
	if drainCapable && g.drain != nil && authorization.DeploymentsAllowed {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL, ApiVersion: drainControlAPIVersion,
		})
	}
	if nodeMonitoringCapable && g.nodeMonitoring != nil {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING, ApiVersion: nodeMonitoringAPIVersion,
		})
	}
	portTransitionEnabled := portTransitionCapable && g.portTransitions != nil && g.portManager != nil && authorization.DeploymentsAllowed
	if portTransitionEnabled {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_PORT_TRANSITION, ApiVersion: gatewayPortTransitionAPIVersion,
		})
	}
	signerTrustEnabled := signerTrustCapable && g.signerTrust != nil
	if signerTrustEnabled {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST, ApiVersion: signerTrustAPIVersion,
		})
	}
	// Installation ban commands follow no deployment gate (installation_ban.go).
	installationBanEnabled := installationBanCapable && g.installationBan != nil
	if installationBanEnabled {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_INSTALLATION_BAN_TICKET, ApiVersion: installationBanAPIVersion,
		})
	}
	// Tables follow deployments: a node whose deployments are paused serves
	// no new configuration and keeps redirecting only until its hold ends.
	sched302Enabled := sched302Capable && g.sched302 != nil && authorization.DeploymentsAllowed
	if sched302Enabled {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_SCHED302, ApiVersion: sched302.APIVersion,
		})
	}
	// Auto defense follows no deployment gate: a paused node must still receive
	// "site off" and withdrawn signatures (autodefense.go).
	autoDefenseEnabled := autoDefenseCapable && g.autoDefense != nil
	if autoDefenseEnabled {
		enabledCapabilities = append(enabledCapabilities, autoDefenseCapability())
	}
	// Site drop follows no deployment gate: a paused node must still stop
	// serving a level D site and see it released (site_drop.go).
	siteDropEnabled := siteDropCapable && g.siteDrops != nil
	if siteDropEnabled {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP, ApiVersion: siteDropAPIVersion,
		})
	}
	// fix-nodegw: address changes follow no deployment gate (a paused node
	// must still be able to move to a new Gateway address).
	if gatewayAddressCapable && g.gatewayAddresses != nil {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE, ApiVersion: gatewayAddressAPIVersion,
		})
	}
	// CACHE-ADD-07: cache cancels ride the cache command subject, so they
	// need cache control and the cache bus.
	cacheCancelEnabled := cacheCancelCapable && g.cache != nil && hasCacheControlCapability(hello.Capabilities)
	if cacheCancelEnabled {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL, ApiVersion: cacheControlCancelAPIVersion,
		})
	}
	marketProbeEnabled := marketProbeVersion != 0 && g.marketProbes != nil
	if marketProbeEnabled {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: marketProbeVersion,
		})
	}
	if g.l4Live == nil {
		l4LiveVersion = 0
	}
	if l4LiveVersion != 0 {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS, ApiVersion: l4LiveVersion,
		})
	}
	endpointMigrationEnabled := g.disableState != nil && endpointMigrationCapable(hello.Capabilities.Features)
	if endpointMigrationEnabled {
		enabledCapabilities = append(enabledCapabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ENDPOINT_MIGRATION, ApiVersion: endpointMigrationAPIVersion,
		})
	}
	nodeEndpoints, nodeEndpointsVersion := g.endpoints.Snapshot()
	err = sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
		Stream: responseStreamMetadata(1, g.now()),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion:   selected,
			GatewayVersion:            g.config.GatewayVersion,
			SessionId:                 lease.ID(),
			SessionEpoch:              lease.Epoch(),
			ServerTime:                timestamppb.New(g.now()),
			HeartbeatIntervalDuration: durationpb.New(g.config.HeartbeatInterval),
			OfflineAfterDuration:      durationpb.New(g.config.OfflineAfter),
			MaximumArtifactChunkBytes: uint32(g.config.MaxArtifactChunkBytes),
			EnabledCapabilities:       enabledCapabilities,
			MessageIdReplayWindow:     uint32(g.config.MessageIDReplayWindow),
			KnownCapabilities:         knownCapabilities(),
			ObservedPeerIp:            observedPeerIP(stream.Context()),
			GatewayEndpoints:          nodeEndpoints,
			GatewayEndpointsVersion:   nodeEndpointsVersion,
			NodeOwnerScopeId:          authorization.GetNodeScopeId(),
		}},
	})
	if err != nil {
		return err
	}
	return g.serveSessionWithInstallation(stream, receive, lease, replay, first.request.Stream.Sequence, identity, hello.Capabilities.AgentVersion, hello.SupportedProtocolVersions, selected, hello.ArtifactEncryptionKeyId, upgradeInstallationID, authorization.SnapshotExpirationTime.AsTime(), authorization.DeploymentsAllowed, hasACMEHTTP01OverlayCapability(hello.Capabilities), hasCacheControlCapability(hello.Capabilities), activeIdentityCapable, activeIdentityCapable && ackReceiptCapable && g.receipts != nil, upgradeEnabled, upgradeStatusPubAckEnabled, upgradeStatusAckReceiptEnabled, firewallCapable, drainCapable, nodeMonitoringCapable, portTransitionEnabled, marketProbeEnabled, multiTenantEnabled, l4LiveVersion >= 1, l4LiveVersion >= 2, signerTrustEnabled, sched302Enabled, autoDefenseEnabled, securityBansEnabled, installationBanEnabled, endpointMigrationEnabled, siteDropEnabled, cacheCancelEnabled, gatewayAddressCapable)
}

// knownCapabilities lists every capability name this build understands
// (GatewayHello.known_capabilities).
func knownCapabilities() []agentv1.CapabilityName {
	out := make([]agentv1.CapabilityName, 0, len(agentv1.CapabilityName_name))
	for value := range agentv1.CapabilityName_name {
		if value > 0 {
			out = append(out, agentv1.CapabilityName(value))
		}
	}
	slices.Sort(out)
	return out
}

func (g *Gateway) FetchArtifact(request *agentv1.FetchArtifactRequest, stream grpc.ServerStreamingServer[agentv1.FetchArtifactResponse]) error {
	identity, err := authenticatedNode(stream.Context())
	if err != nil {
		return err
	}
	if err := g.validateArtifactRequest(request); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	authorization, err := g.authorizeConnection(stream.Context(), identity, nil)
	if err != nil {
		return err
	}
	// Without deployments only a CLEANUP_ONLY ACME HTTP-01 overlay may be
	// fetched (ADR-0003); Control decides which artifact that is.
	decisionCtx, cancel := context.WithTimeout(stream.Context(), g.config.ArtifactTransferTimeout)
	artifacts, err := g.control.FetchArtifact(decisionCtx, &controlv1.FetchArtifactRequest{
		Request:           request.Request,
		EventId:           request.EventId,
		NodeId:            identity.NodeID,
		DeploymentId:      request.DeploymentId,
		Attempt:           request.Attempt,
		ArtifactId:        request.ArtifactId,
		Offset:            request.Offset,
		GatewayInstanceId: g.config.GatewayInstanceID,
		CleanupOnly:       !authorization.DeploymentsAllowed,
	})
	if err != nil {
		cancel()
		return rpcError(err)
	}
	defer cancel()
	for {
		response, err := receiveArtifact(decisionCtx, artifacts)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return rpcError(err)
		}
		if response == nil || response.Chunk == nil || response.Chunk.ArtifactId != request.ArtifactId || len(response.Chunk.Data) > g.config.MaxArtifactChunkBytes {
			return status.Error(codes.Internal, "control plane returned an invalid artifact chunk")
		}
		if err := sendArtifact(decisionCtx, stream, &agentv1.FetchArtifactResponse{Chunk: response.Chunk}); err != nil {
			return rpcError(err)
		}
	}
}

// FetchSiteObjects forwards a node's site object request (ADR 0009 §8.3)
// to the control plane, which authorizes the deployment and every digest,
// and streams the object chunks back unchanged after checking that they are
// the requested objects, whole and in request order.
func (g *Gateway) FetchSiteObjects(request *agentv1.FetchSiteObjectsRequest, stream grpc.ServerStreamingServer[agentv1.FetchSiteObjectsResponse]) error {
	identity, err := authenticatedNode(stream.Context())
	if err != nil {
		return err
	}
	if err := g.validateSiteObjectsRequest(request); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	control, ok := g.control.(SiteObjectControlPlane)
	if !ok {
		return status.Error(codes.Unimplemented, "site objects are unavailable")
	}
	authorization, err := g.authorizeConnection(stream.Context(), identity, nil)
	if err != nil {
		return err
	}
	if !authorization.DeploymentsAllowed {
		return status.Error(codes.PermissionDenied, "node deployments are not authorized")
	}
	decisionCtx, cancel := context.WithTimeout(stream.Context(), g.config.ArtifactTransferTimeout)
	defer cancel()
	objects, err := control.FetchSiteObjects(decisionCtx, &controlv1.FetchSiteObjectsRequest{
		Request: request.Request, EventId: request.EventId, NodeId: identity.NodeID,
		DeploymentId: request.DeploymentId, Attempt: request.Attempt, RootSha256: request.RootSha256,
		Sha256: slices.Clone(request.Sha256), GatewayInstanceId: g.config.GatewayInstanceID,
	})
	if err != nil {
		return rpcError(err)
	}
	next, offset := 0, uint64(0)
	for {
		response, err := receiveSiteObjects(decisionCtx, objects)
		if errors.Is(err, io.EOF) {
			if next != len(request.Sha256) {
				return status.Error(codes.Internal, "control plane ended the site object stream early")
			}
			return nil
		}
		if err != nil {
			return rpcError(err)
		}
		chunk := response.GetChunk()
		if chunk == nil || next >= len(request.Sha256) || chunk.RequestId != request.Request.RequestId ||
			chunk.Sha256 != request.Sha256[next] || chunk.Offset != offset || len(chunk.Data) == 0 ||
			len(chunk.Data) > g.config.MaxArtifactChunkBytes || chunk.Offset+uint64(len(chunk.Data)) > chunk.TotalSizeBytes ||
			chunk.EndOfObject != (chunk.Offset+uint64(len(chunk.Data)) == chunk.TotalSizeBytes) {
			return status.Error(codes.Internal, "control plane returned an invalid site object chunk")
		}
		offset += uint64(len(chunk.Data))
		if chunk.EndOfObject {
			next, offset = next+1, 0
		}
		if err := sendSiteObjects(decisionCtx, stream, &agentv1.FetchSiteObjectsResponse{Chunk: chunk}); err != nil {
			return rpcError(err)
		}
	}
}

func (g *Gateway) validateSiteObjectsRequest(request *agentv1.FetchSiteObjectsRequest) error {
	if request == nil {
		return fmt.Errorf("site object request is required")
	}
	if err := g.validateRequestMetadata(request.Request); err != nil {
		return err
	}
	if err := g.validateUUID("event_id", request.EventId); err != nil {
		return err
	}
	if err := g.validateUUID("deployment_id", request.DeploymentId); err != nil {
		return err
	}
	if request.Attempt == 0 {
		return fmt.Errorf("attempt must be positive")
	}
	if !lowerHexDigest(request.RootSha256) || len(request.Sha256) == 0 || len(request.Sha256) > maxSiteObjectsPerRequest {
		return fmt.Errorf("site object digests are invalid")
	}
	seen := make(map[string]struct{}, len(request.Sha256))
	for _, digest := range request.Sha256 {
		if _, duplicate := seen[digest]; duplicate || !lowerHexDigest(digest) {
			return fmt.Errorf("site object digests are invalid")
		}
		seen[digest] = struct{}{}
	}
	return nil
}

// maxSiteObjectsPerRequest is agent.v1.FetchSiteObjectsRequest's bound.
const maxSiteObjectsPerRequest = 256

func lowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func receiveSiteObjects(ctx context.Context, stream SiteObjectStream) (*controlv1.FetchSiteObjectsResponse, error) {
	type result struct {
		response *controlv1.FetchSiteObjectsResponse
		err      error
	}
	received := make(chan result, 1)
	go func() {
		response, err := stream.Recv()
		select {
		case received <- result{response: response, err: err}:
		case <-ctx.Done():
		}
	}()
	select {
	case result := <-received:
		return result.response, rpcError(result.err)
	case <-ctx.Done():
		return nil, rpcError(ctx.Err())
	}
}

func sendSiteObjects(ctx context.Context, stream grpc.ServerStreamingServer[agentv1.FetchSiteObjectsResponse], response *agentv1.FetchSiteObjectsResponse) error {
	sent := make(chan error, 1)
	go func() {
		err := stream.Send(response)
		select {
		case sent <- err:
		case <-ctx.Done():
		}
	}()
	select {
	case err := <-sent:
		return rpcError(err)
	case <-ctx.Done():
		return rpcError(ctx.Err())
	}
}

func (g *Gateway) validateEnrollment(request *agentv1.EnrollRequest) error {
	if request == nil {
		return fmt.Errorf("enrollment request is required")
	}
	if err := g.validateRequestMetadata(request.Request); err != nil {
		return err
	}
	if request.EnrollmentToken == "" || len(request.EnrollmentToken) > g.config.MaxIdentifierBytes {
		return fmt.Errorf("enrollment token is missing or exceeds its size limit")
	}
	if len(request.CertificateSigningRequestDer) == 0 || len(request.CertificateSigningRequestDer) > maxCSRBytes {
		return fmt.Errorf("certificate signing request is missing or exceeds its size limit")
	}
	if len(request.MachineFingerprintSha256) != 32 || len(request.ArtifactEncryptionPublicKey) != 32 {
		return fmt.Errorf("fingerprint and artifact public key must be 32 bytes")
	}
	if err := validateVersionRange(request.SupportedProtocolVersions); err != nil {
		return err
	}
	if request.Capabilities == nil || len(request.Capabilities.Features) > g.config.MaxCapabilities {
		return fmt.Errorf("capabilities are missing or exceed their size limit")
	}
	return nil
}

func (g *Gateway) validateHello(hello *agentv1.AgentHello) error {
	if err := g.validateUUID("hello.node_id", hello.NodeId); err != nil {
		return err
	}
	if err := g.validateUUID("hello.boot_id", hello.BootId); err != nil {
		return err
	}
	if err := validateVersionRange(hello.SupportedProtocolVersions); err != nil {
		return err
	}
	if hello.Capabilities == nil || len(hello.Capabilities.Features) > g.config.MaxCapabilities {
		return fmt.Errorf("hello capabilities are missing or exceed their size limit")
	}
	if !validAgentVersion(hello.Capabilities.AgentVersion, false) {
		return fmt.Errorf("hello agent version is invalid")
	}
	if len(hello.ActiveDeployments) > g.config.MaxActiveDeployments {
		return fmt.Errorf("hello active deployments exceed their size limit")
	}
	if err := g.validateIdentifier("hello.artifact_encryption_key_id", hello.ArtifactEncryptionKeyId, true); err != nil {
		return err
	}
	activeIdentityCapable, err := activeConfigIdentityCapabilityFromFeatures(hello.Capabilities.Features)
	if err != nil {
		return err
	}
	ackReceiptCapable, err := deploymentStatusAckReceiptCapabilityFromFeatures(hello.Capabilities.Features)
	if err != nil {
		return err
	}
	if ackReceiptCapable && !activeIdentityCapable {
		return fmt.Errorf("deployment status acknowledgement receipt requires active config identity")
	}
	if _, err := edgeUpgradeStatusPubAckCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := edgeUpgradeStatusAckReceiptCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := cacheControlCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := firewallControlCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := drainControlCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := nodeMonitoringCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := signerTrustCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := installationBanCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := marketProbeCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := l4LiveCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := autoDefenseCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := siteDropCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := gatewayAddressCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	if _, err := cacheControlCancelCapabilityFromFeatures(hello.Capabilities.Features); err != nil {
		return err
	}
	multiTenantCapable, err := multiTenantRuntimeCapabilityFromFeatures(hello.Capabilities.Features)
	if err != nil {
		return err
	}
	if multiTenantCapable && !activeIdentityCapable {
		return fmt.Errorf("multi-tenant runtime requires active config identity")
	}
	if err := g.validateHelloScopedConfigIdentities(hello, multiTenantCapable); err != nil {
		return err
	}
	portTransitionCapable, err := gatewayPortTransitionCapabilityFromFeatures(hello.Capabilities.Features)
	if err != nil {
		return err
	}
	if hello.GatewayPortTransitionProof != nil && !portTransitionCapable {
		return fmt.Errorf("gateway port transition proof requires capability v1")
	}
	if err := validatePortTransitionProof(hello.GatewayPortTransitionProof); err != nil {
		return err
	}
	return g.validateHelloActiveConfigIdentities(hello, activeIdentityCapable)
}

func hasACMEHTTP01OverlayCapability(capabilities *agentv1.AgentCapabilities) bool {
	if capabilities == nil {
		return false
	}
	for _, capability := range capabilities.Features {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY && capability.ApiVersion == 1 {
			return true
		}
	}
	return false
}

func hasCacheControlCapability(capabilities *agentv1.AgentCapabilities) bool {
	if capabilities == nil {
		return false
	}
	capable, _ := cacheControlCapabilityFromFeatures(capabilities.Features)
	return capable
}

func hasEdgeUpgradeCapability(capabilities *agentv1.AgentCapabilities) bool {
	if capabilities == nil {
		return false
	}
	for _, capability := range capabilities.Features {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE && capability.ApiVersion == 1 {
			return true
		}
	}
	return false
}

func firewallControlCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL {
			continue
		}
		if seen {
			return false, fmt.Errorf("firewall control capability is duplicated")
		}
		seen = true
		if capability.ApiVersion != firewallControlAPIVersion {
			return false, fmt.Errorf("firewall control capability version is unsupported")
		}
	}
	return seen, nil
}

func edgeUpgradeStatusPubAckCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK {
			continue
		}
		if seen {
			return false, fmt.Errorf("edge upgrade status PubAck capability is duplicated")
		}
		seen = true
		if capability.ApiVersion != edgeUpgradeStatusPubAckAPIVersion {
			return false, fmt.Errorf("edge upgrade status PubAck capability version is unsupported")
		}
	}
	if seen && !hasEdgeUpgradeCapability(&agentv1.AgentCapabilities{Features: features}) {
		return false, fmt.Errorf("edge upgrade status PubAck capability requires edge upgrade v1")
	}
	return seen, nil
}

func edgeUpgradeStatusAckReceiptCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT {
			continue
		}
		if seen {
			return false, fmt.Errorf("edge upgrade status acknowledgement receipt capability is duplicated")
		}
		seen = true
		if capability.ApiVersion != edgeUpgradeStatusAckReceiptAPIVersion {
			return false, fmt.Errorf("edge upgrade status acknowledgement receipt capability version is unsupported")
		}
	}
	if !seen {
		return false, nil
	}
	pubAck, err := edgeUpgradeStatusPubAckCapabilityFromFeatures(features)
	if err != nil {
		return false, err
	}
	if !pubAck {
		return false, fmt.Errorf("edge upgrade status acknowledgement receipt capability requires status PubAck")
	}
	return true, nil
}

func (g *Gateway) authorizeConnection(ctx context.Context, identity nodeIdentity, facts *controlv1.GatewaySessionFactsV1) (*controlv1.GetNodeAuthorizationResponse, error) {
	decisionCtx, cancel := context.WithTimeout(ctx, g.config.ControlDecisionTimeout)
	defer cancel()
	if facts != nil {
		facts = proto.Clone(facts).(*controlv1.GatewaySessionFactsV1)
	}
	response, err := g.control.GetNodeAuthorization(decisionCtx, &controlv1.GetNodeAuthorizationRequest{
		Request:                 newRequestMetadata(g.now()),
		NodeId:                  identity.NodeID,
		CertificateSerialNumber: identity.SerialNumber,
		CertificateSha256:       identity.CertificateSHA256[:],
		GatewayInstanceId:       g.config.GatewayInstanceID,
		SessionFacts:            facts,
	})
	if err != nil {
		return nil, rpcError(err)
	}
	if response == nil || response.NodeId != identity.NodeID {
		return nil, status.Error(codes.Internal, "control plane returned an inconsistent node authorization")
	}
	if !response.ConnectionAllowed || response.CertificateRevoked {
		return nil, status.Error(codes.PermissionDenied, "node connection is not authorized")
	}
	switch response.AdministrativeState {
	case controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE:
	case controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING,
		controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_PENDING:
		response.DeploymentsAllowed = false
	default:
		return nil, status.Error(codes.PermissionDenied, "node administrative state does not allow connections")
	}
	if response.SnapshotExpirationTime == nil || response.SnapshotExpirationTime.CheckValid() != nil || !response.SnapshotExpirationTime.AsTime().After(g.now()) {
		return nil, status.Error(codes.Unavailable, "node authorization snapshot is expired")
	}
	if validateVersionRange(response.AcceptedProtocolVersions) != nil {
		return nil, status.Error(codes.Internal, "control plane returned invalid protocol authorization")
	}
	if response.ArtifactEncryptionKeyId == "" {
		return nil, status.Error(codes.Internal, "control plane returned an incomplete artifact key authorization")
	}
	return response, nil
}

func (g *Gateway) serveSession(
	stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse],
	receive <-chan connectReceive,
	lease SessionLease,
	replay *messageReplayWindow,
	lastStreamSequence uint64,
	identity nodeIdentity,
	agentVersion string,
	agentVersions *commonv1.ProtocolVersionRange,
	selectedVersion *commonv1.ProtocolVersion,
	artifactEncryptionKeyID string,
	authorizationExpiration time.Time,
	deploymentsAllowed bool,
	acmeHTTP01OverlayCapable bool,
	cacheControlCapability ...bool,
) error {
	return g.serveSessionWithInstallation(stream, receive, lease, replay, lastStreamSequence, identity,
		agentVersion, agentVersions, selectedVersion, artifactEncryptionKeyID, "", authorizationExpiration,
		deploymentsAllowed, acmeHTTP01OverlayCapable, cacheControlCapability...)
}

func (g *Gateway) serveSessionWithInstallation(
	stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse],
	receive <-chan connectReceive,
	lease SessionLease,
	replay *messageReplayWindow,
	lastStreamSequence uint64,
	identity nodeIdentity,
	agentVersion string,
	agentVersions *commonv1.ProtocolVersionRange,
	selectedVersion *commonv1.ProtocolVersion,
	artifactEncryptionKeyID string,
	installationID string,
	authorizationExpiration time.Time,
	deploymentsAllowed bool,
	acmeHTTP01OverlayCapable bool,
	cacheControlCapability ...bool,
) error {
	cacheControlCapable := len(cacheControlCapability) >= 1 && cacheControlCapability[0]
	activeIdentityCapable := len(cacheControlCapability) >= 2 && cacheControlCapability[1]
	ackReceiptCapable := len(cacheControlCapability) >= 3 && cacheControlCapability[2]
	upgradeCapable := len(cacheControlCapability) >= 4 && cacheControlCapability[3]
	upgradeStatusPubAckCapable := len(cacheControlCapability) >= 5 && cacheControlCapability[4]
	upgradeStatusAckReceiptCapable := len(cacheControlCapability) >= 6 && cacheControlCapability[5]
	firewallCapable := len(cacheControlCapability) >= 7 && cacheControlCapability[6]
	drainCapable := len(cacheControlCapability) >= 8 && cacheControlCapability[7]
	nodeMonitoringCapable := len(cacheControlCapability) >= 9 && cacheControlCapability[8]
	portTransitionCapable := len(cacheControlCapability) >= 10 && cacheControlCapability[9]
	marketProbeEnabled := len(cacheControlCapability) >= 11 && cacheControlCapability[10] && g.marketProbes != nil
	var marketProbes *sessionMarketProbes
	multiTenantEnabled := len(cacheControlCapability) >= 12 && cacheControlCapability[11] && activeIdentityCapable
	l4LiveEnabled := len(cacheControlCapability) >= 13 && cacheControlCapability[12] && g.l4Live != nil
	l4LiveVersion := uint32(1)
	if len(cacheControlCapability) >= 14 && cacheControlCapability[13] {
		l4LiveVersion = 2
	}
	var l4Live *sessionL4Live
	signerTrustEnabled := len(cacheControlCapability) >= 15 && cacheControlCapability[14] && g.signerTrust != nil
	sched302Enabled := len(cacheControlCapability) >= 16 && cacheControlCapability[15] && g.sched302 != nil
	var sched302Source *sessionSched302
	autoDefenseEnabled := len(cacheControlCapability) >= 17 && cacheControlCapability[16] && g.autoDefense != nil
	var autoDefense *sessionAutoDefense
	var signerTrust *sessionSignerTrust
	securityBansEnabled := len(cacheControlCapability) >= 18 && cacheControlCapability[17] && g.securityBans != nil
	var securityBans *sessionSecurityBans
	installationBanEnabled := len(cacheControlCapability) >= 19 && cacheControlCapability[18] && g.installationBan != nil
	var installationBan *sessionInstallationBan
	endpointMigrationEnabled := len(cacheControlCapability) >= 20 && cacheControlCapability[19]
	// Site drop snapshots are read for every node once the bus is configured;
	// a node without SITE_DROP v1 is answered not_supported by the gateway.
	siteDropCapable := len(cacheControlCapability) >= 21 && cacheControlCapability[20]
	cacheCancelCapable := len(cacheControlCapability) >= 22 && cacheControlCapability[21]
	// Address change documents are read for every node once the bus is
	// configured; a node without the capability is answered not_supported.
	gatewayAddressCapable := len(cacheControlCapability) >= 23 && cacheControlCapability[22]
	var gatewayAddresses *sessionGatewayAddresses
	var siteDrops *sessionSiteDrops
	// Disabled Gateway (ADR 0013 §5.2): once per session, ask the node to
	// migrate; close the session at the eviction time unless re-enabled.
	drainHandled := false
	var evictTimer *time.Timer
	defer func() {
		if evictTimer != nil {
			evictTimer.Stop()
		}
	}()
	var heartbeatSequence uint64
	responseSequence := uint64(1)
	offlineDeadline := g.now().Add(g.config.OfflineAfter)
	authorizationRefreshAt := refreshAt(g.now(), authorizationExpiration)
	pendingCommands := make(pendingCommandSet, g.config.MaxPendingCommands)
	pendingReceiptConfirmations := make(map[deploymentKey]bool, g.config.MaxPendingCommands)
	// Terminal receipts acknowledged this session whose Agent receipt has not
	// arrived yet: each becomes a confirmation (ackReceiptCapable).
	awaitingReceiptConfirmations := make(map[deploymentKey]struct{}, g.config.MaxPendingCommands)
	pendingOverlays := make(pendingOverlayCommandSet, g.config.MaxPendingCommands)
	pendingCacheCommands := make(pendingCacheCommandSet, g.config.MaxPendingCommands)
	pendingCacheCancels := make(pendingCacheCancelSet)
	pendingUpgradeCommands := make(pendingUpgradeCommandSet, g.config.MaxPendingCommands)
	pendingFirewallCommands := make(pendingFirewallCommandSet, g.config.MaxPendingCommands)
	pendingDrainCommands := make(pendingDrainCommandSet, g.config.MaxPendingCommands)
	pendingPortTransitions := make(pendingPortTransitionSet, g.config.MaxPendingCommands)
	var commandSource *sessionCommandSource
	var overlaySource *sessionOverlayCommandSource
	var cacheCommandSource *sessionCacheCommandSource
	var upgradeCommandSource *sessionUpgradeCommandSource
	var firewallCommandSource *sessionFirewallCommandSource
	var drainCommandSource *sessionDrainCommandSource
	var portTransitionSource *sessionPortTransitionSource
	var nodeMonitoringSource *sessionNodeMonitoringSource
	var pendingNodeMonitoring NodeMonitoringDelivery
	var pendingNodeMonitoringArtifact *agentv1.NodeMonitoringArtifact
	var nodeMonitoringLastSequence uint64
	nodeMonitoringAcks := make(map[string]nodeMonitoringAckRecord)
	cacheCommandsAllowed := deploymentsAllowed && cacheControlCapable
	upgradeCommandsAllowed := deploymentsAllowed && upgradeCapable
	firewallCommandsAllowed := deploymentsAllowed && firewallCapable && g.firewall != nil
	drainCommandsAllowed := deploymentsAllowed && drainCapable && g.drain != nil
	portTransitionsAllowed := deploymentsAllowed && portTransitionCapable && g.portTransitions != nil && g.portManager != nil
	nodeMonitoringCommandsAllowed := deploymentsAllowed && nodeMonitoringCapable && g.nodeMonitoring != nil
	if g.receipts != nil {
		operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
		confirmations, err := g.receipts.listTerminalCommandReceiptConfirmations(
			operationCtx, identity.NodeID, g.config.MaxPendingCommands,
		)
		cancel()
		if err != nil {
			return status.Error(codes.Unavailable, "terminal command receipt confirmations could not be recovered")
		}
		for _, confirmation := range confirmations {
			if validateTerminalCommandReceiptConfirmation(confirmation) != nil || confirmation.Receipt.NodeID != identity.NodeID {
				return status.Error(codes.FailedPrecondition, "terminal command receipt confirmation recovery returned invalid state")
			}
			pendingReceiptConfirmations[confirmation.deploymentKey()] = true
		}
	}
	if upgradeStatusAckReceiptCapable {
		if g.upgradeReceipts == nil {
			return status.Error(codes.FailedPrecondition, "upgrade status acknowledgement receipts are unavailable")
		}
		operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
		acks, err := g.upgradeReceipts.listUpgradeStatusAcks(operationCtx, identity.NodeID, g.config.MaxPendingCommands)
		cancel()
		if err != nil {
			return status.Error(codes.Unavailable, "upgrade status acknowledgements could not be recovered")
		}
		sortUpgradeStatusAckRecords(acks)
		for _, record := range acks {
			if validateUpgradeStatusAckRecord(record) != nil || record.NodeID != identity.NodeID ||
				record.InstallationID != installationID {
				return status.Error(codes.FailedPrecondition, "upgrade status acknowledgement recovery returned invalid state")
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream: responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_UpgradeStatusAck{
					UpgradeStatusAck: proto.Clone(record.Ack).(*agentv1.UpgradeStatusAck),
				},
			}); err != nil {
				return err
			}
		}
	}
	if g.commands != nil && deploymentsAllowed {
		var err error
		commandSource, err = newSessionCommandSource(stream.Context(), g.commands, identity.NodeID)
		if err != nil {
			return status.Error(codes.Unavailable, "could not subscribe to node commands")
		}
	}
	// Overlays are subscribed whatever the deployment authorization: a node
	// without deployments still receives CLEANUP_ONLY (ADR-0003); APPLY is
	// gated per command below against the current authorization.
	if g.overlays != nil {
		var err error
		overlaySource, err = newSessionOverlayCommandSource(stream.Context(), g.overlays, identity.NodeID)
		if err != nil {
			return status.Error(codes.Unavailable, "could not subscribe to node overlay commands")
		}
	}
	if g.cache != nil && cacheCommandsAllowed {
		var err error
		cacheCommandSource, err = newSessionCacheCommandSource(stream.Context(), g.cache, identity.NodeID)
		if err != nil {
			return status.Error(codes.Unavailable, "could not subscribe to node cache commands")
		}
	}
	if g.upgrades != nil && upgradeCommandsAllowed {
		var err error
		upgradeCommandSource, err = newSessionUpgradeCommandSource(stream.Context(), g.upgrades, identity.NodeID)
		if err != nil {
			return status.Error(codes.Unavailable, "could not subscribe to node upgrade commands")
		}
	}
	if firewallCommandsAllowed {
		var err error
		firewallCommandSource, err = newSessionFirewallCommandSource(stream.Context(), g.firewall, identity.NodeID)
		if err != nil {
			return status.Error(codes.Unavailable, "could not subscribe to node firewall commands")
		}
	}
	if drainCommandsAllowed {
		var err error
		drainCommandSource, err = newSessionDrainCommandSource(stream.Context(), g.drain, identity.NodeID)
		if err != nil {
			return status.Error(codes.Unavailable, "could not subscribe to node drain commands")
		}
	}
	if portTransitionsAllowed {
		var err error
		portTransitionSource, err = newSessionPortTransitionSource(stream.Context(), g.portTransitions, identity.NodeID)
		if err != nil {
			return status.Error(codes.Unavailable, "could not subscribe to gateway port transitions")
		}
	}
	if nodeMonitoringCommandsAllowed {
		var err error
		nodeMonitoringSource, err = newSessionNodeMonitoringSource(stream.Context(), g.nodeMonitoring, identity.NodeID)
		if err != nil {
			return status.Error(codes.Unavailable, "could not subscribe to node monitoring artifacts")
		}
	}
	defer func() { stopSessionCommands(commandSource, pendingCommands, g.config.CommandOperationTimeout) }()
	defer func() { stopSessionOverlayCommands(overlaySource, pendingOverlays, g.config.CommandOperationTimeout) }()
	defer func() {
		stopSessionCacheCommands(cacheCommandSource, pendingCacheCommands, g.config.CommandOperationTimeout)
		nakPendingCacheCancels(pendingCacheCancels, g.config.CommandOperationTimeout)
	}()
	defer func() {
		stopSessionUpgradeCommands(upgradeCommandSource, pendingUpgradeCommands, g.config.CommandOperationTimeout)
	}()
	defer func() {
		stopSessionFirewallCommands(firewallCommandSource, pendingFirewallCommands, g.config.CommandOperationTimeout)
	}()
	defer func() {
		stopSessionDrainCommands(drainCommandSource, pendingDrainCommands, g.config.CommandOperationTimeout)
	}()
	defer func() {
		stopSessionPortTransitions(portTransitionSource, pendingPortTransitions, g.config.CommandOperationTimeout)
	}()
	defer func() {
		if pendingNodeMonitoring != nil {
			operationCtx, cancel := context.WithTimeout(context.Background(), g.config.CommandOperationTimeout)
			_ = pendingNodeMonitoring.Nak(operationCtx)
			cancel()
		}
		stopSessionNodeMonitoring(nodeMonitoringSource, g.config.CommandOperationTimeout)
	}()
	// Signer trust is delivered whatever the authorization snapshot says about deployments (signer_trust.go).
	if signerTrustEnabled {
		var err error
		if signerTrust, err = g.startSessionSignerTrust(stream.Context(), identity.NodeID); err != nil {
			return err
		}
	}
	defer func() { signerTrust.stop(g.config.CommandOperationTimeout) }()
	if installationBanEnabled {
		var err error
		if installationBan, err = g.startSessionInstallationBan(stream.Context(), identity.NodeID); err != nil {
			return err
		}
	}
	defer func() { installationBan.stop(g.config.CommandOperationTimeout) }()
	// Ban lists are delivered whatever the authorization snapshot says about
	// deployments: a release must reach a node that no longer receives
	// configuration (security_ban.go).
	if securityBansEnabled {
		var err error
		if securityBans, err = g.startSessionSecurityBans(stream.Context(), identity.NodeID); err != nil {
			return err
		}
	}
	defer func() { securityBans.stop(g.config.CommandOperationTimeout) }()
	if g.siteDrops != nil {
		var err error
		if siteDrops, err = g.startSessionSiteDrops(stream.Context(), identity.NodeID); err != nil {
			return err
		}
	}
	defer func() { siteDrops.stop() }()
	if g.gatewayAddresses != nil {
		var err error
		if gatewayAddresses, err = g.startSessionGatewayAddresses(stream.Context(), identity.NodeID); err != nil {
			return err
		}
	}
	defer func() { gatewayAddresses.stop() }()
	if sched302Enabled {
		var err error
		if sched302Source, err = g.startSessionSched302(stream.Context(), identity.NodeID); err != nil {
			return err
		}
	}
	defer func() { sched302Source.stop() }()
	// Auto defense snapshots are delivered whatever the authorization snapshot
	// says about deployments (autodefense.go).
	if autoDefenseEnabled {
		var err error
		if autoDefense, err = g.startSessionAutoDefense(stream.Context(), identity.NodeID); err != nil {
			return err
		}
	}
	defer func() { autoDefense.stop(g.config.CommandOperationTimeout) }()
	if marketProbeEnabled && deploymentsAllowed {
		var err error
		if marketProbes, err = g.startSessionMarketProbes(stream.Context(), identity.NodeID); err != nil {
			return err
		}
	}
	defer func() { marketProbes.stop() }()
	if l4LiveEnabled && deploymentsAllowed {
		var err error
		if l4Live, err = g.startSessionL4Live(stream.Context(), identity.NodeID); err != nil {
			return err
		}
	}
	defer func() { l4Live.stop() }()
	for {
		var commandReceive <-chan commandReceive
		var overlayReceive <-chan overlayCommandReceive
		var cacheCommandReceive <-chan cacheCommandReceive
		var upgradeCommandReceive <-chan upgradeCommandReceive
		var firewallCommandReceive <-chan firewallCommandReceive
		var drainCommandReceive <-chan drainCommandReceive
		var portTransitionReceive <-chan portTransitionReceive
		var nodeMonitoringReceive <-chan nodeMonitoringReceive
		// A terminal receipt keeps its confirmation until two heartbeats
		// compact it, bounded by MaxPendingCommands with the commands in
		// flight: deliver a command only when its receipt can be confirmed.
		if commandSource != nil && pendingCommands.deliveryCount()+len(pendingReceiptConfirmations)+
			len(awaitingReceiptConfirmations) < g.config.MaxPendingCommands {
			commandSource.arm()
			commandReceive = commandSource.next
		}
		if overlaySource != nil && pendingOverlays.deliveryCount() < g.config.MaxPendingCommands {
			overlaySource.arm()
			overlayReceive = overlaySource.next
		}
		if cacheCommandSource != nil && pendingCacheCommands.deliveryCount() < g.config.MaxPendingCommands {
			cacheCommandSource.arm()
			cacheCommandReceive = cacheCommandSource.next
		}
		if upgradeCommandSource != nil && pendingUpgradeCommands.deliveryCount() < g.config.MaxPendingCommands {
			upgradeCommandSource.arm()
			upgradeCommandReceive = upgradeCommandSource.next
		}
		if firewallCommandSource != nil && pendingFirewallCommands.deliveryCount() < g.config.MaxPendingCommands {
			firewallCommandSource.arm()
			firewallCommandReceive = firewallCommandSource.next
		}
		if drainCommandSource != nil && pendingDrainCommands.deliveryCount() < g.config.MaxPendingCommands {
			drainCommandSource.arm()
			drainCommandReceive = drainCommandSource.next
		}
		if portTransitionSource != nil && pendingPortTransitions.deliveryCount() < g.config.MaxPendingCommands {
			portTransitionSource.arm()
			portTransitionReceive = portTransitionSource.next
		}
		if nodeMonitoringSource != nil && pendingNodeMonitoring == nil {
			nodeMonitoringSource.arm()
			nodeMonitoringReceive = nodeMonitoringSource.next
		}
		var drainSignal <-chan struct{}
		if !drainHandled {
			drainSignal = g.disableState.disabledSignal()
		}
		var evictC <-chan time.Time
		if evictTimer != nil {
			evictC = evictTimer.C
		}
		authorizationTimer := time.NewTimer(delayUntil(g.now(), authorizationRefreshAt))
		offlineTimer := time.NewTimer(delayUntil(g.now(), offlineDeadline))
		select {
		case <-stream.Context().Done():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			return rpcError(stream.Context().Err())
		case <-drainSignal:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			drainHandled = true
			disabled, deadline := g.disableState.Disabled()
			if !disabled {
				drainHandled = false
				continue
			}
			if evictTimer == nil {
				evictTimer = time.NewTimer(delayUntil(g.now(), deadline))
			}
			endpoints, version := g.endpoints.Snapshot()
			if !endpointMigrationEnabled || len(endpoints) == 0 {
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream: responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_GatewayEndpointMigration{GatewayEndpointMigration: &agentv1.GatewayEndpointMigration{
					Endpoints: endpoints, EndpointsVersion: version,
				}},
			}); err != nil {
				return err
			}
		case <-evictC:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			if disabled, _ := g.disableState.Disabled(); disabled {
				return status.Error(codes.Unavailable, "gateway is disabled; connect to another gateway endpoint")
			}
			evictTimer, drainHandled = nil, false
		case <-lease.Superseded():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			return status.Error(codes.Aborted, "node session was superseded")
		case request := <-l4Live.requests():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			l4Live.expire(g.now())
			command, admitted := l4Live.admit(request, identity.NodeID, l4LiveVersion, g.now())
			if !admitted {
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_L4LiveConnectionsCommand{L4LiveConnectionsCommand: command},
			}); err != nil {
				return err
			}
		case request := <-marketProbes.requests():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			marketProbes.expire(g.now())
			command, admitted := marketProbes.admit(request, identity.NodeID, g.now())
			if !admitted {
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_MarketProbeCommand{MarketProbeCommand: command},
			}); err != nil {
				return err
			}
		case received := <-sched302Source.receive():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			sched302Source.next = nil
			if received.err != nil || received.delivery == nil {
				return status.Error(codes.Unavailable, "schedule302 table delivery failed")
			}
			table := received.delivery.Table()
			if err := validateSched302Table(table, identity.NodeID); err != nil {
				// A broken publication can never become valid: drop it, keep the session.
				_ = received.delivery.Term()
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_Sched302Table{Sched302Table: table},
			}); err != nil {
				return err
			}
			operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
			ackErr := received.delivery.Ack(operationCtx)
			cancel()
			if ackErr != nil {
				return status.Error(codes.Unavailable, "schedule302 table disposition failed")
			}
		case received := <-autoDefense.receive():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			autoDefense.next = nil
			if received.err != nil || received.delivery == nil {
				return status.Error(codes.Unavailable, "auto defense snapshot delivery failed")
			}
			command := received.delivery.Command()
			if err := validateAutoDefenseCommand(command, identity.NodeID); err != nil {
				// A part with a broken binding can never become valid: drop it and keep the session.
				operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
				if terminal, ok := received.delivery.(interface{ Term() error }); ok {
					_ = terminal.Term()
				} else {
					_ = received.delivery.Nak(operationCtx)
				}
				cancel()
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_AutoDefenseCommand{AutoDefenseCommand: proto.Clone(command).(*agentv1.AutoDefenseCommand)},
			}); err != nil {
				operationCtx, cancel := context.WithTimeout(context.Background(), g.config.CommandOperationTimeout)
				_ = received.delivery.Nak(operationCtx)
				cancel()
				return err
			}
			autoDefense.pending, autoDefense.pendingCommand = received.delivery, command
		case received := <-signerTrust.receive():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			signerTrust.next = nil
			if received.err != nil || received.delivery == nil {
				return status.Error(codes.Unavailable, "edge signer trust bundle delivery failed")
			}
			bundle := received.delivery.Bundle()
			if err := validateSignerTrustBundle(bundle, identity.NodeID); err != nil {
				// A publication with a broken binding can never become valid: drop it and keep the session.
				operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
				if terminal, ok := received.delivery.(interface{ Term() error }); ok {
					_ = terminal.Term()
				} else {
					_ = received.delivery.Nak(operationCtx)
				}
				cancel()
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_EdgeSignerTrustBundle{EdgeSignerTrustBundle: proto.Clone(bundle).(*agentv1.EdgeSignerTrustBundle)},
			}); err != nil {
				operationCtx, cancel := context.WithTimeout(context.Background(), g.config.CommandOperationTimeout)
				_ = received.delivery.Nak(operationCtx)
				cancel()
				return err
			}
			signerTrust.pending, signerTrust.pendingBundle = received.delivery, bundle
		case received := <-installationBan.receive():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			installationBan.next = nil
			if received.err != nil || received.delivery == nil {
				return status.Error(codes.Unavailable, "installation ban command delivery failed")
			}
			command := received.delivery.Command()
			if err := validateInstallationBanCommand(command, identity.NodeID); err != nil {
				// A publication with a broken binding can never become valid: drop it and keep the session.
				operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
				if terminal, ok := received.delivery.(interface{ Term() error }); ok {
					_ = terminal.Term()
				} else {
					_ = received.delivery.Nak(operationCtx)
				}
				cancel()
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_InstallationBanCommand{InstallationBanCommand: proto.Clone(command).(*agentv1.InstallationBanCommand)},
			}); err != nil {
				operationCtx, cancel := context.WithTimeout(context.Background(), g.config.CommandOperationTimeout)
				_ = received.delivery.Nak(operationCtx)
				cancel()
				return err
			}
			installationBan.pending, installationBan.pendingCommand = received.delivery, command
		case received := <-securityBans.receive():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			securityBans.next = nil
			if received.err != nil || received.delivery == nil {
				return status.Error(codes.Unavailable, "security ban list delivery failed")
			}
			command := received.delivery.Command()
			if err := validateSecurityBanCommand(command, identity.NodeID); err != nil {
				// A snapshot with a broken binding can never become valid: drop it and keep the session.
				operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
				if terminal, ok := received.delivery.(interface{ Term() error }); ok {
					_ = terminal.Term()
				} else {
					_ = received.delivery.Nak(operationCtx)
				}
				cancel()
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_SecurityBanCommand{SecurityBanCommand: proto.Clone(command).(*agentv1.SecurityBanCommand)},
			}); err != nil {
				operationCtx, cancel := context.WithTimeout(context.Background(), g.config.CommandOperationTimeout)
				_ = received.delivery.Nak(operationCtx)
				cancel()
				return err
			}
			securityBans.pending, securityBans.pendingCommand = received.delivery, command
		case received := <-siteDrops.receive():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			siteDrops.next = nil
			if received.err != nil || received.command == nil {
				return status.Error(codes.Unavailable, "site drop list delivery failed")
			}
			command := received.command
			if err := validateSiteDropCommand(command, identity.NodeID); err != nil {
				continue // a snapshot with a broken binding can never become valid: skip it and keep the session
			}
			if !siteDropCapable {
				if err := g.publishSiteDropReceipt(stream.Context(), identity.NodeID, notSupportedSiteDropReceipt(command, g.now())); err != nil {
					return err
				}
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_SiteDropCommand{SiteDropCommand: proto.Clone(command).(*agentv1.SiteDropCommand)},
			}); err != nil {
				return err
			}
			siteDrops.pending = command
		case received := <-gatewayAddresses.receive():
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			gatewayAddresses.next = nil
			if received.err != nil || received.command == nil {
				return status.Error(codes.Unavailable, "gateway address change delivery failed")
			}
			command := received.command
			if err := validateGatewayAddressCommand(command, identity.NodeID); err != nil {
				continue // a broken binding can never become valid: skip it and keep the session
			}
			if !gatewayAddressCapable {
				if err := g.publishGatewayAddressReceipt(stream.Context(), identity.NodeID, notSupportedGatewayAddressReceipt(command, g.now())); err != nil {
					return err
				}
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_GatewayAddressChangeCommand{GatewayAddressChangeCommand: proto.Clone(command).(*agentv1.GatewayAddressChangeCommand)},
			}); err != nil {
				return err
			}
			gatewayAddresses.pending = command
		case received := <-nodeMonitoringReceive:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			nodeMonitoringSource.next = nil
			if received.err != nil || received.delivery == nil {
				return status.Error(codes.Unavailable, "node monitoring artifact delivery failed")
			}
			artifact := received.delivery.Artifact()
			if err := validateNodeMonitoringArtifact(artifact, identity.NodeID); err != nil {
				operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
				_ = received.delivery.Nak(operationCtx)
				cancel()
				return status.Error(codes.FailedPrecondition, "node monitoring artifact is unsupported or invalid")
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream: responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_NodeMonitoringArtifact{
					NodeMonitoringArtifact: proto.Clone(artifact).(*agentv1.NodeMonitoringArtifact),
				},
			}); err != nil {
				operationCtx, cancel := context.WithTimeout(context.Background(), g.config.CommandOperationTimeout)
				_ = received.delivery.Nak(operationCtx)
				cancel()
				return err
			}
			pendingNodeMonitoring = received.delivery
			pendingNodeMonitoringArtifact = artifact
		case <-authorizationTimer.C:
			stopTimer(offlineTimer)
			refreshed, err := g.refreshSessionAuthorization(stream.Context(), identity, agentVersions, selectedVersion, artifactEncryptionKeyID, offlineDeadline, installationID)
			if err != nil {
				return err
			}
			authorizationRefreshAt = refreshed.refreshAt
			commandSource, err = g.applyDeploymentAuthorization(stream.Context(), identity.NodeID, commandSource, pendingCommands, deploymentsAllowed, refreshed.deploymentsAllowed)
			if err != nil {
				return err
			}
			refreshedCacheAllowed := refreshed.deploymentsAllowed && cacheControlCapable
			cacheCommandSource, err = g.applyCacheAuthorization(stream.Context(), identity.NodeID, cacheCommandSource, pendingCacheCommands, cacheCommandsAllowed, refreshedCacheAllowed)
			if err != nil {
				return err
			}
			deploymentsAllowed = refreshed.deploymentsAllowed
			cacheCommandsAllowed = refreshedCacheAllowed
			refreshedUpgradeAllowed := refreshed.deploymentsAllowed && upgradeCapable
			upgradeCommandSource, err = g.applyUpgradeAuthorization(stream.Context(), identity.NodeID, upgradeCommandSource, pendingUpgradeCommands, upgradeCommandsAllowed, refreshedUpgradeAllowed)
			if err != nil {
				return err
			}
			upgradeCommandsAllowed = refreshedUpgradeAllowed
			refreshedFirewallAllowed := refreshed.deploymentsAllowed && firewallCapable && g.firewall != nil
			firewallCommandSource, err = g.applyFirewallAuthorization(stream.Context(), identity.NodeID, firewallCommandSource,
				pendingFirewallCommands, firewallCommandsAllowed, refreshedFirewallAllowed)
			if err != nil {
				return err
			}
			firewallCommandsAllowed = refreshedFirewallAllowed
			refreshedDrainAllowed := refreshed.deploymentsAllowed && drainCapable && g.drain != nil
			drainCommandSource, err = g.applyDrainAuthorization(stream.Context(), identity.NodeID, drainCommandSource,
				pendingDrainCommands, drainCommandsAllowed, refreshedDrainAllowed)
			if err != nil {
				return err
			}
			drainCommandsAllowed = refreshedDrainAllowed
			refreshedPortTransitionsAllowed := refreshed.deploymentsAllowed && portTransitionCapable && g.portTransitions != nil && g.portManager != nil
			portTransitionSource, err = g.applyPortTransitionAuthorization(stream.Context(), identity.NodeID, portTransitionSource,
				pendingPortTransitions, portTransitionsAllowed, refreshedPortTransitionsAllowed)
			if err != nil {
				return err
			}
			portTransitionsAllowed = refreshedPortTransitionsAllowed
			refreshedNodeMonitoringAllowed := refreshed.deploymentsAllowed && nodeMonitoringCapable && g.nodeMonitoring != nil
			nodeMonitoringSource, pendingNodeMonitoring, err = g.applyNodeMonitoringAuthorization(stream.Context(), identity.NodeID,
				nodeMonitoringSource, pendingNodeMonitoring, nodeMonitoringCommandsAllowed, refreshedNodeMonitoringAllowed)
			if err != nil {
				return err
			}
			if pendingNodeMonitoring == nil {
				pendingNodeMonitoringArtifact = nil
			}
			nodeMonitoringCommandsAllowed = refreshedNodeMonitoringAllowed
			if l4Live, err = g.applyL4LiveAuthorization(stream.Context(), identity.NodeID, l4Live,
				l4LiveEnabled && refreshed.deploymentsAllowed); err != nil {
				return err
			}
			if marketProbes, err = g.applyMarketProbeAuthorization(stream.Context(), identity.NodeID, marketProbes,
				marketProbeEnabled && refreshed.deploymentsAllowed); err != nil {
				return err
			}
		case <-offlineTimer.C:
			stopTimer(authorizationTimer)
			return status.Error(codes.DeadlineExceeded, "node heartbeat deadline exceeded")
		case incoming := <-receive:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			if sessionSuperseded(lease) {
				return status.Error(codes.Aborted, "node session was superseded")
			}
			if !g.now().Before(offlineDeadline) {
				return status.Error(codes.DeadlineExceeded, "node heartbeat deadline exceeded")
			}
			if !g.now().Before(authorizationRefreshAt) {
				refreshed, err := g.refreshSessionAuthorization(stream.Context(), identity, agentVersions, selectedVersion, artifactEncryptionKeyID, offlineDeadline, installationID)
				if err != nil {
					return err
				}
				authorizationRefreshAt = refreshed.refreshAt
				commandSource, err = g.applyDeploymentAuthorization(stream.Context(), identity.NodeID, commandSource, pendingCommands, deploymentsAllowed, refreshed.deploymentsAllowed)
				if err != nil {
					return err
				}
				refreshedCacheAllowed := refreshed.deploymentsAllowed && cacheControlCapable
				cacheCommandSource, err = g.applyCacheAuthorization(stream.Context(), identity.NodeID, cacheCommandSource, pendingCacheCommands, cacheCommandsAllowed, refreshedCacheAllowed)
				if err != nil {
					return err
				}
				deploymentsAllowed = refreshed.deploymentsAllowed
				cacheCommandsAllowed = refreshedCacheAllowed
				refreshedUpgradeAllowed := refreshed.deploymentsAllowed && upgradeCapable
				upgradeCommandSource, err = g.applyUpgradeAuthorization(stream.Context(), identity.NodeID, upgradeCommandSource, pendingUpgradeCommands, upgradeCommandsAllowed, refreshedUpgradeAllowed)
				if err != nil {
					return err
				}
				upgradeCommandsAllowed = refreshedUpgradeAllowed
				refreshedFirewallAllowed := refreshed.deploymentsAllowed && firewallCapable && g.firewall != nil
				firewallCommandSource, err = g.applyFirewallAuthorization(stream.Context(), identity.NodeID, firewallCommandSource,
					pendingFirewallCommands, firewallCommandsAllowed, refreshedFirewallAllowed)
				if err != nil {
					return err
				}
				firewallCommandsAllowed = refreshedFirewallAllowed
				refreshedDrainAllowed := refreshed.deploymentsAllowed && drainCapable && g.drain != nil
				drainCommandSource, err = g.applyDrainAuthorization(stream.Context(), identity.NodeID, drainCommandSource,
					pendingDrainCommands, drainCommandsAllowed, refreshedDrainAllowed)
				if err != nil {
					return err
				}
				drainCommandsAllowed = refreshedDrainAllowed
				refreshedPortTransitionsAllowed := refreshed.deploymentsAllowed && portTransitionCapable && g.portTransitions != nil && g.portManager != nil
				portTransitionSource, err = g.applyPortTransitionAuthorization(stream.Context(), identity.NodeID, portTransitionSource,
					pendingPortTransitions, portTransitionsAllowed, refreshedPortTransitionsAllowed)
				if err != nil {
					return err
				}
				portTransitionsAllowed = refreshedPortTransitionsAllowed
				refreshedNodeMonitoringAllowed := refreshed.deploymentsAllowed && nodeMonitoringCapable && g.nodeMonitoring != nil
				nodeMonitoringSource, pendingNodeMonitoring, err = g.applyNodeMonitoringAuthorization(stream.Context(), identity.NodeID,
					nodeMonitoringSource, pendingNodeMonitoring, nodeMonitoringCommandsAllowed, refreshedNodeMonitoringAllowed)
				if err != nil {
					return err
				}
				if pendingNodeMonitoring == nil {
					pendingNodeMonitoringArtifact = nil
				}
				nodeMonitoringCommandsAllowed = refreshedNodeMonitoringAllowed
				if l4Live, err = g.applyL4LiveAuthorization(stream.Context(), identity.NodeID, l4Live,
					l4LiveEnabled && refreshed.deploymentsAllowed); err != nil {
					return err
				}
				if marketProbes, err = g.applyMarketProbeAuthorization(stream.Context(), identity.NodeID, marketProbes,
					marketProbeEnabled && refreshed.deploymentsAllowed); err != nil {
					return err
				}
			}
			if errors.Is(incoming.err, io.EOF) {
				return nil
			}
			if incoming.err != nil {
				return rpcError(incoming.err)
			}
			request := incoming.request
			if request == nil || g.validateStreamMetadata(request.Stream) != nil {
				return status.Error(codes.InvalidArgument, "stream metadata is invalid")
			}
			duplicate, err := replay.accept(request, lastStreamSequence)
			if errors.Is(err, ErrMessageIDConflict) {
				return status.Error(codes.FailedPrecondition, err.Error())
			}
			if err != nil {
				return status.Error(codes.InvalidArgument, err.Error())
			}
			if !duplicate {
				lastStreamSequence = request.Stream.Sequence
			}
			switch payload := request.Payload.(type) {
			case *agentv1.ConnectRequest_NodeMonitoringReport:
				if !nodeMonitoringCapable || g.nodeMonitoring == nil {
					return status.Error(codes.PermissionDenied, "node monitoring report is not negotiated")
				}
				report := payload.NodeMonitoringReport
				if replayed, ok, replayErr := replayNodeMonitoringAck(nodeMonitoringAcks, report); replayErr != nil {
					return status.Error(codes.FailedPrecondition, replayErr.Error())
				} else if ok {
					responseSequence++
					if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
						Stream:  responseStreamMetadata(responseSequence, g.now()),
						Payload: &agentv1.ConnectResponse_NodeMonitoringAck{NodeMonitoringAck: replayed},
					}); err != nil {
						return err
					}
					continue
				}
				ack, err := publishNodeMonitoringReport(stream.Context(), g.nodeMonitoring, identity.NodeID,
					report, nodeMonitoringLastSequence, g.now)
				if err != nil {
					return status.Error(codes.InvalidArgument, err.Error())
				}
				nodeMonitoringLastSequence = report.PublicationSequence
				if err := rememberNodeMonitoringAck(nodeMonitoringAcks, report, ack, g.config.MessageIDReplayWindow); err != nil {
					return status.Error(codes.ResourceExhausted, err.Error())
				}
				responseSequence++
				if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
					Stream:  responseStreamMetadata(responseSequence, g.now()),
					Payload: &agentv1.ConnectResponse_NodeMonitoringAck{NodeMonitoringAck: ack},
				}); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_L4LiveConnectionsResult:
				if !l4LiveEnabled {
					return status.Error(codes.PermissionDenied, "L4 live connections result is not negotiated")
				}
				if duplicate || l4Live == nil {
					continue
				}
				if err := l4Live.settle(payload.L4LiveConnectionsResult, identity.NodeID); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_MarketProbeResult:
				if !marketProbeEnabled {
					return status.Error(codes.PermissionDenied, "market probe result is not negotiated")
				}
				if duplicate || marketProbes == nil {
					continue
				}
				if err := marketProbes.settle(payload.MarketProbeResult, identity.NodeID); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_SecurityBanStatus:
				if !securityBansEnabled {
					return status.Error(codes.PermissionDenied, "security ban status is not negotiated")
				}
				// A replayed message was settled when first seen.
				if duplicate || securityBans == nil {
					continue
				}
				if securityBans.pending == nil {
					return status.Error(codes.FailedPrecondition, "security ban status without a pending list")
				}
				if err := g.settleSecurityBanStatus(stream.Context(), securityBans, identity.NodeID, payload.SecurityBanStatus); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_SiteDropReceipt:
				if !siteDropCapable || g.siteDrops == nil {
					return status.Error(codes.PermissionDenied, "site drop receipt is not negotiated")
				}
				// A replayed message was settled when first seen.
				if duplicate || siteDrops == nil {
					continue
				}
				if siteDrops.pending == nil {
					return status.Error(codes.FailedPrecondition, "site drop receipt without a pending list")
				}
				if err := g.settleSiteDropReceipt(stream.Context(), siteDrops, identity.NodeID, payload.SiteDropReceipt); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_GatewayAddressChangeReceipt:
				if !gatewayAddressCapable || g.gatewayAddresses == nil {
					return status.Error(codes.PermissionDenied, "gateway address change receipt is not negotiated")
				}
				if duplicate || gatewayAddresses == nil {
					continue
				}
				if gatewayAddresses.pending == nil {
					return status.Error(codes.FailedPrecondition, "gateway address change receipt without a pending document")
				}
				if err := g.settleGatewayAddressReceipt(stream.Context(), gatewayAddresses, identity.NodeID, payload.GatewayAddressChangeReceipt); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_AutoDefenseReceipt:
				if !autoDefenseEnabled {
					return status.Error(codes.PermissionDenied, "auto defense receipt is not negotiated")
				}
				// A replayed message was settled when first seen.
				if duplicate || autoDefense == nil {
					continue
				}
				if autoDefense.pending == nil {
					return status.Error(codes.FailedPrecondition, "auto defense receipt without a pending snapshot")
				}
				if err := g.settleAutoDefenseReceipt(stream.Context(), autoDefense, identity.NodeID, payload.AutoDefenseReceipt); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_AutoDefenseReport:
				if !autoDefenseEnabled {
					return status.Error(codes.PermissionDenied, "auto defense report is not negotiated")
				}
				// Display only: invalid, replayed or over-budget reports are dropped, never fatal.
				if duplicate || autoDefense == nil {
					continue
				}
				autoDefense.reports.offer(payload.AutoDefenseReport)
			case *agentv1.ConnectRequest_EdgeSignerTrustReceipt:
				if !signerTrustEnabled {
					return status.Error(codes.PermissionDenied, "edge signer trust receipt is not negotiated")
				}
				// A replayed message was settled when first seen.
				if duplicate || signerTrust == nil {
					continue
				}
				if signerTrust.pending == nil {
					return status.Error(codes.FailedPrecondition, "edge signer trust receipt has no pending bundle")
				}
				if err := g.settleSignerTrustReceipt(stream.Context(), signerTrust, identity.NodeID, payload.EdgeSignerTrustReceipt); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_InstallationBanReceipt:
				if !installationBanEnabled {
					return status.Error(codes.PermissionDenied, "installation ban receipt is not negotiated")
				}
				// A replayed message was settled when first seen.
				if duplicate || installationBan == nil {
					continue
				}
				if installationBan.pending == nil {
					return status.Error(codes.FailedPrecondition, "installation ban receipt has no pending command")
				}
				if err := g.settleInstallationBanReceipt(stream.Context(), installationBan, identity.NodeID, payload.InstallationBanReceipt); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_NodeMonitoringApplyStatus:
				if duplicate && pendingNodeMonitoring == nil {
					continue
				}
				if pendingNodeMonitoring == nil || pendingNodeMonitoringArtifact == nil ||
					validateNodeMonitoringApplyStatus(payload.NodeMonitoringApplyStatus, pendingNodeMonitoringArtifact, identity.NodeID) != nil {
					return status.Error(codes.FailedPrecondition, "node monitoring apply status is invalid")
				}
				operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
				if nodeMonitoringRejectionDisposition(payload.NodeMonitoringApplyStatus) == nodeMonitoringDispositionAck {
					err = pendingNodeMonitoring.Ack(operationCtx)
				} else {
					// Keep the session: closing it made a rejected revision
					// redeliver immediately on every reconnect.
					err = pendingNodeMonitoring.NakWithDelay(operationCtx, nodeMonitoringRejectedRetryDelay)
				}
				cancel()
				pendingNodeMonitoring = nil
				pendingNodeMonitoringArtifact = nil
				if err != nil {
					return status.Error(codes.Unavailable, "node monitoring artifact disposition failed")
				}
			case *agentv1.ConnectRequest_Heartbeat:
				heartbeat := payload.Heartbeat
				if err := g.validateHeartbeat(heartbeat, lease.Epoch(), heartbeatSequence, duplicate, agentVersion, activeIdentityCapable, multiTenantEnabled); err != nil {
					return status.Error(codes.InvalidArgument, err.Error())
				}
				if sessionSuperseded(lease) {
					return status.Error(codes.Aborted, "node session was superseded")
				}
				if err := g.persistHeartbeat(stream.Context(), identity.NodeID, heartbeat); err != nil {
					return err
				}
				if len(pendingReceiptConfirmations) != 0 {
					if err := g.advanceTerminalCommandReceiptConfirmations(
						stream.Context(), identity.NodeID, lease.Epoch(), request.Stream.Sequence, heartbeat, pendingReceiptConfirmations,
					); err != nil {
						return err
					}
				}
				if !duplicate {
					heartbeatSequence = heartbeat.HeartbeatSequence
					offlineDeadline = g.now().Add(g.config.OfflineAfter)
				}
				responseSequence++
				if sessionSuperseded(lease) {
					return status.Error(codes.Aborted, "node session was superseded")
				}
				err = sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
					Stream: responseStreamMetadata(responseSequence, g.now()),
					Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
						HeartbeatEventId: heartbeat.Event.EventId,
						SessionEpoch:     lease.Epoch(),
						ReceivedTime:     timestamppb.New(g.now()),
					}},
				})
				if err != nil {
					return err
				}
			case *agentv1.ConnectRequest_DeploymentStatus:
				if g.commands == nil || !deploymentsAllowed {
					return status.Error(codes.PermissionDenied, "deployment status is not authorized")
				}
				receipt, err := g.persistStatusAndAckCommandReceipt(
					stream.Context(), identity.NodeID, payload.DeploymentStatus, pendingCommands, activeIdentityCapable, ackReceiptCapable, multiTenantEnabled,
				)
				if err != nil {
					return err
				}
				if activeIdentityCapable && receipt != nil {
					if !ackReceiptCapable && g.receipts != nil {
						key := receipt.deploymentKey()
						if _, exists := pendingReceiptConfirmations[key]; !exists && len(pendingReceiptConfirmations) >= g.config.MaxPendingCommands {
							return status.Error(codes.ResourceExhausted, "deployment status acknowledgement confirmations exceed their limit")
						}
						if err := g.confirmTerminalCommandReceipt(
							stream.Context(), identity.NodeID, receipt.deploymentStatusAckReceipt(), lease.Epoch(), request.Stream.Sequence, false,
						); err != nil {
							return err
						}
						pendingReceiptConfirmations[key] = false
					} else if ackReceiptCapable {
						key := receipt.deploymentKey()
						if _, confirmed := pendingReceiptConfirmations[key]; !confirmed {
							awaitingReceiptConfirmations[key] = struct{}{}
						}
					}
					responseSequence++
					if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
						Stream: responseStreamMetadata(responseSequence, g.now()),
						Payload: &agentv1.ConnectResponse_DeploymentStatusAck{
							DeploymentStatusAck: receipt.deploymentStatusAck(),
						},
					}); err != nil {
						return err
					}
				}
			case *agentv1.ConnectRequest_DeploymentStatusAckReceipt:
				if !ackReceiptCapable || g.receipts == nil {
					return status.Error(codes.PermissionDenied, "deployment status acknowledgement receipt is not negotiated")
				}
				key := deploymentKey{
					deploymentID:  payload.DeploymentStatusAckReceipt.GetDeploymentId(),
					attempt:       payload.DeploymentStatusAckReceipt.GetAttempt(),
					configVersion: payload.DeploymentStatusAckReceipt.GetConfigVersionId(),
				}
				if _, exists := pendingReceiptConfirmations[key]; !exists && len(pendingReceiptConfirmations) >= g.config.MaxPendingCommands {
					return status.Error(codes.ResourceExhausted, "deployment status acknowledgement confirmations exceed their limit")
				}
				if err := g.confirmTerminalCommandReceipt(
					stream.Context(), identity.NodeID, payload.DeploymentStatusAckReceipt, lease.Epoch(), request.Stream.Sequence, true,
				); err != nil {
					return err
				}
				pendingReceiptConfirmations[key] = false
				delete(awaitingReceiptConfirmations, key)
			case *agentv1.ConnectRequest_AcmeHttp01OverlayStatus:
				if g.overlays == nil || !acmeHTTP01OverlayCapable {
					return status.Error(codes.PermissionDenied, "overlay deployment status is not authorized")
				}
				if err := g.persistOverlayStatusAndAckCommand(stream.Context(), identity.NodeID, payload.AcmeHttp01OverlayStatus, pendingOverlays); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_CacheControlStatus:
				if g.cache == nil || !cacheCommandsAllowed {
					return status.Error(codes.PermissionDenied, "cache control status is not authorized")
				}
				if cacheControlMessageHasUnknown(request.ProtoReflect()) {
					return status.Error(codes.InvalidArgument, "cache control status contains unknown fields")
				}
				ack, err := g.persistCacheStatusAndAckCommand(stream.Context(), identity.NodeID, payload.CacheControlStatus, pendingCacheCommands)
				if err != nil {
					return err
				}
				responseSequence++
				if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
					Stream: responseStreamMetadata(responseSequence, g.now()),
					Payload: &agentv1.ConnectResponse_CacheControlStatusAck{
						CacheControlStatusAck: ack,
					},
				}); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_CacheControlCancelReceipt:
				if g.cache == nil || !cacheCancelCapable {
					return status.Error(codes.PermissionDenied, "cache cancel receipt is not authorized")
				}
				if err := g.settleCacheCancelReceipt(stream.Context(), identity.NodeID, payload.CacheControlCancelReceipt, pendingCacheCancels); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_UpgradeStatus:
				if g.upgrades == nil || !upgradeCommandsAllowed || payload.UpgradeStatus == nil {
					return status.Error(codes.PermissionDenied, "upgrade status is not authorized")
				}
				if cacheControlMessageHasUnknown(request.ProtoReflect()) {
					return status.Error(codes.InvalidArgument, "upgrade status contains unknown fields")
				}
				statusDigest := sha256.Sum256(payload.UpgradeStatus.Status)
				if len(payload.UpgradeStatus.StatusSha256) != sha256.Size || !bytes.Equal(statusDigest[:], payload.UpgradeStatus.StatusSha256) {
					return status.Error(codes.InvalidArgument, "upgrade status digest is invalid")
				}
				var ack *agentv1.UpgradeStatusAck
				operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
				operationErr := lease.FencedSend(func() error {
					var err error
					ack, err = g.persistUpgradeStatusAndAckCommand(operationCtx, identity.NodeID, installationID,
						payload.UpgradeStatus.Status, pendingUpgradeCommands, upgradeStatusPubAckCapable,
						upgradeStatusAckReceiptCapable)
					return err
				})
				cancel()
				if errors.Is(operationErr, ErrSessionSuperseded) {
					return status.Error(codes.Aborted, "node session was superseded")
				}
				if operationErr != nil {
					return operationErr
				}
				if ack == nil {
					continue
				}
				responseSequence++
				if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
					Stream:  responseStreamMetadata(responseSequence, g.now()),
					Payload: &agentv1.ConnectResponse_UpgradeStatusAck{UpgradeStatusAck: ack},
				}); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_UpgradeStatusAckReceipt:
				if !upgradeStatusAckReceiptCapable || g.upgradeReceipts == nil || payload.UpgradeStatusAckReceipt == nil {
					return status.Error(codes.PermissionDenied, "upgrade status acknowledgement receipt is not negotiated")
				}
				if cacheControlMessageHasUnknown(request.ProtoReflect()) ||
					validateUpgradeStatusAckReceiptShape(payload.UpgradeStatusAckReceipt) != nil {
					return status.Error(codes.InvalidArgument, "upgrade status acknowledgement receipt is invalid")
				}
				operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
				confirmed, confirmErr := g.upgradeReceipts.confirmUpgradeStatusAck(
					operationCtx, identity.NodeID, payload.UpgradeStatusAckReceipt, g.config.MaxPendingCommands,
				)
				cancel()
				if confirmErr != nil {
					switch {
					case errors.Is(confirmErr, errUpgradeStatusAckConflict), errors.Is(confirmErr, errUpgradeStatusAckNotFound):
						return status.Error(codes.FailedPrecondition, "upgrade status acknowledgement receipt conflicts with durable state")
					default:
						return status.Error(codes.Unavailable, "upgrade status acknowledgement receipt could not be persisted")
					}
				}
				responseSequence++
				if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
					Stream: responseStreamMetadata(responseSequence, g.now()),
					Payload: &agentv1.ConnectResponse_UpgradeStatusAckReceipt{
						UpgradeStatusAckReceipt: confirmed,
					},
				}); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_FirewallStatus:
				if !firewallCommandsAllowed || payload.FirewallStatus == nil {
					return status.Error(codes.PermissionDenied, "firewall status is not authorized")
				}
				if err := g.persistFirewallStatusAndAckCommand(stream.Context(), identity.NodeID,
					payload.FirewallStatus, pendingFirewallCommands, duplicate); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_DrainStatus:
				if !drainCommandsAllowed || payload.DrainStatus == nil {
					return status.Error(codes.PermissionDenied, "drain status is not authorized")
				}
				if err := g.persistDrainStatusAndAdvance(stream.Context(), identity.NodeID, payload.DrainStatus, pendingDrainCommands); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_GatewayPortTransitionStatus:
				if !portTransitionsAllowed || payload.GatewayPortTransitionStatus == nil {
					return status.Error(codes.PermissionDenied, "gateway port transition status is not authorized")
				}
				if err := g.persistPortTransitionStatus(stream.Context(), identity.NodeID, certificateIdentityHex(identity),
					payload.GatewayPortTransitionStatus, pendingPortTransitions); err != nil {
					return err
				}
			default:
				return status.Error(codes.InvalidArgument, "unsupported session payload")
			}
		case delivered := <-commandReceive:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			commandSource.next = nil
			if delivered.err != nil {
				return status.Error(codes.Unavailable, "node command delivery failed")
			}
			if g.revocation != nil && g.revocation.CertificateRevoked(identity.NodeID, identity.SerialNumber, 1) {
				nakCommand(delivered.delivery, g.config.CommandOperationTimeout)
				continue
			}
			command := delivered.delivery.Command()
			if err := g.validateDeploymentCommand(command, artifactEncryptionKeyID, activeIdentityCapable); err != nil {
				nakCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return status.Error(codes.InvalidArgument, "durable deployment command is invalid")
			}
			if activeIdentityCapable && g.receipts != nil {
				operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
				receipt, err := g.receipts.loadTerminalCommandReceipt(operationCtx, identity.NodeID, commandKey(command))
				cancel()
				if err != nil {
					nakCommand(delivered.delivery, g.config.CommandOperationTimeout)
					return status.Error(codes.Unavailable, "terminal command receipt could not be loaded")
				}
				if receipt != nil {
					if err := validateTerminalCommandReceiptCommand(receipt, command, []CommandDelivery{delivered.delivery}); err != nil {
						nakCommand(delivered.delivery, g.config.CommandOperationTimeout)
						return status.Error(codes.FailedPrecondition, err.Error())
					}
					operationCtx, cancel = context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
					err = delivered.delivery.Ack(operationCtx)
					cancel()
					if err != nil {
						return status.Error(codes.Unavailable, "completed deployment command could not be acknowledged")
					}
					continue
				}
			}
			key := commandKey(command)
			previous, exists := pendingCommands[key]
			if exists && !proto.Equal(previous.command, command) {
				nakCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return status.Error(codes.FailedPrecondition, "deployment command identity conflicts with an in-flight command")
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_DeploymentCommand{DeploymentCommand: command},
			}); err != nil {
				nakCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return err
			}
			if exists {
				previous.deliveries = append(previous.deliveries, delivered.delivery)
			} else {
				pendingCommands[key] = &pendingCommand{command: command, deliveries: []CommandDelivery{delivered.delivery}}
			}
		case delivered := <-overlayReceive:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			overlaySource.next = nil
			if delivered.err != nil {
				return status.Error(codes.Unavailable, "node overlay command delivery failed")
			}
			command := delivered.delivery.Command()
			if err := g.validateACMEHTTP01OverlayCommand(command); err != nil {
				nakOverlayCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return status.Error(codes.InvalidArgument, "durable overlay command is invalid")
			}
			key := overlayCommandKey(command)
			previous, exists := pendingOverlays[key]
			if exists && !proto.Equal(previous.command, command) {
				nakOverlayCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return status.Error(codes.FailedPrecondition, "overlay command identity conflicts with an in-flight command")
			}
			if exists {
				previous.deliveries = append(previous.deliveries, delivered.delivery)
			} else {
				pendingOverlays[key] = &pendingOverlayCommand{command: command, deliveries: []OverlayCommandDelivery{delivered.delivery}}
			}
			if !acmeHTTP01OverlayCapable {
				if err := g.persistOverlayStatusAndAckCommand(stream.Context(), identity.NodeID,
					unsupportedACMEHTTP01OverlayStatus(command, g.now()), pendingOverlays); err != nil {
					return err
				}
				continue
			}
			if !deploymentsAllowed && command.Purpose != agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_CLEANUP_ONLY {
				if err := g.persistOverlayStatusAndAckCommand(stream.Context(), identity.NodeID,
					applyRefusedACMEHTTP01OverlayStatus(command, g.now()), pendingOverlays); err != nil {
					return err
				}
				continue
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream: responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_AcmeHttp01OverlayCommand{
					AcmeHttp01OverlayCommand: command,
				},
			}); err != nil {
				nakOverlayCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return err
			}
		case delivered := <-cacheCommandReceive:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			cacheCommandSource.next = nil
			if delivered.err != nil {
				return status.Error(codes.Unavailable, "node cache command delivery failed")
			}
			if cancel := delivered.delivery.Cancel(); cancel != nil {
				if !cacheCancelCapable {
					// An older Agent cannot stop the task: the cancel stays
					// queued until a session that negotiated it (the control
					// plane records the node as not responding meanwhile).
					nakCacheCommand(delivered.delivery, g.config.CommandOperationTimeout)
					continue
				}
				if err := g.validateCacheControlCancel(cancel, identity.NodeID); err != nil {
					nakCacheCommand(delivered.delivery, g.config.CommandOperationTimeout)
					return status.Error(codes.InvalidArgument, "durable cache cancel is invalid")
				}
				responseSequence++
				if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
					Stream:  responseStreamMetadata(responseSequence, g.now()),
					Payload: &agentv1.ConnectResponse_CacheControlCancel{CacheControlCancel: cancel},
				}); err != nil {
					nakCacheCommand(delivered.delivery, g.config.CommandOperationTimeout)
					return err
				}
				if entry := pendingCacheCancels[cancel.CancelId]; entry != nil {
					entry.deliveries = append(entry.deliveries, delivered.delivery)
				} else {
					pendingCacheCancels[cancel.CancelId] = &pendingCacheCancel{cancel: cancel, deliveries: []CacheCommandDelivery{delivered.delivery}}
				}
				continue
			}
			command := delivered.delivery.Command()
			if err := g.validateCacheControlCommand(command, identity.NodeID); err != nil {
				nakCacheCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return status.Error(codes.InvalidArgument, "durable cache command is invalid")
			}
			key := cacheCommandIdentity(command)
			previous, exists := pendingCacheCommands[key]
			if exists && !proto.Equal(previous.command, command) {
				nakCacheCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return status.Error(codes.FailedPrecondition, "cache command identity conflicts with an in-flight command")
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_CacheControlCommand{CacheControlCommand: command},
			}); err != nil {
				nakCacheCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return err
			}
			if exists {
				previous.deliveries = append(previous.deliveries, delivered.delivery)
			} else {
				pendingCacheCommands[key] = &pendingCacheCommand{command: command, deliveries: []CacheCommandDelivery{delivered.delivery}}
			}
		case delivered := <-upgradeCommandReceive:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			upgradeCommandSource.next = nil
			if delivered.err != nil {
				return status.Error(codes.Unavailable, "node upgrade command delivery failed")
			}
			command := delivered.delivery.Command()
			if command.NodeID != identity.NodeID || command.InstallationID != installationID {
				nakUpgradeCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return status.Error(codes.InvalidArgument, "durable upgrade command is invalid")
			}
			if upgradeStatusAckReceiptCapable && g.upgradeReceipts != nil {
				operationCtx, cancel := context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
				completed, completionErr := g.upgradeReceipts.hasCompletedUpgradeCommand(
					operationCtx, command, g.config.MaxPendingCommands,
				)
				cancel()
				if completionErr != nil {
					nakUpgradeCommand(delivered.delivery, g.config.CommandOperationTimeout)
					if errors.Is(completionErr, errUpgradeStatusAckConflict) {
						return status.Error(codes.FailedPrecondition, "completed upgrade command conflicts with durable state")
					}
					return status.Error(codes.Unavailable, "completed upgrade command could not be loaded")
				}
				if completed {
					operationCtx, cancel = context.WithTimeout(stream.Context(), g.config.CommandOperationTimeout)
					ackErr := delivered.delivery.Ack(operationCtx)
					cancel()
					if ackErr != nil {
						return status.Error(codes.Unavailable, "completed upgrade command could not be acknowledged")
					}
					continue
				}
			}
			previous, exists := pendingUpgradeCommands[command.CommandID]
			if exists && (previous.command.SHA256 != command.SHA256 || !bytes.Equal(previous.command.Encoded, command.Encoded)) {
				nakUpgradeCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return status.Error(codes.FailedPrecondition, "upgrade command conflicts with an in-flight command")
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream: responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_UpgradeCommand{UpgradeCommand: &agentv1.UpgradeCommand{
					Command: append([]byte(nil), command.Encoded...), CommandSha256: append([]byte(nil), command.SHA256[:]...),
				}},
			}); err != nil {
				nakUpgradeCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return err
			}
			if exists {
				previous.deliveries = append(previous.deliveries, delivered.delivery)
			} else {
				pendingUpgradeCommands[command.CommandID] = &pendingUpgradeCommand{command: command, deliveries: []UpgradeCommandDelivery{delivered.delivery}}
			}
		case delivered := <-firewallCommandReceive:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			firewallCommandSource.next = nil
			if delivered.err != nil {
				return status.Error(codes.Unavailable, "node firewall command delivery failed")
			}
			command := delivered.delivery.Command()
			if err := validateFirewallCommand(command, identity.NodeID); err != nil {
				nakFirewallCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return status.Error(codes.InvalidArgument, "durable firewall command is invalid")
			}
			key := firewallCommandIdentity(command)
			previous, exists := pendingFirewallCommands[key]
			if exists && !proto.Equal(previous.command, command) {
				nakFirewallCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return status.Error(codes.FailedPrecondition, "firewall command identity conflicts with an in-flight command")
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream: responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_FirewallCommand{
					FirewallCommand: command,
				},
			}); err != nil {
				nakFirewallCommand(delivered.delivery, g.config.CommandOperationTimeout)
				return err
			}
			if exists {
				previous.deliveries = append(previous.deliveries, delivered.delivery)
			} else {
				pendingFirewallCommands[key] = &pendingFirewallCommand{command: command,
					deliveries: []FirewallCommandDelivery{delivered.delivery}}
			}
		case delivered := <-drainCommandReceive:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			drainCommandSource.next = nil
			if delivered.err != nil {
				return status.Error(codes.Unavailable, "node drain command delivery failed")
			}
			command := delivered.delivery.Command()
			if err := validateDrainCommand(command, identity.NodeID, g.now()); err != nil {
				retryDrainCommand(delivered.delivery, g.config.CommandOperationTimeout, time.Second)
				return status.Error(codes.InvalidArgument, "durable drain command is invalid")
			}
			previous, exists := pendingDrainCommands[command.CommandId]
			if exists && !proto.Equal(previous.command, command) {
				retryDrainCommand(delivered.delivery, g.config.CommandOperationTimeout, time.Second)
				return status.Error(codes.FailedPrecondition, "drain command identity conflicts with an in-flight command")
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{
				Stream:  responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_DrainCommand{DrainCommand: command},
			}); err != nil {
				retryDrainCommand(delivered.delivery, g.config.CommandOperationTimeout, time.Second)
				return err
			}
			if exists {
				previous.deliveries = append(previous.deliveries, delivered.delivery)
			} else {
				pendingDrainCommands[command.CommandId] = &pendingDrainCommand{command: command,
					deliveries: []DrainCommandDelivery{delivered.delivery}}
			}
		case delivered := <-portTransitionReceive:
			stopTimer(authorizationTimer)
			stopTimer(offlineTimer)
			portTransitionSource.next = nil
			if delivered.err != nil {
				return status.Error(codes.Unavailable, "gateway port transition delivery failed")
			}
			command := delivered.delivery.Command()
			if err := validateGatewayPortTransitionCommand(command, g.now()); err != nil || command.NodeId != identity.NodeID || command.CertificateSha256 != certificateIdentityHex(identity) {
				retryPortTransition(delivered.delivery, g.config.CommandOperationTimeout, time.Second)
				return status.Error(codes.InvalidArgument, "durable gateway port transition is invalid")
			}
			var prepared *agentv1.GatewayPortTransitionCommand
			var err error
			if command.Action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH {
				prepared, err = g.portManager.Prepare(stream.Context(), command)
			} else {
				prepared, err = g.portManager.ValidateAction(command)
			}
			if err != nil {
				retryPortTransition(delivered.delivery, g.config.CommandOperationTimeout, time.Second)
				return status.Error(codes.Unavailable, "gateway port transition listener could not be prepared")
			}
			previous, exists := pendingPortTransitions[command.TransitionId]
			if exists && !proto.Equal(previous.command, command) {
				retryPortTransition(delivered.delivery, g.config.CommandOperationTimeout, time.Second)
				return status.Error(codes.FailedPrecondition, "gateway port transition conflicts with an in-flight command")
			}
			responseSequence++
			if err := sendSessionResponse(lease, stream, &agentv1.ConnectResponse{Stream: responseStreamMetadata(responseSequence, g.now()),
				Payload: &agentv1.ConnectResponse_GatewayPortTransitionCommand{GatewayPortTransitionCommand: prepared}}); err != nil {
				retryPortTransition(delivered.delivery, g.config.CommandOperationTimeout, time.Second)
				return err
			}
			if exists {
				previous.deliveries = append(previous.deliveries, delivered.delivery)
			} else {
				pendingPortTransitions[command.TransitionId] = &pendingPortTransition{command: command, deliveries: []PortTransitionCommandDelivery{delivered.delivery}}
			}
		}
	}
}

func (g *Gateway) applyPortTransitionAuthorization(ctx context.Context, nodeID string, source *sessionPortTransitionSource,
	pending pendingPortTransitionSet, wasAllowed, isAllowed bool,
) (*sessionPortTransitionSource, error) {
	if g.portTransitions == nil || wasAllowed == isAllowed {
		return source, nil
	}
	if !isAllowed {
		stopSessionPortTransitions(source, pending, g.config.CommandOperationTimeout)
		return nil, nil
	}
	created, err := newSessionPortTransitionSource(ctx, g.portTransitions, nodeID)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "could not subscribe to gateway port transitions")
	}
	return created, nil
}

func (g *Gateway) persistHeartbeat(ctx context.Context, nodeID string, heartbeat *agentv1.Heartbeat) error {
	if g.heartbeats == nil {
		return nil
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.HeartbeatPersistTimeout)
	err := g.heartbeats.PersistHeartbeat(operationCtx, nodeID, heartbeat)
	cancel()
	if err != nil {
		return status.Error(codes.Unavailable, "heartbeat could not be persisted")
	}
	return nil
}

type refreshedSessionAuthorization struct {
	refreshAt          time.Time
	deploymentsAllowed bool
}

func (g *Gateway) refreshSessionAuthorization(
	ctx context.Context,
	identity nodeIdentity,
	agentVersions *commonv1.ProtocolVersionRange,
	selectedVersion *commonv1.ProtocolVersion,
	artifactEncryptionKeyID string,
	offlineDeadline time.Time,
	installationIDs ...string,
) (refreshedSessionAuthorization, error) {
	installationID := ""
	if len(installationIDs) != 0 {
		installationID = installationIDs[0]
	}
	refreshContext, cancel := context.WithDeadline(ctx, offlineDeadline)
	authorization, err := g.authorizeConnection(refreshContext, identity, nil)
	cancel()
	if err != nil {
		if !g.now().Before(offlineDeadline) {
			return refreshedSessionAuthorization{}, status.Error(codes.DeadlineExceeded, "node heartbeat deadline exceeded")
		}
		return refreshedSessionAuthorization{}, err
	}
	if _, ok := negotiateVersion(
		&commonv1.ProtocolVersionRange{Minimum: selectedVersion, Maximum: selectedVersion},
		agentVersions,
		g.config.SupportedVersions,
		authorization.AcceptedProtocolVersions,
	); !ok {
		return refreshedSessionAuthorization{}, status.Error(codes.FailedPrecondition, "active protocol version is no longer authorized")
	}
	if authorization.ArtifactEncryptionKeyId != artifactEncryptionKeyID {
		return refreshedSessionAuthorization{}, status.Error(codes.FailedPrecondition, "artifact encryption key authorization changed")
	}
	if installationID != "" && authorization.InstallationId != installationID {
		return refreshedSessionAuthorization{}, status.Error(codes.FailedPrecondition, "installation authorization changed")
	}
	return refreshedSessionAuthorization{
		refreshAt:          refreshAt(g.now(), authorization.SnapshotExpirationTime.AsTime()),
		deploymentsAllowed: authorization.DeploymentsAllowed,
	}, nil
}

func (g *Gateway) applyDeploymentAuthorization(
	ctx context.Context,
	nodeID string,
	source *sessionCommandSource,
	pending pendingCommandSet,
	wasAllowed bool,
	isAllowed bool,
) (*sessionCommandSource, error) {
	if g.commands == nil || wasAllowed == isAllowed {
		return source, nil
	}
	if !isAllowed {
		stopSessionCommands(source, pending, g.config.CommandOperationTimeout)
		return nil, nil
	}
	created, err := newSessionCommandSource(ctx, g.commands, nodeID)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "could not subscribe to node commands")
	}
	return created, nil
}

func (g *Gateway) applyFirewallAuthorization(
	ctx context.Context,
	nodeID string,
	source *sessionFirewallCommandSource,
	pending pendingFirewallCommandSet,
	wasAllowed bool,
	isAllowed bool,
) (*sessionFirewallCommandSource, error) {
	if g.firewall == nil || wasAllowed == isAllowed {
		return source, nil
	}
	if !isAllowed {
		stopSessionFirewallCommands(source, pending, g.config.CommandOperationTimeout)
		return nil, nil
	}
	created, err := newSessionFirewallCommandSource(ctx, g.firewall, nodeID)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "could not subscribe to node firewall commands")
	}
	return created, nil
}

func (g *Gateway) persistStatusAndAckCommand(ctx context.Context, nodeID string, deploymentStatus *agentv1.DeploymentStatus, pending pendingCommandSet, activeIdentityCapability ...bool) error {
	_, err := g.persistStatusAndAckCommandReceipt(ctx, nodeID, deploymentStatus, pending, activeIdentityCapability...)
	return err
}

func (g *Gateway) persistFirewallStatusAndAckCommand(
	ctx context.Context,
	nodeID string,
	firewallStatus *agentv1.FirewallStatus,
	pending pendingFirewallCommandSet,
	duplicate bool,
) error {
	if g.firewall == nil {
		return status.Error(codes.PermissionDenied, "firewall status is not authorized")
	}
	key := firewallStatusCommandIdentity(firewallStatus)
	command, exists := pending[key]
	if !exists {
		if !duplicate || validateFirewallStatusEnvelope(firewallStatus, nodeID) != nil {
			return status.Error(codes.FailedPrecondition, "firewall status has no matching in-flight command")
		}
		operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		publication, err := g.firewall.PublishFirewallStatus(operationCtx, nodeID, firewallStatus)
		cancel()
		if err != nil {
			return status.Error(codes.Unavailable, "firewall status could not be persisted")
		}
		if !publication.Replayed || publication.Stream == "" || publication.Sequence == 0 {
			return status.Error(codes.FailedPrecondition, "firewall status replay conflicts with durable state")
		}
		return nil
	}
	if err := validateFirewallStatus(firewallStatus, command.command, nodeID); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	publication, err := g.firewall.PublishFirewallStatus(operationCtx, nodeID, firewallStatus)
	cancel()
	if err != nil {
		return status.Error(codes.Unavailable, "firewall status could not be persisted")
	}
	if publication.Stream == "" || publication.Sequence == 0 {
		return status.Error(codes.Unavailable, "firewall status persistence returned an invalid acknowledgement")
	}
	for _, delivery := range command.deliveries {
		operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		err = delivery.Ack(operationCtx)
		cancel()
		if err != nil {
			return status.Error(codes.Unavailable, "firewall command could not be acknowledged")
		}
	}
	delete(pending, key)
	return nil
}

// persistStatusAndAckCommandReceipt takes (activeIdentityEnabled,
// ackReceiptEnabled, multiTenantEnabled); only the first and last are read here.
func (g *Gateway) persistStatusAndAckCommandReceipt(ctx context.Context, nodeID string, deploymentStatus *agentv1.DeploymentStatus, pending pendingCommandSet, activeIdentityCapability ...bool) (*terminalCommandReceipt, error) {
	activeIdentityEnabled := len(activeIdentityCapability) >= 1 && activeIdentityCapability[0]
	multiTenantEnabled := len(activeIdentityCapability) >= 3 && activeIdentityCapability[2]
	if err := g.validateDeploymentStatus(deploymentStatus, activeIdentityEnabled, multiTenantEnabled); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	key := statusKey(deploymentStatus)
	command, exists := pending[key]
	if exists && multiTenantEnabled {
		if err := validateDeploymentStatusScopeCommandBinding(deploymentStatus, command.command); err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
	}
	receiptEnabled := activeIdentityEnabled && g.receipts != nil
	if receiptEnabled && terminalDeploymentStatus(deploymentStatus.State) {
		operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		receipt, err := g.receipts.loadTerminalCommandReceipt(operationCtx, nodeID, key)
		cancel()
		if err != nil {
			return nil, status.Error(codes.Unavailable, "terminal command receipt could not be loaded")
		}
		if receipt != nil {
			if err := validateTerminalCommandReceiptStatus(receipt, deploymentStatus); err != nil {
				return nil, status.Error(codes.FailedPrecondition, err.Error())
			}
			if exists {
				if err := validateTerminalCommandReceiptCommand(receipt, command.command, command.deliveries); err != nil {
					return nil, status.Error(codes.FailedPrecondition, err.Error())
				}
				for len(command.deliveries) > 0 {
					delivery := command.deliveries[0]
					operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
					err = delivery.Ack(operationCtx)
					cancel()
					if err != nil {
						return nil, status.Error(codes.Unavailable, "deployment command could not be acknowledged")
					}
					command.deliveries = command.deliveries[1:]
				}
				delete(pending, key)
			}
			return receipt, nil
		}
	}
	if activeIdentityEnabled && terminalDeploymentStatus(deploymentStatus.State) && exists {
		if err := validateDeploymentStatusActiveIdentityCommandBinding(deploymentStatus, command.command); err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
	}
	if activeIdentityEnabled && terminalDeploymentStatus(deploymentStatus.State) && !exists {
		if deploymentStatus.ActiveConfigIdentity != nil {
			return nil, status.Error(codes.FailedPrecondition, "deployment status active config identity has no authoritative command")
		}
		return nil, nil
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	publication, err := g.commands.PublishStatus(operationCtx, nodeID, deploymentStatus)
	cancel()
	if err != nil || publication.Stream == "" || publication.Sequence == 0 {
		return nil, status.Error(codes.Unavailable, "deployment status could not be persisted")
	}
	if !exists {
		return nil, nil
	}
	if activeIdentityEnabled {
		switch deploymentStatus.State {
		case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY:
			if deploymentStatus.ActiveConfigIdentity == nil {
				if len(command.command.Artifacts) != 1 || command.command.Artifacts[0] == nil ||
					command.command.Artifacts[0].Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE &&
						!nodeArtifactSetMediaType(command.command.Artifacts[0].MediaType) {
					return nil, nil
				}
			}
		case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED:
		default:
			return nil, nil
		}
		if len(command.deliveries) == 0 {
			return nil, nil
		}
	}
	var receipt *terminalCommandReceipt
	if receiptEnabled {
		candidate, err := newTerminalCommandReceipt(
			nodeID, command.command, deploymentStatus, command.deliveries, g.now(), publication,
		)
		if err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		receipt, err = g.receipts.saveTerminalCommandReceipt(operationCtx, candidate)
		cancel()
		if err != nil {
			return nil, status.Error(codes.Unavailable, "terminal command receipt could not be persisted")
		}
		if receipt == nil {
			return nil, status.Error(codes.Unavailable, "terminal command receipt persistence returned no receipt")
		}
	}
	for len(command.deliveries) > 0 {
		delivery := command.deliveries[0]
		operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		err = delivery.Ack(operationCtx)
		cancel()
		if err != nil {
			return nil, status.Error(codes.Unavailable, "deployment command could not be acknowledged")
		}
		command.deliveries = command.deliveries[1:]
	}
	delete(pending, key)
	if receipt == nil {
		receipt = terminalCommandReceiptForStatus(deploymentStatus, g.now(), publication)
	}
	return receipt, nil
}

// nodeArtifactSetMediaType: a node artifact set or segment deployment
// (ARTIFACT_SET v1) never becomes the running configuration, so its healthy
// status has no active config identity.
func nodeArtifactSetMediaType(mediaType string) bool {
	return mediaType == artifactset.MediaTypeSet || mediaType == artifactset.MediaTypeSegment
}

func terminalDeploymentStatus(state agentv1.NodeDeploymentState) bool {
	switch state {
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED:
		return true
	default:
		return false
	}
}

func terminalCommandReceiptForStatus(value *agentv1.DeploymentStatus, persisted time.Time, publications ...DeploymentStatusPublication) *terminalCommandReceipt {
	receipt := &terminalCommandReceipt{
		StatusEventID: value.GetEvent().GetEventId(), DeploymentID: value.GetDeploymentId(), Attempt: value.GetAttempt(),
		ConfigVersionID: value.GetConfigVersionId(), TransitionSequence: value.GetTransitionSequence(),
		PersistedUnixNano: persisted.UTC().UnixNano(),
	}
	if len(publications) == 1 {
		receipt.PublishedStream = publications[0].Stream
		receipt.PublishedSequence = publications[0].Sequence
	}
	return receipt
}

func (r *terminalCommandReceipt) deploymentStatusAck() *agentv1.DeploymentStatusAck {
	if r == nil {
		return nil
	}
	return &agentv1.DeploymentStatusAck{
		StatusEventId: r.StatusEventID, DeploymentId: r.DeploymentID, Attempt: r.Attempt,
		ConfigVersionId: r.ConfigVersionID, TransitionSequence: r.TransitionSequence,
		PersistedTime:   timestamppb.New(time.Unix(0, r.PersistedUnixNano).UTC()),
		PublishedStream: r.PublishedStream, PublishedSequence: r.PublishedSequence,
	}
}

func (r *terminalCommandReceipt) deploymentStatusAckReceipt() *agentv1.DeploymentStatusAckReceipt {
	if r == nil {
		return nil
	}
	return &agentv1.DeploymentStatusAckReceipt{
		StatusEventId: r.StatusEventID, DeploymentId: r.DeploymentID, Attempt: r.Attempt,
		ConfigVersionId: r.ConfigVersionID, TransitionSequence: r.TransitionSequence,
		PersistedTime:   timestamppb.New(time.Unix(0, r.PersistedUnixNano).UTC()),
		PublishedStream: r.PublishedStream, PublishedSequence: r.PublishedSequence,
	}
}

func (g *Gateway) confirmTerminalCommandReceipt(
	ctx context.Context,
	nodeID string,
	value *agentv1.DeploymentStatusAckReceipt,
	sessionEpoch uint64,
	streamSequence uint64,
	agentReceiptPersisted bool,
) error {
	if value == nil || cacheControlMessageHasUnknown(value.ProtoReflect()) || !canonicalUUID(value.StatusEventId) ||
		!canonicalUUID(value.DeploymentId) || value.Attempt == 0 || !canonicalUUID(value.ConfigVersionId) ||
		value.TransitionSequence == 0 || value.PersistedTime == nil || value.PersistedTime.CheckValid() != nil ||
		sessionEpoch == 0 || streamSequence == 0 {
		return status.Error(codes.InvalidArgument, "deployment status acknowledgement receipt is invalid")
	}
	key := deploymentKey{deploymentID: value.DeploymentId, attempt: value.Attempt, configVersion: value.ConfigVersionId}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	receipt, err := g.receipts.loadTerminalCommandReceipt(operationCtx, nodeID, key)
	cancel()
	if err != nil {
		return status.Error(codes.Unavailable, "terminal command receipt could not be loaded")
	}
	operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	confirmation, confirmationErr := g.receipts.loadTerminalCommandReceiptConfirmation(operationCtx, nodeID, key)
	cancel()
	if confirmationErr != nil {
		return status.Error(codes.Unavailable, "terminal command receipt confirmation could not be loaded")
	}
	if confirmation != nil && validateTerminalCommandReceiptConfirmation(confirmation) != nil {
		return status.Error(codes.FailedPrecondition, "terminal command receipt confirmation is invalid")
	}
	if receipt == nil && confirmation != nil {
		receipt = &confirmation.Receipt
	}
	if receipt == nil || !proto.Equal(receipt.deploymentStatusAckReceipt(), value) {
		return status.Error(codes.FailedPrecondition, "deployment status acknowledgement receipt does not match durable state")
	}
	if confirmation != nil && confirmation.Receipt != *receipt {
		return status.Error(codes.FailedPrecondition, "deployment status acknowledgement receipt conflicts with its confirmation")
	}
	candidate := &terminalCommandReceiptConfirmation{
		Version: terminalCommandReceiptConfirmationVersion, Receipt: *receipt,
		SessionEpoch: sessionEpoch, ReceiptStreamSequence: streamSequence,
		AgentReceiptPersisted: agentReceiptPersisted || confirmation != nil && confirmation.AgentReceiptPersisted,
	}
	if confirmation != nil && confirmation.SessionEpoch == sessionEpoch && confirmation.ReceiptStreamSequence == streamSequence &&
		(!agentReceiptPersisted || confirmation.AgentReceiptPersisted) {
		return nil
	}
	operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	persisted, err := g.receipts.saveTerminalCommandReceiptConfirmation(operationCtx, candidate)
	cancel()
	if err != nil {
		return status.Error(codes.Unavailable, "terminal command receipt confirmation could not be persisted")
	}
	if persisted == nil || *persisted != *candidate {
		return status.Error(codes.Unavailable, "terminal command receipt confirmation persistence returned inconsistent state")
	}
	return nil
}

func (g *Gateway) advanceTerminalCommandReceiptConfirmations(
	ctx context.Context,
	nodeID string,
	sessionEpoch uint64,
	heartbeatStreamSequence uint64,
	heartbeat *agentv1.Heartbeat,
	pending map[deploymentKey]bool,
) error {
	if heartbeat == nil || heartbeat.Event == nil || !canonicalUUID(heartbeat.Event.EventId) {
		return status.Error(codes.InvalidArgument, "terminal command receipt heartbeat proof is invalid")
	}
	for key, recovered := range pending {
		operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		confirmation, err := g.receipts.loadTerminalCommandReceiptConfirmation(operationCtx, nodeID, key)
		cancel()
		if err != nil {
			return status.Error(codes.Unavailable, "terminal command receipt confirmation could not be loaded")
		}
		if confirmation == nil || validateTerminalCommandReceiptConfirmation(confirmation) != nil {
			return status.Error(codes.FailedPrecondition, "terminal command receipt confirmation is invalid")
		}
		if recovered || confirmation.SessionEpoch != sessionEpoch {
			if !confirmation.AgentReceiptPersisted {
				continue
			}
			candidate := *confirmation
			candidate.SessionEpoch = sessionEpoch
			candidate.ReceiptStreamSequence = heartbeatStreamSequence
			candidate.HeartbeatBarrierSequence = heartbeatStreamSequence
			candidate.HeartbeatBarrierEventID = heartbeat.Event.EventId
			operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
			persisted, saveErr := g.receipts.saveTerminalCommandReceiptConfirmation(operationCtx, &candidate)
			cancel()
			if saveErr != nil || persisted == nil || *persisted != candidate {
				return status.Error(codes.Unavailable, "terminal command receipt restart barrier could not be persisted")
			}
			pending[key] = false
			continue
		}
		if heartbeatStreamSequence <= confirmation.ReceiptStreamSequence {
			continue
		}
		if confirmation.HeartbeatBarrierSequence != 0 && confirmation.HeartbeatBarrierEventID != "" &&
			heartbeatStreamSequence > confirmation.HeartbeatBarrierSequence &&
			heartbeat.Event.GetCausationId() == confirmation.HeartbeatBarrierEventID {
			operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
			receipt, loadErr := g.receipts.loadTerminalCommandReceipt(operationCtx, nodeID, key)
			cancel()
			if loadErr != nil {
				return status.Error(codes.Unavailable, "terminal command receipt could not be loaded")
			}
			if receipt != nil {
				if *receipt != confirmation.Receipt {
					return status.Error(codes.FailedPrecondition, "terminal command receipt changed before causal cleanup")
				}
				operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
				deleteErr := g.receipts.deleteTerminalCommandReceipt(operationCtx, receipt)
				cancel()
				if deleteErr != nil {
					return status.Error(codes.Unavailable, "terminal command receipt could not be compacted")
				}
			}
			operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
			err = g.receipts.deleteTerminalCommandReceiptConfirmation(operationCtx, confirmation)
			cancel()
			if err != nil {
				return status.Error(codes.Unavailable, "terminal command receipt confirmation could not be compacted")
			}
			delete(pending, key)
			continue
		}
		if confirmation.HeartbeatBarrierSequence == 0 || confirmation.HeartbeatBarrierEventID != heartbeat.Event.EventId {
			candidate := *confirmation
			candidate.HeartbeatBarrierSequence = heartbeatStreamSequence
			candidate.HeartbeatBarrierEventID = heartbeat.Event.EventId
			operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
			persisted, saveErr := g.receipts.saveTerminalCommandReceiptConfirmation(operationCtx, &candidate)
			cancel()
			if saveErr != nil || persisted == nil || *persisted != candidate {
				return status.Error(codes.Unavailable, "terminal command receipt heartbeat barrier could not be persisted")
			}
			continue
		}
	}
	return nil
}

func newTerminalCommandReceipt(nodeID string, command *agentv1.DeploymentCommand, value *agentv1.DeploymentStatus,
	deliveries []CommandDelivery, persisted time.Time, publications ...DeploymentStatusPublication,
) (*terminalCommandReceipt, error) {
	if len(publications) > 1 {
		return nil, fmt.Errorf("terminal command receipt publication is invalid")
	}
	var publication DeploymentStatusPublication
	if len(publications) == 1 {
		publication = publications[0]
		if publication.Stream == "" || publication.Sequence == 0 {
			return nil, fmt.Errorf("terminal command receipt publication is invalid")
		}
	}
	commandDigest, err := deterministicMessageSHA256(command)
	if err != nil {
		return nil, fmt.Errorf("terminal command receipt could not hash command")
	}
	statusDigest, err := deterministicMessageSHA256(value)
	if err != nil {
		return nil, fmt.Errorf("terminal command receipt could not hash status")
	}
	artifactDigest, err := deploymentArtifactSetSHA256(command)
	if err != nil {
		return nil, fmt.Errorf("terminal command receipt could not hash artifacts")
	}
	deliveryID, err := commandDeliveryReceiptIdentity(deliveries)
	if err != nil {
		return nil, err
	}
	receipt := &terminalCommandReceipt{
		Version: terminalCommandReceiptVersion, NodeID: nodeID, DeploymentID: command.GetDeploymentId(),
		Attempt: command.GetAttempt(), ConfigVersionID: command.GetConfigVersionId(),
		CommandEventID: command.GetEvent().GetEventId(), StatusEventID: value.GetEvent().GetEventId(),
		TransitionSequence: value.GetTransitionSequence(), CommandSHA256: commandDigest,
		StatusSHA256: statusDigest, ArtifactSetSHA256: artifactDigest, CommandDeliveryID: deliveryID,
		PublishedStream: publication.Stream, PublishedSequence: publication.Sequence,
		PersistedUnixNano: persisted.UTC().UnixNano(),
	}
	if err := validateTerminalCommandReceipt(receipt); err != nil {
		return nil, err
	}
	return receipt, nil
}

func deterministicMessageSHA256(value proto.Message) (string, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func deploymentArtifactSetSHA256(command *agentv1.DeploymentCommand) (string, error) {
	hash := sha256.New()
	var size [8]byte
	for _, artifact := range command.GetArtifacts() {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(artifact)
		if err != nil {
			return "", err
		}
		binary.BigEndian.PutUint64(size[:], uint64(len(encoded)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write(encoded)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func commandDeliveryReceiptIdentity(deliveries []CommandDelivery) (string, error) {
	if len(deliveries) == 0 {
		return "", fmt.Errorf("terminal command receipt requires a broker delivery")
	}
	var identity string
	for _, delivery := range deliveries {
		provider, ok := delivery.(terminalCommandDeliveryReceipt)
		if !ok {
			return "", fmt.Errorf("terminal command delivery has no durable identity")
		}
		candidate, err := provider.terminalCommandDeliveryIdentity()
		if err != nil || candidate == "" {
			return "", fmt.Errorf("terminal command delivery identity is invalid")
		}
		if identity != "" && identity != candidate {
			return "", fmt.Errorf("terminal command deliveries do not share one durable identity")
		}
		identity = candidate
	}
	return identity, nil
}

func validateTerminalCommandReceipt(receipt *terminalCommandReceipt) error {
	if receipt == nil || receipt.Version != terminalCommandReceiptVersion || !canonicalUUID(receipt.NodeID) ||
		!canonicalUUID(receipt.DeploymentID) || receipt.Attempt == 0 || !canonicalUUID(receipt.ConfigVersionID) ||
		!canonicalUUID(receipt.CommandEventID) || !canonicalUUID(receipt.StatusEventID) || receipt.TransitionSequence == 0 ||
		!canonicalLowerSHA256(receipt.CommandSHA256) || !canonicalLowerSHA256(receipt.StatusSHA256) ||
		!canonicalLowerSHA256(receipt.ArtifactSetSHA256) || receipt.CommandDeliveryID == "" ||
		(receipt.PublishedStream == "") != (receipt.PublishedSequence == 0) ||
		(receipt.PublishedStream != "" && !validNATSName(receipt.PublishedStream)) ||
		receipt.PersistedUnixNano <= 0 || timestamppb.New(time.Unix(0, receipt.PersistedUnixNano).UTC()).CheckValid() != nil {
		return fmt.Errorf("terminal command receipt is invalid")
	}
	return nil
}

func validateTerminalCommandReceiptConfirmation(confirmation *terminalCommandReceiptConfirmation) error {
	if confirmation == nil || confirmation.Version != terminalCommandReceiptConfirmationVersion ||
		validateTerminalCommandReceipt(&confirmation.Receipt) != nil || confirmation.SessionEpoch == 0 ||
		confirmation.ReceiptStreamSequence == 0 || confirmation.HeartbeatBarrierSequence != 0 &&
		confirmation.HeartbeatBarrierSequence < confirmation.ReceiptStreamSequence ||
		confirmation.HeartbeatBarrierEventID != "" && (confirmation.HeartbeatBarrierSequence == 0 ||
			!canonicalUUID(confirmation.HeartbeatBarrierEventID)) {
		return fmt.Errorf("terminal command receipt confirmation is invalid")
	}
	return nil
}

func canonicalLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validateTerminalCommandReceiptStatus(receipt *terminalCommandReceipt, value *agentv1.DeploymentStatus) error {
	if err := validateTerminalCommandReceipt(receipt); err != nil || receipt.deploymentKey() != statusKey(value) ||
		receipt.StatusEventID != value.GetEvent().GetEventId() || receipt.TransitionSequence != value.GetTransitionSequence() {
		return fmt.Errorf("terminal command receipt does not match deployment status identity")
	}
	digest, err := deterministicMessageSHA256(value)
	if err != nil || digest != receipt.StatusSHA256 {
		return fmt.Errorf("terminal command receipt does not match exact deployment status")
	}
	return nil
}

func validateTerminalCommandReceiptCommand(receipt *terminalCommandReceipt, command *agentv1.DeploymentCommand, deliveries []CommandDelivery) error {
	if err := validateTerminalCommandReceipt(receipt); err != nil || receipt.deploymentKey() != commandKey(command) ||
		receipt.CommandEventID != command.GetEvent().GetEventId() {
		return fmt.Errorf("terminal command receipt does not match command identity")
	}
	commandDigest, err := deterministicMessageSHA256(command)
	if err != nil || commandDigest != receipt.CommandSHA256 {
		return fmt.Errorf("terminal command receipt does not match exact command")
	}
	artifactDigest, err := deploymentArtifactSetSHA256(command)
	if err != nil || artifactDigest != receipt.ArtifactSetSHA256 {
		return fmt.Errorf("terminal command receipt does not match exact artifacts")
	}
	deliveryID, err := commandDeliveryReceiptIdentity(deliveries)
	if err != nil || deliveryID != receipt.CommandDeliveryID {
		return fmt.Errorf("terminal command receipt does not match exact broker delivery")
	}
	return nil
}

func sameTerminalCommandReceiptBinding(left, right *terminalCommandReceipt) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftCopy, rightCopy := *left, *right
	leftCopy.PersistedUnixNano = 0
	rightCopy.PersistedUnixNano = 0
	return leftCopy == rightCopy
}

func terminalCommandReceiptWireIdentity(subject string, receipt *terminalCommandReceipt) ([]byte, string, error) {
	if subject == "" || validateTerminalCommandReceipt(receipt) != nil {
		return nil, "", fmt.Errorf("terminal command receipt wire identity is invalid")
	}
	stable := *receipt
	stable.PersistedUnixNano = 0
	encoded, err := json.Marshal(&stable)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(subject)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write([]byte(subject))
	_, _ = hash.Write(encoded)
	return encoded, "terminal-receipt-" + hex.EncodeToString(hash.Sum(nil)), nil
}

func terminalCommandReceiptSubject(prefix, nodeID string, key deploymentKey) string {
	return terminalCommandReceiptSubjectWithNamespace(prefix, "terminal-receipt", nodeID, key)
}

func terminalCommandReceiptSubjectWithNamespace(prefix, namespace, nodeID string, key deploymentKey) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", nodeID, key.deploymentID, key.attempt, key.configVersion)))
	return prefix + "." + namespace + "." + nodeID + "." + hex.EncodeToString(digest[:])
}

func decodeTerminalCommandReceipt(encoded []byte) (*terminalCommandReceipt, error) {
	if len(encoded) == 0 || len(encoded) > 4096 {
		return nil, fmt.Errorf("terminal command receipt payload is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var receipt terminalCommandReceipt
	if err := decoder.Decode(&receipt); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("terminal command receipt payload is invalid")
	}
	canonical, err := json.Marshal(&receipt)
	persisted := receipt.PersistedUnixNano
	receipt.PersistedUnixNano = 1
	if err != nil || !bytes.Equal(encoded, canonical) || persisted != 0 || validateTerminalCommandReceipt(&receipt) != nil {
		return nil, fmt.Errorf("terminal command receipt payload is noncanonical")
	}
	receipt.PersistedUnixNano = 0
	return &receipt, nil
}

func terminalCommandReceiptConfirmationSubject(prefix, nodeID string, key deploymentKey) string {
	return terminalCommandReceiptSubjectWithNamespace(prefix, "terminal-receipt-confirmation", nodeID, key)
}

func terminalCommandReceiptConfirmationWireIdentity(subject string, confirmation *terminalCommandReceiptConfirmation, previousSequence uint64) ([]byte, string, error) {
	if subject == "" || validateTerminalCommandReceiptConfirmation(confirmation) != nil {
		return nil, "", fmt.Errorf("terminal command receipt confirmation wire identity is invalid")
	}
	wire := terminalCommandReceiptConfirmationWire{
		Version: terminalCommandReceiptConfirmationWireVersion, Confirmation: *confirmation, PreviousSequence: previousSequence,
	}
	encoded, err := json.Marshal(&wire)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(subject)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write([]byte(subject))
	binary.BigEndian.PutUint64(size[:], previousSequence)
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(encoded)
	return encoded, "terminal-receipt-confirmation-" + hex.EncodeToString(hash.Sum(nil)), nil
}

func decodeTerminalCommandReceiptConfirmation(encoded []byte) (*terminalCommandReceiptConfirmation, error) {
	confirmation, _, err := decodeTerminalCommandReceiptConfirmationWire(encoded)
	return confirmation, err
}

func decodeTerminalCommandReceiptConfirmationWire(encoded []byte) (*terminalCommandReceiptConfirmation, uint64, error) {
	if len(encoded) == 0 || len(encoded) > 8192 {
		return nil, 0, fmt.Errorf("terminal command receipt confirmation payload is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire terminalCommandReceiptConfirmationWire
	if err := decoder.Decode(&wire); err == nil && decoder.Decode(&struct{}{}) == io.EOF {
		canonical, marshalErr := json.Marshal(&wire)
		if marshalErr == nil && bytes.Equal(encoded, canonical) && wire.Version == terminalCommandReceiptConfirmationWireVersion &&
			validateTerminalCommandReceiptConfirmation(&wire.Confirmation) == nil {
			return &wire.Confirmation, wire.PreviousSequence, nil
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var confirmation terminalCommandReceiptConfirmation
	if err := decoder.Decode(&confirmation); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, 0, fmt.Errorf("terminal command receipt confirmation payload is invalid")
	}
	canonical, err := json.Marshal(&confirmation)
	if err != nil || !bytes.Equal(encoded, canonical) || validateTerminalCommandReceiptConfirmation(&confirmation) != nil {
		return nil, 0, fmt.Errorf("terminal command receipt confirmation payload is noncanonical")
	}
	return &confirmation, 0, nil
}

func terminalCommandReceiptConfirmationIndexSubject(prefix, nodeID string) string {
	return prefix + ".terminal-receipt-confirmation-index." + nodeID
}

func terminalCommandReceiptConfirmationIndexEntryForKey(key deploymentKey) terminalCommandReceiptConfirmationIndexEntry {
	return terminalCommandReceiptConfirmationIndexEntry{
		DeploymentID: key.deploymentID, Attempt: key.attempt, ConfigVersionID: key.configVersion,
	}
}

func terminalCommandReceiptConfirmationIndexEntryLess(left, right terminalCommandReceiptConfirmationIndexEntry) bool {
	if left.DeploymentID != right.DeploymentID {
		return left.DeploymentID < right.DeploymentID
	}
	if left.Attempt != right.Attempt {
		return left.Attempt < right.Attempt
	}
	return left.ConfigVersionID < right.ConfigVersionID
}

func validateTerminalCommandReceiptConfirmationIndex(index *terminalCommandReceiptConfirmationIndex) error {
	if index == nil || index.Version != terminalCommandReceiptConfirmationIndexVersion || !canonicalUUID(index.NodeID) {
		return fmt.Errorf("terminal command receipt confirmation index is invalid")
	}
	for position, entry := range index.Entries {
		if !canonicalUUID(entry.DeploymentID) || entry.Attempt == 0 || !canonicalUUID(entry.ConfigVersionID) ||
			position > 0 && !terminalCommandReceiptConfirmationIndexEntryLess(index.Entries[position-1], entry) {
			return fmt.Errorf("terminal command receipt confirmation index is invalid")
		}
	}
	return nil
}

func sameTerminalCommandReceiptConfirmationIndex(left, right *terminalCommandReceiptConfirmationIndex) bool {
	if left == nil || right == nil || left.Version != right.Version || left.NodeID != right.NodeID || len(left.Entries) != len(right.Entries) {
		return left == nil && right == nil
	}
	for position := range left.Entries {
		if left.Entries[position] != right.Entries[position] {
			return false
		}
	}
	return true
}

func terminalCommandReceiptConfirmationIndexWireIdentity(subject string, index *terminalCommandReceiptConfirmationIndex) ([]byte, string, error) {
	if subject == "" || validateTerminalCommandReceiptConfirmationIndex(index) != nil {
		return nil, "", fmt.Errorf("terminal command receipt confirmation index wire identity is invalid")
	}
	encoded, err := json.Marshal(index)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(subject)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write([]byte(subject))
	_, _ = hash.Write(encoded)
	return encoded, "terminal-receipt-confirmation-index-" + hex.EncodeToString(hash.Sum(nil)), nil
}

func decodeTerminalCommandReceiptConfirmationIndex(encoded []byte) (*terminalCommandReceiptConfirmationIndex, error) {
	if len(encoded) == 0 || len(encoded) > 8192 {
		return nil, fmt.Errorf("terminal command receipt confirmation index payload is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var index terminalCommandReceiptConfirmationIndex
	if err := decoder.Decode(&index); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("terminal command receipt confirmation index payload is invalid")
	}
	canonical, err := json.Marshal(&index)
	if err != nil || !bytes.Equal(encoded, canonical) || validateTerminalCommandReceiptConfirmationIndex(&index) != nil {
		return nil, fmt.Errorf("terminal command receipt confirmation index payload is noncanonical")
	}
	return &index, nil
}

func (b *NATSCommandBus) loadTerminalCommandReceipt(ctx context.Context, nodeID string, key deploymentKey) (*terminalCommandReceipt, error) {
	receipt, _, err := b.loadTerminalCommandReceiptMessage(ctx, nodeID, key)
	return receipt, err
}

func (b *NATSCommandBus) loadTerminalCommandReceiptMessage(ctx context.Context, nodeID string, key deploymentKey) (*terminalCommandReceipt, uint64, error) {
	if b == nil || ctx == nil || !canonicalUUID(nodeID) {
		return nil, 0, fmt.Errorf("terminal command receipt lookup is invalid")
	}
	subject := terminalCommandReceiptSubject(b.config.StatusSubjectPrefix, nodeID, key)
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	message, err := b.js.GetLastMsg(b.config.StatusStream, subject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if message == nil || message.Subject != subject {
		return nil, 0, fmt.Errorf("terminal command receipt subject is invalid")
	}
	receipt, err := decodeTerminalCommandReceipt(message.Data)
	if err != nil || receipt.NodeID != nodeID || receipt.deploymentKey() != key {
		return nil, 0, fmt.Errorf("terminal command receipt identity is invalid")
	}
	receipt.PersistedUnixNano = message.Time.UTC().UnixNano()
	if validateTerminalCommandReceipt(receipt) != nil {
		return nil, 0, fmt.Errorf("terminal command receipt persistence time is invalid")
	}
	return receipt, message.Sequence, nil
}

func (b *NATSCommandBus) saveTerminalCommandReceipt(ctx context.Context, receipt *terminalCommandReceipt) (*terminalCommandReceipt, error) {
	if err := validateTerminalCommandReceipt(receipt); err != nil {
		return nil, err
	}
	if existing, err := b.loadTerminalCommandReceipt(ctx, receipt.NodeID, receipt.deploymentKey()); err != nil {
		return nil, err
	} else if existing != nil {
		if !sameTerminalCommandReceiptBinding(existing, receipt) {
			return nil, fmt.Errorf("terminal command receipt conflicts with durable state")
		}
		return existing, nil
	}
	subject := terminalCommandReceiptSubject(b.config.StatusSubjectPrefix, receipt.NodeID, receipt.deploymentKey())
	encoded, receiptID, err := terminalCommandReceiptWireIdentity(subject, receipt)
	if err != nil || len(encoded) > b.config.MaxStatusBytes {
		return nil, fmt.Errorf("terminal command receipt exceeds its size limit")
	}
	message := nats.NewMsg(subject)
	message.Data = encoded
	message.Header.Set(nats.MsgIdHdr, receiptID)
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	_, publishErr := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(b.config.StatusStream), nats.ExpectLastSequencePerSubject(0))
	cancel()
	existing, loadErr := b.loadTerminalCommandReceipt(ctx, receipt.NodeID, receipt.deploymentKey())
	if loadErr != nil || existing == nil || !sameTerminalCommandReceiptBinding(existing, receipt) {
		if loadErr != nil {
			return nil, loadErr
		}
		if publishErr != nil {
			return nil, publishErr
		}
		return nil, fmt.Errorf("terminal command receipt persistence returned no receipt")
	}
	return existing, nil
}

func (b *NATSCommandBus) deleteTerminalCommandReceipt(ctx context.Context, receipt *terminalCommandReceipt) error {
	if err := validateTerminalCommandReceipt(receipt); err != nil {
		return err
	}
	existing, sequence, err := b.loadTerminalCommandReceiptMessage(ctx, receipt.NodeID, receipt.deploymentKey())
	if err != nil || existing == nil {
		return err
	}
	if *existing != *receipt {
		return fmt.Errorf("terminal command receipt changed before compaction")
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	err = b.js.DeleteMsg(b.config.StatusStream, sequence, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil
	}
	return err
}

func (b *NATSCommandBus) loadTerminalCommandReceiptConfirmation(
	ctx context.Context,
	nodeID string,
	key deploymentKey,
) (*terminalCommandReceiptConfirmation, error) {
	confirmation, _, _, err := b.loadTerminalCommandReceiptConfirmationMessage(ctx, nodeID, key)
	return confirmation, err
}

func (b *NATSCommandBus) loadTerminalCommandReceiptConfirmationMessage(
	ctx context.Context,
	nodeID string,
	key deploymentKey,
) (*terminalCommandReceiptConfirmation, uint64, uint64, error) {
	if b == nil || ctx == nil || !canonicalUUID(nodeID) {
		return nil, 0, 0, fmt.Errorf("terminal command receipt confirmation lookup is invalid")
	}
	subject := terminalCommandReceiptConfirmationSubject(b.config.StatusSubjectPrefix, nodeID, key)
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	message, err := b.js.GetLastMsg(b.config.StatusStream, subject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, 0, 0, nil
	}
	if err != nil {
		return nil, 0, 0, err
	}
	if message == nil || message.Subject != subject {
		return nil, 0, 0, fmt.Errorf("terminal command receipt confirmation subject is invalid")
	}
	confirmation, previousSequence, err := decodeTerminalCommandReceiptConfirmationWire(message.Data)
	if err != nil || confirmation.Receipt.NodeID != nodeID || confirmation.deploymentKey() != key {
		return nil, 0, 0, fmt.Errorf("terminal command receipt confirmation identity is invalid")
	}
	encoded, messageID, err := terminalCommandReceiptConfirmationWireIdentity(subject, confirmation, previousSequence)
	if err != nil || !bytes.Equal(message.Data, encoded) || message.Header.Get(nats.MsgIdHdr) != messageID {
		return nil, 0, 0, fmt.Errorf("terminal command receipt confirmation wire identity is invalid")
	}
	return confirmation, message.Sequence, previousSequence, nil
}

func (b *NATSCommandBus) loadTerminalCommandReceiptConfirmationIndexMessage(
	ctx context.Context,
	nodeID string,
) (*terminalCommandReceiptConfirmationIndex, uint64, error) {
	if b == nil || ctx == nil || !canonicalUUID(nodeID) {
		return nil, 0, fmt.Errorf("terminal command receipt confirmation index lookup is invalid")
	}
	subject := terminalCommandReceiptConfirmationIndexSubject(b.config.StatusSubjectPrefix, nodeID)
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	message, err := b.js.GetLastMsg(b.config.StatusStream, subject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if message == nil || message.Subject != subject {
		return nil, 0, fmt.Errorf("terminal command receipt confirmation index subject is invalid")
	}
	index, err := decodeTerminalCommandReceiptConfirmationIndex(message.Data)
	if err != nil || index.NodeID != nodeID {
		return nil, 0, fmt.Errorf("terminal command receipt confirmation index identity is invalid")
	}
	encoded, messageID, err := terminalCommandReceiptConfirmationIndexWireIdentity(subject, index)
	if err != nil || !bytes.Equal(message.Data, encoded) || message.Header.Get(nats.MsgIdHdr) != messageID {
		return nil, 0, fmt.Errorf("terminal command receipt confirmation index wire identity is invalid")
	}
	return index, message.Sequence, nil
}

func (b *NATSCommandBus) listTerminalCommandReceiptConfirmations(
	ctx context.Context,
	nodeID string,
	limit int,
) ([]*terminalCommandReceiptConfirmation, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("terminal command receipt confirmation recovery limit is invalid")
	}
	index, _, err := b.loadTerminalCommandReceiptConfirmationIndexMessage(ctx, nodeID)
	if err != nil || index == nil {
		return nil, err
	}
	if len(index.Entries) > limit || len(index.Entries) > b.config.MaxAckPending {
		return nil, fmt.Errorf("terminal command receipt confirmations exceed their recovery limit")
	}
	confirmations := make([]*terminalCommandReceiptConfirmation, 0, len(index.Entries))
	stale := make([]deploymentKey, 0)
	for _, entry := range index.Entries {
		key := entry.deploymentKey()
		confirmation, err := b.loadTerminalCommandReceiptConfirmation(ctx, nodeID, key)
		if err != nil {
			return nil, err
		}
		if confirmation != nil {
			if confirmation.Receipt.NodeID != nodeID || confirmation.deploymentKey() != key {
				return nil, fmt.Errorf("terminal command receipt confirmation index entry does not match durable state")
			}
			confirmations = append(confirmations, confirmation)
			continue
		}
		receipt, err := b.loadTerminalCommandReceipt(ctx, nodeID, key)
		if err != nil {
			return nil, err
		}
		if receipt == nil {
			stale = append(stale, key)
		}
	}
	for _, key := range stale {
		if err := b.updateTerminalCommandReceiptConfirmationIndex(ctx, nodeID, key, false); err != nil {
			return nil, err
		}
	}
	sort.Slice(confirmations, func(i, j int) bool {
		return terminalCommandReceiptConfirmationIndexEntryLess(
			terminalCommandReceiptConfirmationIndexEntryForKey(confirmations[i].deploymentKey()),
			terminalCommandReceiptConfirmationIndexEntryForKey(confirmations[j].deploymentKey()),
		)
	})
	return confirmations, nil
}

func (b *NATSCommandBus) saveTerminalCommandReceiptConfirmationIndex(
	ctx context.Context,
	index *terminalCommandReceiptConfirmationIndex,
) error {
	if err := validateTerminalCommandReceiptConfirmationIndex(index); err != nil || len(index.Entries) > b.config.MaxAckPending {
		return fmt.Errorf("terminal command receipt confirmation index exceeds its limit")
	}
	existing, sequence, err := b.loadTerminalCommandReceiptConfirmationIndexMessage(ctx, index.NodeID)
	if err != nil {
		return err
	}
	if sameTerminalCommandReceiptConfirmationIndex(existing, index) {
		if existing == nil {
			return nil
		}
		subject := terminalCommandReceiptConfirmationIndexSubject(b.config.StatusSubjectPrefix, index.NodeID)
		return b.deleteTerminalCommandReceiptConfirmationIndexPredecessors(ctx, subject, existing.PreviousSequence)
	}
	candidate := *index
	candidate.Entries = append([]terminalCommandReceiptConfirmationIndexEntry(nil), index.Entries...)
	candidate.PreviousSequence = sequence
	subject := terminalCommandReceiptConfirmationIndexSubject(b.config.StatusSubjectPrefix, index.NodeID)
	encoded, messageID, err := terminalCommandReceiptConfirmationIndexWireIdentity(subject, &candidate)
	if err != nil || len(encoded) > b.config.MaxStatusBytes {
		return fmt.Errorf("terminal command receipt confirmation index exceeds its size limit")
	}
	message := nats.NewMsg(subject)
	message.Data = encoded
	message.Header.Set(nats.MsgIdHdr, messageID)
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	_, publishErr := b.js.PublishMsg(
		message,
		nats.Context(operationCtx),
		nats.ExpectStream(b.config.StatusStream),
		nats.ExpectLastSequencePerSubject(sequence),
	)
	cancel()
	persisted, persistedSequence, loadErr := b.loadTerminalCommandReceiptConfirmationIndexMessage(ctx, index.NodeID)
	if loadErr != nil || persisted == nil || !sameTerminalCommandReceiptConfirmationIndex(persisted, &candidate) ||
		persistedSequence == 0 || persisted.PreviousSequence != sequence {
		if loadErr != nil {
			return loadErr
		}
		if publishErr != nil {
			return publishErr
		}
		return fmt.Errorf("terminal command receipt confirmation index persistence returned inconsistent state")
	}
	return b.deleteTerminalCommandReceiptConfirmationIndexPredecessors(ctx, subject, sequence)
}

func (b *NATSCommandBus) updateTerminalCommandReceiptConfirmationIndex(
	ctx context.Context,
	nodeID string,
	key deploymentKey,
	add bool,
) error {
	index, _, err := b.loadTerminalCommandReceiptConfirmationIndexMessage(ctx, nodeID)
	if err != nil {
		return err
	}
	if index == nil {
		index = &terminalCommandReceiptConfirmationIndex{Version: terminalCommandReceiptConfirmationIndexVersion, NodeID: nodeID}
	}
	entry := terminalCommandReceiptConfirmationIndexEntryForKey(key)
	position := sort.Search(len(index.Entries), func(position int) bool {
		return !terminalCommandReceiptConfirmationIndexEntryLess(index.Entries[position], entry)
	})
	exists := position < len(index.Entries) && index.Entries[position] == entry
	if add {
		if exists {
			return b.saveTerminalCommandReceiptConfirmationIndex(ctx, index)
		}
		if len(index.Entries) >= b.config.MaxAckPending {
			return fmt.Errorf("terminal command receipt confirmation index exceeds its limit")
		}
		index.Entries = append(index.Entries, terminalCommandReceiptConfirmationIndexEntry{})
		copy(index.Entries[position+1:], index.Entries[position:])
		index.Entries[position] = entry
	} else {
		if !exists {
			return b.saveTerminalCommandReceiptConfirmationIndex(ctx, index)
		}
		index.Entries = append(index.Entries[:position], index.Entries[position+1:]...)
	}
	return b.saveTerminalCommandReceiptConfirmationIndex(ctx, index)
}

func (b *NATSCommandBus) deleteTerminalCommandReceiptConfirmationPredecessors(ctx context.Context, subject string, sequence uint64) error {
	sequences, err := b.terminalCommandReceiptPredecessors(ctx, subject, sequence, func(message *nats.RawStreamMsg) (uint64, error) {
		confirmation, previousSequence, err := decodeTerminalCommandReceiptConfirmationWire(message.Data)
		if err != nil {
			return 0, err
		}
		expectedSubject := terminalCommandReceiptConfirmationSubject(
			b.config.StatusSubjectPrefix, confirmation.Receipt.NodeID, confirmation.deploymentKey(),
		)
		encoded, messageID, err := terminalCommandReceiptConfirmationWireIdentity(expectedSubject, confirmation, previousSequence)
		if err != nil || subject != expectedSubject || !bytes.Equal(message.Data, encoded) || message.Header.Get(nats.MsgIdHdr) != messageID {
			return 0, fmt.Errorf("terminal command receipt confirmation predecessor identity is invalid")
		}
		return previousSequence, nil
	})
	if err != nil {
		return err
	}
	return b.deleteTerminalCommandReceiptPredecessors(ctx, sequences)
}

func (b *NATSCommandBus) deleteTerminalCommandReceiptConfirmationIndexPredecessors(ctx context.Context, subject string, sequence uint64) error {
	sequences, err := b.terminalCommandReceiptPredecessors(ctx, subject, sequence, func(message *nats.RawStreamMsg) (uint64, error) {
		index, err := decodeTerminalCommandReceiptConfirmationIndex(message.Data)
		if err != nil {
			return 0, err
		}
		expectedSubject := terminalCommandReceiptConfirmationIndexSubject(b.config.StatusSubjectPrefix, index.NodeID)
		encoded, messageID, err := terminalCommandReceiptConfirmationIndexWireIdentity(expectedSubject, index)
		if err != nil || subject != expectedSubject || !bytes.Equal(message.Data, encoded) || message.Header.Get(nats.MsgIdHdr) != messageID {
			return 0, fmt.Errorf("terminal command receipt confirmation index predecessor identity is invalid")
		}
		return index.PreviousSequence, nil
	})
	if err != nil {
		return err
	}
	return b.deleteTerminalCommandReceiptPredecessors(ctx, sequences)
}

func (b *NATSCommandBus) terminalCommandReceiptPredecessors(
	ctx context.Context,
	subject string,
	sequence uint64,
	previous func(*nats.RawStreamMsg) (uint64, error),
) ([]uint64, error) {
	if b == nil || b.config.MaxAckPending <= 0 || b.config.MaxStatusBytes <= 0 || previous == nil {
		return nil, fmt.Errorf("terminal command receipt predecessor limits are invalid")
	}
	maxBytes := uint64(b.config.MaxAckPending) * uint64(b.config.MaxStatusBytes)
	if maxBytes/uint64(b.config.MaxAckPending) != uint64(b.config.MaxStatusBytes) {
		return nil, fmt.Errorf("terminal command receipt predecessor limits overflow")
	}
	sequences := make([]uint64, 0, min(b.config.MaxAckPending, 32))
	var aggregateBytes uint64
	for sequence != 0 {
		if len(sequences) >= b.config.MaxAckPending {
			// Older predecessors are non-authoritative retained history. Bound the
			// validation window without blocking the current durable head.
			break
		}
		operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
		message, err := b.js.GetMsg(b.config.StatusStream, sequence, nats.Context(operationCtx))
		cancel()
		if errors.Is(err, nats.ErrMsgNotFound) {
			break
		}
		if err != nil || message == nil || message.Subject != subject || message.Sequence != sequence {
			return nil, fmt.Errorf("terminal command receipt predecessor is invalid")
		}
		if len(message.Data) == 0 || len(message.Data) > b.config.MaxStatusBytes || uint64(len(message.Data)) > maxBytes-aggregateBytes {
			return nil, fmt.Errorf("terminal command receipt predecessor byte budget exceeded")
		}
		aggregateBytes += uint64(len(message.Data))
		previousSequence, err := previous(message)
		if err != nil || previousSequence >= sequence {
			return nil, fmt.Errorf("terminal command receipt predecessor chain is invalid")
		}
		sequences = append(sequences, sequence)
		sequence = previousSequence
	}
	return sequences, nil
}

func (b *NATSCommandBus) deleteTerminalCommandReceiptPredecessors(_ context.Context, _ []uint64) error {
	// JetStream deletion is conditional only on stream name and sequence. Keep
	// validated predecessors as non-authoritative history so stream recreation
	// cannot turn an old cleanup decision into deletion of a new message.
	return nil
}

func (b *NATSCommandBus) saveTerminalCommandReceiptConfirmation(
	ctx context.Context,
	confirmation *terminalCommandReceiptConfirmation,
) (*terminalCommandReceiptConfirmation, error) {
	if err := validateTerminalCommandReceiptConfirmation(confirmation); err != nil {
		return nil, err
	}
	if err := b.updateTerminalCommandReceiptConfirmationIndex(
		ctx, confirmation.Receipt.NodeID, confirmation.deploymentKey(), true,
	); err != nil {
		return nil, err
	}
	existing, sequence, previousSequence, err := b.loadTerminalCommandReceiptConfirmationMessage(
		ctx, confirmation.Receipt.NodeID, confirmation.deploymentKey(),
	)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.Receipt != confirmation.Receipt {
		return nil, fmt.Errorf("terminal command receipt confirmation conflicts with durable receipt")
	}
	subject := terminalCommandReceiptConfirmationSubject(
		b.config.StatusSubjectPrefix, confirmation.Receipt.NodeID, confirmation.deploymentKey(),
	)
	if existing != nil && *existing == *confirmation {
		if err := b.deleteTerminalCommandReceiptConfirmationPredecessors(ctx, subject, previousSequence); err != nil {
			return nil, err
		}
		return existing, nil
	}
	encoded, messageID, err := terminalCommandReceiptConfirmationWireIdentity(subject, confirmation, sequence)
	if err != nil || len(encoded) > b.config.MaxStatusBytes {
		return nil, fmt.Errorf("terminal command receipt confirmation exceeds its size limit")
	}
	message := nats.NewMsg(subject)
	message.Data = encoded
	message.Header.Set(nats.MsgIdHdr, messageID)
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	_, publishErr := b.js.PublishMsg(
		message,
		nats.Context(operationCtx),
		nats.ExpectStream(b.config.StatusStream),
		nats.ExpectLastSequencePerSubject(sequence),
	)
	cancel()
	persisted, persistedSequence, persistedPreviousSequence, loadErr := b.loadTerminalCommandReceiptConfirmationMessage(
		ctx, confirmation.Receipt.NodeID, confirmation.deploymentKey(),
	)
	if loadErr != nil || persisted == nil || *persisted != *confirmation || persistedSequence == 0 || persistedPreviousSequence != sequence {
		if loadErr != nil {
			return nil, loadErr
		}
		if publishErr != nil {
			return nil, publishErr
		}
		return nil, fmt.Errorf("terminal command receipt confirmation persistence returned inconsistent state")
	}
	if err := b.deleteTerminalCommandReceiptConfirmationPredecessors(ctx, subject, sequence); err != nil {
		return nil, err
	}
	return persisted, nil
}

func (b *NATSCommandBus) deleteTerminalCommandReceiptConfirmation(
	ctx context.Context,
	confirmation *terminalCommandReceiptConfirmation,
) error {
	if err := validateTerminalCommandReceiptConfirmation(confirmation); err != nil {
		return err
	}
	index, _, err := b.loadTerminalCommandReceiptConfirmationIndexMessage(ctx, confirmation.Receipt.NodeID)
	if err != nil {
		return err
	}
	entry := terminalCommandReceiptConfirmationIndexEntryForKey(confirmation.deploymentKey())
	position := 0
	if index != nil {
		position = sort.Search(len(index.Entries), func(position int) bool {
			return !terminalCommandReceiptConfirmationIndexEntryLess(index.Entries[position], entry)
		})
	}
	if index == nil || position >= len(index.Entries) || index.Entries[position] != entry {
		return nil
	}
	existing, sequence, previousSequence, err := b.loadTerminalCommandReceiptConfirmationMessage(
		ctx, confirmation.Receipt.NodeID, confirmation.deploymentKey(),
	)
	if err != nil {
		return err
	}
	if existing == nil {
		return b.updateTerminalCommandReceiptConfirmationIndex(
			ctx, confirmation.Receipt.NodeID, confirmation.deploymentKey(), false,
		)
	}
	if *existing != *confirmation {
		return fmt.Errorf("terminal command receipt confirmation changed before compaction")
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	err = b.js.DeleteMsg(b.config.StatusStream, sequence, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		err = nil
	}
	if err != nil {
		return err
	}
	current, currentSequence, _, err := b.loadTerminalCommandReceiptConfirmationMessage(
		ctx, confirmation.Receipt.NodeID, confirmation.deploymentKey(),
	)
	if err != nil {
		return err
	}
	if current != nil && currentSequence != previousSequence {
		return fmt.Errorf("terminal command receipt confirmation changed during compaction")
	}
	return b.updateTerminalCommandReceiptConfirmationIndex(
		ctx, confirmation.Receipt.NodeID, confirmation.deploymentKey(), false,
	)
}

func (d *natsCommandDelivery) terminalCommandDeliveryIdentity() (string, error) {
	if d == nil || d.message == nil {
		return "", fmt.Errorf("NATS command delivery is missing")
	}
	metadata, err := d.message.Metadata()
	if err != nil || metadata == nil || metadata.Sequence.Stream == 0 {
		return "", fmt.Errorf("NATS command delivery metadata is invalid")
	}
	return fmt.Sprintf("stream:%d", metadata.Sequence.Stream), nil
}

func (g *Gateway) persistOverlayStatusAndAckCommand(ctx context.Context, nodeID string, overlayStatus *agentv1.AcmeHTTP01OverlayStatus, pending pendingOverlayCommandSet) error {
	if err := g.validateACMEHTTP01OverlayStatus(overlayStatus); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	key := overlayStatusKey(overlayStatus)
	command, exists := pending[key]
	if exists && !overlayStatusMatchesCommand(overlayStatus, command.command) {
		return status.Error(codes.FailedPrecondition, "overlay status identity conflicts with the in-flight command")
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	err := g.overlays.PublishOverlayStatus(operationCtx, nodeID, overlayStatus)
	cancel()
	if err != nil {
		return status.Error(codes.Unavailable, "overlay deployment status could not be persisted")
	}
	if !exists {
		return nil
	}
	for len(command.deliveries) > 0 {
		delivery := command.deliveries[0]
		operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		err = delivery.Ack(operationCtx)
		cancel()
		if err != nil {
			return status.Error(codes.Unavailable, "overlay command could not be acknowledged")
		}
		command.deliveries = command.deliveries[1:]
	}
	delete(pending, key)
	return nil
}

func overlayStatusMatchesCommand(status *agentv1.AcmeHTTP01OverlayStatus, command *agentv1.AcmeHTTP01OverlayCommand) bool {
	if status == nil || command == nil || status.Event == nil || command.Event == nil ||
		status.OverlayRevision != command.OverlayRevision || status.Event.CausationId == nil ||
		status.Event.GetCausationId() != command.Event.EventId || status.Event.RequestId != command.Event.RequestId ||
		status.Event.Traceparent != command.Event.Traceparent || status.Event.CorrelationId != command.Event.CorrelationId {
		return false
	}
	if (status.Event.TaskId == nil) != (command.Event.TaskId == nil) {
		return false
	}
	return status.Event.TaskId == nil || status.Event.GetTaskId() == command.Event.GetTaskId()
}

// validateHeartbeat takes (activeIdentityEnabled, multiTenantEnabled).
func (g *Gateway) validateHeartbeat(heartbeat *agentv1.Heartbeat, epoch, lastSequence uint64, duplicate bool, agentVersion string, activeIdentityCapability ...bool) error {
	activeIdentityEnabled := len(activeIdentityCapability) >= 1 && activeIdentityCapability[0]
	multiTenantEnabled := activeIdentityEnabled && len(activeIdentityCapability) >= 2 && activeIdentityCapability[1]
	if heartbeat == nil {
		return fmt.Errorf("heartbeat is required")
	}
	if err := g.validateEventMetadata(heartbeat.Event); err != nil {
		return err
	}
	if heartbeat.SessionEpoch != epoch {
		return fmt.Errorf("heartbeat session epoch does not match the active session")
	}
	if heartbeat.HeartbeatSequence == 0 || (!duplicate && heartbeat.HeartbeatSequence <= lastSequence) {
		return fmt.Errorf("heartbeat sequence is not strictly increasing")
	}
	if len(heartbeat.ActiveDeployments) > g.config.MaxActiveDeployments {
		return fmt.Errorf("heartbeat active deployments exceed their size limit")
	}
	if heartbeat.AgentVersion != nil {
		if !validAgentVersion(heartbeat.GetAgentVersion(), true) {
			return fmt.Errorf("heartbeat agent version is invalid")
		}
		if heartbeat.GetAgentVersion() != agentVersion {
			return fmt.Errorf("heartbeat agent version does not match AgentHello")
		}
	}
	if err := g.validateHeartbeatScopedConfigIdentities(heartbeat, multiTenantEnabled); err != nil {
		return err
	}
	return g.validateHeartbeatActiveConfigIdentities(heartbeat, activeIdentityEnabled)
}

func (g *Gateway) validateArtifactRequest(request *agentv1.FetchArtifactRequest) error {
	if request == nil {
		return fmt.Errorf("artifact request is required")
	}
	if err := g.validateRequestMetadata(request.Request); err != nil {
		return err
	}
	if err := g.validateUUID("event_id", request.EventId); err != nil {
		return err
	}
	if err := g.validateUUID("deployment_id", request.DeploymentId); err != nil {
		return err
	}
	if request.Attempt == 0 {
		return fmt.Errorf("attempt must be positive")
	}
	return g.validateUUID("artifact_id", request.ArtifactId)
}

type connectReceive struct {
	request *agentv1.ConnectRequest
	err     error
}

func pumpConnectRequests(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) (<-chan connectReceive, <-chan struct{}) {
	received := make(chan connectReceive, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			request, err := stream.Recv()
			select {
			case received <- connectReceive{request: request, err: err}:
			case <-stream.Context().Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return received, done
}

func receiveArtifact(ctx context.Context, stream ArtifactStream) (*controlv1.FetchArtifactResponse, error) {
	type result struct {
		response *controlv1.FetchArtifactResponse
		err      error
	}
	received := make(chan result, 1)
	go func() {
		response, err := stream.Recv()
		select {
		case received <- result{response: response, err: err}:
		case <-ctx.Done():
		}
	}()
	select {
	case result := <-received:
		return result.response, rpcError(result.err)
	case <-ctx.Done():
		return nil, rpcError(ctx.Err())
	}
}

func sendArtifact(ctx context.Context, stream grpc.ServerStreamingServer[agentv1.FetchArtifactResponse], response *agentv1.FetchArtifactResponse) error {
	// gRPC Send unblocks when this handler returns and closes the RPC. The
	// buffered result lets its goroutine finish without waiting on the caller.
	return sendArtifactWithContext(ctx, response, func(_ context.Context, response *agentv1.FetchArtifactResponse) error {
		return stream.Send(response)
	})
}

func sendArtifactWithContext(ctx context.Context, response *agentv1.FetchArtifactResponse, send func(context.Context, *agentv1.FetchArtifactResponse) error) error {
	sent := make(chan error, 1)
	go func() {
		err := send(ctx, response)
		select {
		case sent <- err:
		case <-ctx.Done():
		}
	}()
	select {
	case err := <-sent:
		return rpcError(err)
	case <-ctx.Done():
		return rpcError(ctx.Err())
	}
}

func sendSessionResponse(lease SessionLease, stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse], response *agentv1.ConnectResponse) error {
	err := lease.FencedSend(func() error { return stream.Send(response) })
	if errors.Is(err, ErrSessionSuperseded) {
		return status.Error(codes.Aborted, "node session was superseded")
	}
	return rpcError(err)
}

func sendConnectResponse(ctx context.Context, stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse], response *agentv1.ConnectResponse) error {
	sent := make(chan error, 1)
	go func() {
		err := stream.Send(response)
		select {
		case sent <- err:
		case <-ctx.Done():
		}
	}()
	select {
	case err := <-sent:
		return rpcError(err)
	case <-ctx.Done():
		return rpcError(ctx.Err())
	}
}

func sessionSuperseded(lease SessionLease) bool {
	select {
	case <-lease.Superseded():
		return true
	default:
		return false
	}
}

func refreshAt(now, expiration time.Time) time.Time {
	return now.Add(expiration.Sub(now) / 2)
}

func delayUntil(now, deadline time.Time) time.Duration {
	if delay := deadline.Sub(now); delay > 0 {
		return delay
	}
	return time.Nanosecond
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func receiveWithTimeout(ctx context.Context, received <-chan connectReceive, timeout time.Duration) (connectReceive, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-received:
		return result, rpcError(result.err)
	case <-timer.C:
		return connectReceive{}, status.Error(codes.DeadlineExceeded, "AgentHello was not received before the handshake deadline")
	case <-ctx.Done():
		return connectReceive{}, rpcError(ctx.Err())
	}
}

func rpcError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	return err
}

func (g *Gateway) protocolErrorResponse(sequence uint64, code commonv1.ErrorCode, message string) *agentv1.ConnectResponse {
	return &agentv1.ConnectResponse{
		Stream: responseStreamMetadata(sequence, g.now()),
		Payload: &agentv1.ConnectResponse_Error{Error: &agentv1.StreamError{Error: &commonv1.ProtocolError{
			Code: code, Message: message,
		}}},
	}
}

func responseStreamMetadata(sequence uint64, now time.Time) *commonv1.StreamMetadata {
	return &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.New(now), Sequence: sequence}
}

func newRequestMetadata(now time.Time) *commonv1.RequestMetadata {
	return &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.New(now)}
}

// observedPeerIP is echoed in GatewayHello (ADR 0013 §4.4).
func observedPeerIP(ctx context.Context) string {
	if addr, _, ok := peerAddress(ctx); ok {
		return addr.String()
	}
	return ""
}

func peerIP(ctx context.Context) *string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return nil
	}
	return &host
}
