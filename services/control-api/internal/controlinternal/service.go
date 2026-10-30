package controlinternal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const DefaultGatewayWorkloadURISAN = "spiffe://cdn-platform/gateway/control"

const renewalErrorDomain = "cdnca.com/node-certificate-renewal"

var ErrInvalidConfig = errors.New("invalid control internal service configuration")

type NodeIdentityService interface {
	Authorize(context.Context, nodeidentity.AuthorizeRequest) (nodeidentity.Authorization, error)
	Complete(context.Context, nodeidentity.CompleteRequest) (nodeidentity.EnrollmentCompletion, error)
	Renew(context.Context, nodeidentity.RenewRequest) (nodeidentity.Certificate, error)
	GetAuthorization(context.Context, nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error)
}

type ArtifactStore interface {
	FetchChunk(context.Context, *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error)
}

// SiteObjectStore serves site runtime v8 objects (edgeartifact.Store).
type SiteObjectStore interface {
	FetchSiteObjects(context.Context, *controlv1.FetchSiteObjectsRequest, edgeartifact.SiteObjectChunkSink) error
}

var _ SiteObjectStore = (*edgeartifact.Store)(nil)

// GatewayWorkloadURIPrefix + gateway_id is the client certificate URI SAN of
// a standalone Gateway bound through the Gateway registry (ADR 0013 §3.2).
const GatewayWorkloadURIPrefix = "spiffe://cdn-platform/gateway/"

// GatewayCertificate is a renewed Gateway certificate.
type GatewayCertificate struct {
	PEM      []byte
	NotAfter time.Time
	RenewAt  time.Time
}

// GatewayRegistry decides bound Gateways (gatewayregistry.Service).
type GatewayRegistry interface {
	// AuthorizeGateway: disabled reports a Gateway disabled within the grace
	// period (it serves its connected nodes, enrolls none, ADR 0013 §5.2).
	AuthorizeGateway(ctx context.Context, id uuid.UUID, serial string, certificateSHA256 [32]byte) (disabled bool, err error)
	MarkReady(ctx context.Context, id uuid.UUID, version string) error
	Renew(ctx context.Context, id uuid.UUID, kind string, csrDER []byte) (GatewayCertificate, error)
	// Settings is what the Gateway management page publishes (GW-06/GW-07).
	Settings(ctx context.Context) (GatewaySettings, error)
}

type GatewayTrustedProxy struct{ CIDR, Header string }

type GatewayEndpoint struct{ Address, ServerName, Transport, TunnelHost, EnrollmentAddress string }

// GatewaySettings are the trusted CDN ranges and the node endpoint list.
type GatewaySettings struct {
	TrustedProxies   []GatewayTrustedProxy
	Endpoints        []GatewayEndpoint
	EndpointsVersion string
}

var errGatewayRefused = errors.New("gateway refused")

type Config struct {
	GatewayWorkloadURISAN string
	// Gateways enables standalone Gateways (per-gateway URI SAN). Nil: only
	// the co-located Gateway's GatewayWorkloadURISAN is accepted.
	Gateways GatewayRegistry
	// InstallationID is returned by ReportGatewayReady (tunnel token audience).
	InstallationID string
	// SiteObjects serves site runtime v8 objects. Unset: the artifact store
	// when it implements SiteObjectStore (production wraps it, so main sets
	// this explicitly).
	SiteObjects SiteObjectStore
}

func DefaultConfig() Config {
	return Config{GatewayWorkloadURISAN: DefaultGatewayWorkloadURISAN}
}

type Service struct {
	controlv1.UnimplementedControlInternalServiceServer

	identity              NodeIdentityService
	artifacts             ArtifactStore
	siteObjects           SiteObjectStore
	gatewayWorkloadURISAN string
	gateways              GatewayRegistry
	installationID        string
	logger                *slog.Logger
}

func NewService(identity NodeIdentityService, artifacts ArtifactStore, config Config) (*Service, error) {
	if config.GatewayWorkloadURISAN == "" {
		config.GatewayWorkloadURISAN = DefaultGatewayWorkloadURISAN
	}
	if nilDependency(identity) || nilDependency(artifacts) || !validWorkloadURISAN(config.GatewayWorkloadURISAN) {
		return nil, ErrInvalidConfig
	}
	siteObjects := config.SiteObjects
	if nilDependency(siteObjects) {
		siteObjects, _ = artifacts.(SiteObjectStore)
	}
	return &Service{
		identity:              identity,
		artifacts:             artifacts,
		siteObjects:           siteObjects,
		gatewayWorkloadURISAN: config.GatewayWorkloadURISAN,
		gateways:              config.Gateways,
		installationID:        config.InstallationID,
		logger:                slog.Default(),
	}, nil
}

func (s *Service) AuthorizeEnrollment(ctx context.Context, request *controlv1.AuthorizeEnrollmentRequest) (*controlv1.AuthorizeEnrollmentResponse, error) {
	workloadIdentity, err := s.authenticateEnrollingGateway(ctx, request.GetGatewayInstanceId())
	if err != nil {
		return nil, err
	}
	if invalidMessage(request) || request.GetRequest() == nil || !canonicalUUID(request.GetRequest().GetRequestId()) ||
		!canonicalUUID(request.GetGatewayInstanceId()) {
		return nil, invalidRequestError()
	}
	authorization, err := s.identity.Authorize(ctx, nodeidentity.AuthorizeRequest{
		RequestID:                    request.GetRequest().GetRequestId(),
		EnrollmentToken:              request.GetEnrollmentToken(),
		CertificateSigningRequestDER: bytes.Clone(request.GetCertificateSigningRequestDer()),
		MachineFingerprintSHA256:     bytes.Clone(request.GetMachineFingerprintSha256()),
		SupportedProtocolVersions:    cloneProtocolRange(request.GetSupportedProtocolVersions()),
		Capabilities:                 cloneCapabilities(request.GetCapabilities()),
		GatewayWorkloadIdentity:      workloadIdentity,
		GatewayInstanceID:            request.GetGatewayInstanceId(),
		PeerIP:                       request.GetPeerIp(),
		ArtifactEncryptionPublicKey:  bytes.Clone(request.GetArtifactEncryptionPublicKey()),
	})
	if err != nil {
		return nil, s.logFailure(ctx, "AuthorizeEnrollment", "", err, rpcError(err))
	}
	if authorization.ID == uuid.Nil || authorization.NodeID == uuid.Nil || authorization.SelectedProtocolVersion == nil ||
		authorization.ArtifactEncryptionKeyID == "" || invalidMessage(authorization.SelectedProtocolVersion) {
		return nil, internalResponseError()
	}
	expiresAt, err := timestamp(authorization.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &controlv1.AuthorizeEnrollmentResponse{
		AuthorizationId:                 authorization.ID.String(),
		NodeId:                          authorization.NodeID.String(),
		CertificateSigningRequestSha256: bytes.Clone(authorization.CertificateSigningRequestSHA256[:]),
		SelectedProtocolVersion:         cloneProtocolVersion(authorization.SelectedProtocolVersion),
		AuthorizationExpirationTime:     expiresAt,
		Replayed:                        authorization.Replayed,
		ArtifactEncryptionKeyId:         authorization.ArtifactEncryptionKeyID,
	}, nil
}

func (s *Service) CompleteEnrollment(ctx context.Context, request *controlv1.CompleteEnrollmentRequest) (*controlv1.CompleteEnrollmentResponse, error) {
	workloadIdentity, err := s.authenticateEnrollingGateway(ctx, request.GetGatewayInstanceId())
	if err != nil {
		return nil, err
	}
	if invalidMessage(request) || request.GetRequest() == nil || !canonicalUUID(request.GetRequest().GetRequestId()) ||
		!canonicalUUID(request.GetGatewayInstanceId()) {
		return nil, invalidRequestError()
	}
	authorizationID, err := parseUUID(request.GetAuthorizationId())
	if err != nil {
		return nil, invalidRequestError()
	}
	completion, err := s.identity.Complete(ctx, nodeidentity.CompleteRequest{
		RequestID:               request.GetRequest().GetRequestId(),
		AuthorizationID:         authorizationID,
		GatewayWorkloadIdentity: workloadIdentity,
		GatewayInstanceID:       request.GetGatewayInstanceId(),
	})
	if err != nil {
		return nil, s.logFailure(ctx, "CompleteEnrollment", "", err, rpcError(err))
	}
	if completion.Certificate.NodeID == uuid.Nil || completion.ArtifactEncryptionKeyID == "" {
		return nil, internalResponseError()
	}
	bundle, err := certificateBundle(completion.Certificate)
	if err != nil {
		return nil, err
	}
	return &controlv1.CompleteEnrollmentResponse{
		NodeId:                  completion.Certificate.NodeID.String(),
		Certificate:             bundle,
		ArtifactEncryptionKeyId: completion.ArtifactEncryptionKeyID,
	}, nil
}

func (s *Service) RenewNodeCertificate(ctx context.Context, request *controlv1.RenewNodeCertificateRequest) (*controlv1.RenewNodeCertificateResponse, error) {
	workloadIdentity, err := s.authenticateGateway(ctx, request.GetGatewayInstanceId())
	if err != nil {
		return nil, err
	}
	if invalidMessage(request) || request.GetRequest() == nil || !canonicalUUID(request.GetRequest().GetRequestId()) ||
		!canonicalUUID(request.GetGatewayInstanceId()) || len(request.GetCurrentCertificateSha256()) != sha256.Size {
		return nil, invalidRequestError()
	}
	nodeID, err := parseUUID(request.GetNodeId())
	if err != nil {
		return nil, invalidRequestError()
	}
	var currentCertificateSHA256 [sha256.Size]byte
	copy(currentCertificateSHA256[:], request.GetCurrentCertificateSha256())
	certificate, err := s.identity.Renew(ctx, nodeidentity.RenewRequest{
		RequestID:                    request.GetRequest().GetRequestId(),
		NodeID:                       nodeID,
		CurrentSerialNumber:          request.GetCurrentSerialNumber(),
		CurrentCertificateSHA256:     currentCertificateSHA256,
		CertificateSigningRequestDER: bytes.Clone(request.GetCertificateSigningRequestDer()),
		GatewayWorkloadIdentity:      workloadIdentity,
		GatewayInstanceID:            request.GetGatewayInstanceId(),
	})
	if err != nil {
		return nil, s.logFailure(ctx, "RenewNodeCertificate", nodeID.String(), err, renewalRPCError(err))
	}
	if certificate.NodeID != nodeID {
		return nil, internalResponseError()
	}
	bundle, err := certificateBundle(certificate)
	if err != nil {
		return nil, err
	}
	return &controlv1.RenewNodeCertificateResponse{Certificate: bundle}, nil
}

// NodeCertificateRecoverer is implemented by nodeidentity.Service (ADR 0013 GW-02).
type NodeCertificateRecoverer interface {
	Recover(context.Context, nodeidentity.RecoverRequest) (nodeidentity.Certificate, error)
}

func (s *Service) RecoverNodeCertificate(ctx context.Context, request *controlv1.RecoverNodeCertificateRequest) (*controlv1.RecoverNodeCertificateResponse, error) {
	workloadIdentity, err := s.authenticateGateway(ctx, request.GetGatewayInstanceId())
	if err != nil {
		return nil, err
	}
	recoverer, ok := s.identity.(NodeCertificateRecoverer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "node certificate recovery is not available")
	}
	recovery := request.GetRecovery()
	if invalidMessage(request) || recovery.GetRequest() == nil || !canonicalUUID(recovery.GetRequest().GetRequestId()) ||
		recovery.GetRequest().GetSentTime() == nil || recovery.GetRequest().GetSentTime().CheckValid() != nil ||
		!canonicalUUID(request.GetGatewayInstanceId()) {
		return nil, invalidRequestError()
	}
	nodeID, err := parseUUID(recovery.GetNodeId())
	if err != nil {
		return nil, invalidRequestError()
	}
	certificate, err := recoverer.Recover(ctx, nodeidentity.RecoverRequest{
		RequestID:                    recovery.GetRequest().GetRequestId(),
		SentTime:                     recovery.GetRequest().GetSentTime().AsTime(),
		NodeID:                       nodeID,
		ExpiredCertificateDER:        bytes.Clone(recovery.GetExpiredCertificateDer()),
		CertificateSigningRequestDER: bytes.Clone(recovery.GetCertificateSigningRequestDer()),
		Nonce:                        bytes.Clone(recovery.GetNonce()),
		Signature:                    bytes.Clone(recovery.GetSignature()),
		GatewayWorkloadIdentity:      workloadIdentity,
		GatewayInstanceID:            request.GetGatewayInstanceId(),
		PeerIP:                       request.GetPeerIp(),
	})
	if err != nil {
		return nil, s.logFailure(ctx, "RecoverNodeCertificate", nodeID.String(), err, recoveryRPCError(err))
	}
	if certificate.NodeID != nodeID {
		return nil, internalResponseError()
	}
	bundle, err := certificateBundle(certificate)
	if err != nil {
		return nil, err
	}
	return &controlv1.RecoverNodeCertificateResponse{Certificate: bundle}, nil
}

// recoveryRPCError: refusals the node cannot fix by retrying are
// PermissionDenied (manual re-enrollment needed); a not yet expired
// certificate is FailedPrecondition (renew over mTLS instead).
func recoveryRPCError(err error) error {
	switch {
	case errors.Is(err, nodeidentity.ErrRecoveryWindowExceeded), errors.Is(err, nodeidentity.ErrRecoveryProofInvalid),
		errors.Is(err, nodeidentity.ErrRecoveryReplay):
		return status.Error(codes.PermissionDenied, "node certificate recovery is not authorized")
	case errors.Is(err, nodeidentity.ErrRecoveryNotExpired):
		return status.Error(codes.FailedPrecondition, "node certificate has not expired")
	}
	return rpcError(err)
}

func (s *Service) GetNodeAuthorization(ctx context.Context, request *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	workloadIdentity, err := s.authenticateGateway(ctx, request.GetGatewayInstanceId())
	if err != nil {
		return nil, err
	}
	if invalidMessage(request) || request.GetRequest() == nil || !canonicalUUID(request.GetRequest().GetRequestId()) ||
		!canonicalUUID(request.GetGatewayInstanceId()) || len(request.GetCertificateSha256()) != sha256.Size {
		return nil, invalidRequestError()
	}
	nodeID, err := parseUUID(request.GetNodeId())
	if err != nil {
		return nil, invalidRequestError()
	}
	var certificateSHA256 [sha256.Size]byte
	copy(certificateSHA256[:], request.GetCertificateSha256())
	snapshot, err := s.identity.GetAuthorization(ctx, nodeidentity.GetAuthorizationRequest{
		NodeID:                  nodeID,
		CertificateSerialNumber: request.GetCertificateSerialNumber(),
		CertificateSHA256:       certificateSHA256,
		GatewayWorkloadIdentity: workloadIdentity,
		GatewayInstanceID:       request.GetGatewayInstanceId(),
		SessionFacts:            request.GetSessionFacts(),
	})
	if err != nil {
		return nil, s.logFailure(ctx, "GetNodeAuthorization", nodeID.String(), err, rpcError(err))
	}
	administrativeState, ok := nodeAdministrativeState(snapshot.AdministrativeState)
	if request.SessionFacts != nil {
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request.SessionFacts)
		digest := sha256.Sum256(encoded)
		// Paused deployments may record no facts (no receipt, no upgrade authority).
		unrecorded := len(snapshot.SessionFactsSHA256) == 0 && !snapshot.DeploymentsAllowed
		if err != nil || !unrecorded && !bytes.Equal(snapshot.SessionFactsSHA256, digest[:]) {
			return nil, internalResponseError()
		}
	} else if len(snapshot.SessionFactsSHA256) != 0 {
		return nil, internalResponseError()
	}
	if !ok || snapshot.NodeID != nodeID || snapshot.AcceptedProtocolVersions == nil ||
		invalidMessage(snapshot.AcceptedProtocolVersions) || snapshot.ArtifactEncryptionKeyID == "" ||
		!validInstallationID(snapshot.InstallationID) {
		return nil, internalResponseError()
	}
	telemetrySiteScopes, ok := mapTelemetrySiteScopes(snapshot)
	if !ok {
		return nil, internalResponseError()
	}
	certificateExpiresAt, err := timestamp(snapshot.CertificateExpirationTime)
	if err != nil {
		return nil, err
	}
	snapshotExpiresAt, err := timestamp(snapshot.SnapshotExpirationTime)
	if err != nil {
		return nil, err
	}
	return &controlv1.GetNodeAuthorizationResponse{
		NodeId:                    snapshot.NodeID.String(),
		AuthorizationRevision:     snapshot.AuthorizationRevision,
		AdministrativeState:       administrativeState,
		ConnectionAllowed:         snapshot.ConnectionAllowed,
		DeploymentsAllowed:        snapshot.DeploymentsAllowed,
		CertificateRevoked:        snapshot.CertificateRevoked,
		CertificateExpirationTime: certificateExpiresAt,
		AcceptedProtocolVersions:  cloneProtocolRange(snapshot.AcceptedProtocolVersions),
		SnapshotExpirationTime:    snapshotExpiresAt,
		ArtifactEncryptionKeyId:   snapshot.ArtifactEncryptionKeyID,
		InstallationId:            snapshot.InstallationID,
		TenantId:                  optionalUUIDString(snapshot.TenantID),
		TelemetrySiteScopes:       telemetrySiteScopes,
		SessionFactsSha256:        append([]byte(nil), snapshot.SessionFactsSHA256...),
		NodeScopeId:               optionalUUIDString(snapshot.NodeScopeID),
	}, nil
}

func (s *Service) FetchArtifact(request *controlv1.FetchArtifactRequest, stream controlv1.ControlInternalService_FetchArtifactServer) error {
	if stream == nil {
		return status.Error(codes.Unauthenticated, "verified gateway client certificate required")
	}
	if _, err := s.authenticateGateway(stream.Context(), request.GetGatewayInstanceId()); err != nil {
		return err
	}
	if invalidMessage(request) || request.GetRequest() == nil || !canonicalUUID(request.GetGatewayInstanceId()) {
		return invalidRequestError()
	}
	cloned := proto.Clone(request).(*controlv1.FetchArtifactRequest)
	result, err := s.artifacts.FetchChunk(stream.Context(), cloned)
	if err != nil {
		return s.logFailure(stream.Context(), "FetchArtifact", request.GetNodeId(), err, rpcError(err))
	}
	if result.EOF {
		if result.Response != nil {
			return internalResponseError()
		}
		return nil
	}
	if invalidMessage(result.Response) || result.Response.GetChunk() == nil || len(result.Response.GetChunk().GetData()) == 0 ||
		result.Response.GetChunk().GetRequestId() != request.GetRequest().GetRequestId() ||
		result.Response.GetChunk().GetArtifactId() != request.GetArtifactId() ||
		result.Response.GetChunk().GetOffset() != request.GetOffset() {
		return internalResponseError()
	}
	response := proto.Clone(result.Response).(*controlv1.FetchArtifactResponse)
	if err := stream.Send(response); err != nil {
		return rpcError(err)
	}
	return nil
}

// FetchSiteObjects streams the requested site objects of the node's site
// runtime v8 deployment, after edgeartifact authorizes every digest.
func (s *Service) FetchSiteObjects(request *controlv1.FetchSiteObjectsRequest, stream controlv1.ControlInternalService_FetchSiteObjectsServer) error {
	if stream == nil {
		return status.Error(codes.Unauthenticated, "verified gateway client certificate required")
	}
	if _, err := s.authenticateGateway(stream.Context(), request.GetGatewayInstanceId()); err != nil {
		return err
	}
	objects := s.siteObjects
	if objects == nil {
		return status.Error(codes.Unimplemented, "site objects are unavailable")
	}
	if invalidMessage(request) || request.GetRequest() == nil || !canonicalUUID(request.GetGatewayInstanceId()) {
		return invalidRequestError()
	}
	cloned := proto.Clone(request).(*controlv1.FetchSiteObjectsRequest)
	next := 0
	err := objects.FetchSiteObjects(stream.Context(), cloned, func(response *controlv1.FetchSiteObjectsResponse) error {
		chunk := response.GetChunk()
		if invalidMessage(response) || chunk == nil || len(chunk.GetData()) == 0 ||
			chunk.GetRequestId() != request.GetRequest().GetRequestId() || next >= len(request.GetSha256()) ||
			chunk.GetSha256() != request.GetSha256()[next] {
			return internalResponseError()
		}
		if chunk.GetEndOfObject() {
			next++
		}
		return stream.Send(proto.Clone(response).(*controlv1.FetchSiteObjectsResponse))
	})
	if err != nil {
		if _, isStatus := status.FromError(err); isStatus && status.Code(err) != codes.Unknown {
			return err
		}
		return s.logFailure(stream.Context(), "FetchSiteObjects", request.GetNodeId(), err, rpcError(err))
	}
	if next != len(request.GetSha256()) {
		return internalResponseError()
	}
	return nil
}

func gatewayUnauthenticated() error {
	return status.Error(codes.Unauthenticated, "verified gateway client certificate required")
}

// authenticateGateway returns the workload identity the node identity layer
// binds sessions to. The co-located Gateway presents GatewayWorkloadURISAN;
// a standalone Gateway presents GatewayWorkloadURIPrefix+<gateway_id>, must
// be bound, unrevoked and send its own ID as gateway_instance_id. Both map
// to GatewayWorkloadURISAN so a node can move between Gateways (sessions and
// inventory are bound to the workload identity, nodeidentity/session_facts.go).
func (s *Service) authenticateGateway(ctx context.Context, instanceID string) (string, error) {
	if _, err := s.gatewayCaller(ctx, instanceID); err != nil {
		return "", err
	}
	return s.gatewayWorkloadURISAN, nil
}

// authenticateEnrollingGateway also refuses a disabled Gateway: it takes no
// new nodes (ADR 0013 §5.2).
func (s *Service) authenticateEnrollingGateway(ctx context.Context, instanceID string) (string, error) {
	disabled, err := s.gatewayCaller(ctx, instanceID)
	if err != nil {
		return "", err
	}
	if disabled {
		return "", status.Error(codes.FailedPrecondition, "gateway is disabled")
	}
	return s.gatewayWorkloadURISAN, nil
}

// gatewayCaller authenticates the caller; disabled marks a standalone
// Gateway disabled within the grace period.
func (s *Service) gatewayCaller(ctx context.Context, instanceID string) (disabled bool, err error) {
	_, _, disabled, err = s.gatewayPrincipal(ctx, instanceID)
	return disabled, err
}

// gatewayPrincipal authenticates the caller; bound is the gateway_id of a
// standalone Gateway (uuid.Nil for the co-located one).
func (s *Service) gatewayPrincipal(ctx context.Context, instanceID string) (*x509.Certificate, uuid.UUID, bool, error) {
	if ctx == nil {
		return nil, uuid.Nil, false, gatewayUnauthenticated()
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return nil, uuid.Nil, false, gatewayUnauthenticated()
	}
	var verifiedChains [][]*x509.Certificate
	switch info := p.AuthInfo.(type) {
	case credentials.TLSInfo:
		verifiedChains = info.State.VerifiedChains
	case *credentials.TLSInfo:
		if info != nil {
			verifiedChains = info.State.VerifiedChains
		}
	}
	if len(verifiedChains) == 0 {
		return nil, uuid.Nil, false, gatewayUnauthenticated()
	}
	var leaf *x509.Certificate
	for _, chain := range verifiedChains {
		if len(chain) == 0 || chain[0] == nil {
			return nil, uuid.Nil, false, gatewayUnauthenticated()
		}
		if leaf == nil {
			leaf = chain[0]
			continue
		}
		if !bytes.Equal(leaf.Raw, chain[0].Raw) {
			return nil, uuid.Nil, false, gatewayUnauthenticated()
		}
	}
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return nil, uuid.Nil, false, gatewayUnauthenticated()
	}
	uri := leaf.URIs[0].String()
	if uri == s.gatewayWorkloadURISAN {
		return leaf, uuid.Nil, false, nil
	}
	if s.gateways == nil || !strings.HasPrefix(uri, GatewayWorkloadURIPrefix) {
		return nil, uuid.Nil, false, gatewayUnauthenticated()
	}
	id, err := uuid.Parse(strings.TrimPrefix(uri, GatewayWorkloadURIPrefix))
	if err != nil || id == uuid.Nil || id.String() != strings.TrimPrefix(uri, GatewayWorkloadURIPrefix) ||
		instanceID != id.String() || leaf.SerialNumber == nil {
		return nil, uuid.Nil, false, gatewayUnauthenticated()
	}
	disabled, err := s.gateways.AuthorizeGateway(ctx, id, leaf.SerialNumber.Text(16), sha256.Sum256(leaf.Raw))
	if err != nil {
		return nil, uuid.Nil, false, gatewayUnauthenticated()
	}
	return leaf, id, disabled, nil
}

// ReportGatewayReady marks a standalone Gateway online and returns the
// installation ID to every Gateway (ADR 0013 §3.2 step 5, §4.6).
func (s *Service) ReportGatewayReady(ctx context.Context, request *controlv1.ReportGatewayReadyRequest) (*controlv1.ReportGatewayReadyResponse, error) {
	_, bound, disabled, err := s.gatewayPrincipal(ctx, request.GetGatewayInstanceId())
	if err != nil {
		return nil, err
	}
	if disabled {
		return nil, status.Error(codes.FailedPrecondition, "gateway is disabled")
	}
	if invalidMessage(request) || request.GetRequest() == nil || !canonicalUUID(request.GetGatewayInstanceId()) || len(request.GetVersion()) > 64 {
		return nil, invalidRequestError()
	}
	if !canonicalUUID(s.installationID) {
		return nil, status.Error(codes.Unavailable, "installation identity is not configured")
	}
	if bound != uuid.Nil {
		if err := s.gateways.MarkReady(ctx, bound, request.GetVersion()); err != nil {
			return nil, gatewayUnauthenticated()
		}
	}
	return &controlv1.ReportGatewayReadyResponse{InstallationId: s.installationID}, nil
}

// RenewGatewayCertificate renews a standalone Gateway's own certificates.
// The co-located Gateway's certificates come from the installer.
func (s *Service) RenewGatewayCertificate(ctx context.Context, request *controlv1.RenewGatewayCertificateRequest) (*controlv1.RenewGatewayCertificateResponse, error) {
	_, bound, disabled, err := s.gatewayPrincipal(ctx, request.GetGatewayInstanceId())
	if err != nil {
		return nil, err
	}
	if disabled {
		return nil, status.Error(codes.FailedPrecondition, "gateway is disabled")
	}
	if invalidMessage(request) || request.GetRequest() == nil || (request.GetKind() != "client" && request.GetKind() != "server") ||
		len(request.GetCertificateSigningRequestDer()) == 0 {
		return nil, invalidRequestError()
	}
	if bound == uuid.Nil {
		return nil, status.Error(codes.FailedPrecondition, "installer-provisioned gateway certificates are not renewed here")
	}
	renewed, err := s.gateways.Renew(ctx, bound, request.GetKind(), bytes.Clone(request.GetCertificateSigningRequestDer()))
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "gateway certificate renewal refused")
	}
	notAfter, err := timestamp(renewed.NotAfter)
	if err != nil {
		return nil, err
	}
	renewAt, err := timestamp(renewed.RenewAt)
	if err != nil {
		return nil, err
	}
	return &controlv1.RenewGatewayCertificateResponse{CertificatePem: renewed.PEM, ExpirationTime: notAfter, RenewalTime: renewAt}, nil
}

// GetGatewaySettings serves every Gateway, co-located or bound, the trusted
// CDN ranges and node endpoint list of the Gateway management page.
func (s *Service) GetGatewaySettings(ctx context.Context, request *controlv1.GetGatewaySettingsRequest) (*controlv1.GetGatewaySettingsResponse, error) {
	disabled, err := s.gatewayCaller(ctx, request.GetGatewayInstanceId())
	if err != nil {
		return nil, err
	}
	if invalidMessage(request) || request.GetRequest() == nil || !canonicalUUID(request.GetGatewayInstanceId()) {
		return nil, invalidRequestError()
	}
	if s.gateways == nil {
		return nil, status.Error(codes.FailedPrecondition, "gateway settings are not configured")
	}
	settings, err := s.gateways.Settings(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "gateway settings are unavailable")
	}
	response := &controlv1.GetGatewaySettingsResponse{EndpointsVersion: settings.EndpointsVersion, Disabled: disabled}
	for _, item := range settings.TrustedProxies {
		response.TrustedProxies = append(response.TrustedProxies, &controlv1.GatewayTrustedProxyRangeV1{Cidr: item.CIDR, Header: item.Header})
	}
	for _, item := range settings.Endpoints {
		response.Endpoints = append(response.Endpoints, &agentv1.GatewayEndpointV1{Address: item.Address, ServerName: item.ServerName,
			Transport: item.Transport, TunnelHost: item.TunnelHost, EnrollmentAddress: item.EnrollmentAddress})
	}
	return response, nil
}

// logFailure logs a failure the caller cannot act on (Unavailable, Internal)
// with the underlying error, which the RPC response never carries. Refusals
// (not found, denied, conflicts) are expected and stay quiet.
func (s *Service) logFailure(ctx context.Context, rpc, nodeID string, cause, mapped error) error {
	if code := status.Code(mapped); code == codes.Unavailable || code == codes.Internal {
		s.logger.WarnContext(ctx, "control internal rpc failed", "rpc", rpc, "node_id", nodeID, "code", code.String(), "error", cause)
	}
	return mapped
}

func rpcError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	switch {
	case errors.Is(err, nodeidentity.ErrInvalidInput), errors.Is(err, edgeartifact.ErrInvalidRequest):
		return invalidRequestError()
	case errors.Is(err, nodeidentity.ErrInvalidToken), errors.Is(err, nodeidentity.ErrTokenExpired), errors.Is(err, nodeidentity.ErrTokenConsumed):
		return status.Error(codes.Unauthenticated, "enrollment credential is invalid")
	case errors.Is(err, nodeidentity.ErrIdempotencyConflict), errors.Is(err, nodeidentity.ErrRenewalConflict), errors.Is(err, edgeartifact.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, "request conflicts with an existing operation")
	case errors.Is(err, nodeidentity.ErrEnrollmentDenied), errors.Is(err, nodeidentity.ErrAuthorizationExpired),
		errors.Is(err, nodeidentity.ErrRenewalTooEarly), errors.Is(err, nodeidentity.ErrNodeStateDenied), errors.Is(err, edgeartifact.ErrRequestFailed),
		errors.Is(err, edgeartifact.ErrDeploymentIneligible):
		return status.Error(codes.FailedPrecondition, "operation is not currently allowed")
	case errors.Is(err, nodeidentity.ErrGatewayBinding), errors.Is(err, nodeidentity.ErrCertificateRevoked),
		errors.Is(err, edgeartifact.ErrBindingConflict), errors.Is(err, edgeartifact.ErrSiteObjectNotMember):
		return status.Error(codes.PermissionDenied, "operation is not authorized")
	case errors.Is(err, nodeidentity.ErrAuthorizationNotFound), errors.Is(err, nodeidentity.ErrCertificateNotFound):
		return status.Error(codes.NotFound, "requested identity record was not found")
	case errors.Is(err, nodeidentity.ErrIssuanceInProgress), errors.Is(err, edgeartifact.ErrRequestInProgress):
		return status.Error(codes.Aborted, "operation is already in progress")
	case errors.Is(err, edgeartifact.ErrOffsetOutOfRange):
		return status.Error(codes.OutOfRange, "artifact offset is out of range")
	case errors.Is(err, edgeartifact.ErrArtifactIntegrity):
		return status.Error(codes.DataLoss, "artifact integrity verification failed")
	case errors.Is(err, nodeidentity.ErrSigningFailed), errors.Is(err, nodeidentity.ErrPersistence), errors.Is(err, edgeartifact.ErrStorage):
		return status.Error(codes.Unavailable, "control service is temporarily unavailable")
	case errors.Is(err, nodeidentity.ErrCertificateInvalid):
		return status.Error(codes.Internal, "certificate issuance failed")
	default:
		return status.Error(codes.Internal, "internal control service error")
	}
}

func renewalRPCError(err error) error {
	var retry *nodeidentity.RenewalRetryError
	if !errors.As(err, &retry) || retry == nil ||
		(retry.Reason != nodeidentity.RenewalReasonTooEarly && retry.Reason != nodeidentity.RenewalReasonRequestExpired) ||
		retry.RetryAt.IsZero() || retry.RetryAfter < 0 {
		return rpcError(err)
	}
	base := status.New(codes.FailedPrecondition, "operation is not currently allowed")
	detailed, detailErr := base.WithDetails(
		&errdetails.ErrorInfo{
			Reason: retry.Reason,
			Domain: renewalErrorDomain,
			Metadata: map[string]string{
				"retry_at": retry.RetryAt.UTC().Truncate(time.Second).Format(time.RFC3339),
			},
		},
		&errdetails.RetryInfo{RetryDelay: durationpb.New(retry.RetryAfter)},
	)
	if detailErr != nil {
		return base.Err()
	}
	return detailed.Err()
}

func certificateBundle(certificate nodeidentity.Certificate) (*agentv1.CertificateBundle, error) {
	notBefore, err := timestamp(certificate.NotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := timestamp(certificate.NotAfter)
	if err != nil {
		return nil, err
	}
	renewalAt, err := timestamp(certificate.RenewalAt)
	if err != nil {
		return nil, err
	}
	chain := make([][]byte, len(certificate.IssuingChainPEM))
	for index := range certificate.IssuingChainPEM {
		chain[index] = bytes.Clone(certificate.IssuingChainPEM[index])
	}
	return &agentv1.CertificateBundle{
		LeafCertificatePem: bytes.Clone(certificate.LeafCertificatePEM),
		IssuingChainPem:    chain,
		SerialNumber:       certificate.SerialNumber,
		NotBeforeTime:      notBefore,
		ExpirationTime:     notAfter,
		RenewalTime:        renewalAt,
	}, nil
}

func timestamp(value time.Time) (*timestamppb.Timestamp, error) {
	result := timestamppb.New(value)
	if result.CheckValid() != nil {
		return nil, internalResponseError()
	}
	return result, nil
}

func nodeAdministrativeState(value string) (controlv1.NodeAdministrativeState, bool) {
	switch value {
	case "pending":
		return controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_PENDING, true
	case "active":
		return controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, true
	case "draining":
		return controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING, true
	case "disabled":
		return controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DISABLED, true
	case "retired":
		return controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_RETIRED, true
	default:
		return controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_UNSPECIFIED, false
	}
}

func invalidMessage(message proto.Message) bool {
	return message == nil || hasUnknownFields(message.ProtoReflect())
}

func hasUnknownFields(message protoreflect.Message) bool {
	if !message.IsValid() || len(message.GetUnknown()) != 0 {
		return true
	}
	found := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsList() && field.Message() != nil {
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if hasUnknownFields(list.Get(index).Message()) {
					found = true
					return false
				}
			}
			return !found
		}
		if field.IsMap() && field.MapValue().Message() != nil {
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				found = hasUnknownFields(item.Message())
				return !found
			})
			return !found
		}
		if field.Message() != nil {
			found = hasUnknownFields(value.Message())
		}
		return !found
	})
	return found
}

func cloneProtocolVersion(value *commonv1.ProtocolVersion) *commonv1.ProtocolVersion {
	if value == nil {
		return nil
	}
	return proto.Clone(value).(*commonv1.ProtocolVersion)
}

func cloneProtocolRange(value *commonv1.ProtocolVersionRange) *commonv1.ProtocolVersionRange {
	if value == nil {
		return nil
	}
	return proto.Clone(value).(*commonv1.ProtocolVersionRange)
}

func cloneCapabilities(value *agentv1.AgentCapabilities) *agentv1.AgentCapabilities {
	if value == nil {
		return nil
	}
	return proto.Clone(value).(*agentv1.AgentCapabilities)
}

func parseUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, ErrInvalidConfig
	}
	return parsed, nil
}

func canonicalUUID(value string) bool {
	_, err := parseUUID(value)
	return err == nil
}

func validInstallationID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

// mapTelemetrySiteScopes keeps a single-tenant snapshot's sites on its tenant.
// A snapshot without a tenant is a node serving several scopes: each site
// carries its own tenant, and one scope must map to exactly one tenant.
func mapTelemetrySiteScopes(snapshot nodeidentity.AuthorizationSnapshot) ([]*controlv1.TelemetrySiteScope, bool) {
	if len(snapshot.TelemetrySites) > nodeidentity.MaxTelemetrySiteScopes {
		return nil, false
	}
	result := make([]*controlv1.TelemetrySiteScope, len(snapshot.TelemetrySites))
	tenantByScope := make(map[uuid.UUID]uuid.UUID)
	previous := ""
	for index, site := range snapshot.TelemetrySites {
		if site.SiteID == uuid.Nil || site.TenantID == uuid.Nil || site.ConfigurationScopeID == uuid.Nil ||
			site.ConfigVersionID == uuid.Nil || (snapshot.TenantID != uuid.Nil && site.TenantID != snapshot.TenantID) {
			return nil, false
		}
		if tenantID, exists := tenantByScope[site.ConfigurationScopeID]; exists && tenantID != site.TenantID {
			return nil, false
		}
		tenantByScope[site.ConfigurationScopeID] = site.TenantID
		key := site.SiteID.String() + "/" + site.ConfigVersionID.String()
		if previous != "" && key <= previous {
			return nil, false
		}
		previous = key
		result[index] = &controlv1.TelemetrySiteScope{
			SiteId: site.SiteID.String(), TenantId: site.TenantID.String(), ConfigVersionId: site.ConfigVersionID.String(),
			PackageSubscriptionId: optionalUUIDString(site.PackageSubscriptionID),
			ConfigurationScopeId:  site.ConfigurationScopeID.String(),
		}
	}
	return result, true
}

func optionalUUIDString(value uuid.UUID) string {
	if value == uuid.Nil {
		return ""
	}
	return value.String()
}

func validWorkloadURISAN(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || strings.Contains(value, "*") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Scheme != "" && parsed.Host != "" && parsed.Path != "" &&
		!strings.Contains(parsed.Path, "*") &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

func invalidRequestError() error {
	return status.Error(codes.InvalidArgument, "request is invalid")
}

func internalResponseError() error {
	return status.Error(codes.Internal, "control service returned an invalid result")
}
