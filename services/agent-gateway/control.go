package gateway

import (
	"context"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
)

// ArtifactStream is the only streaming operation the Gateway needs from the
// control plane. Recv must unblock when the context passed to FetchArtifact is
// canceled; the generated gRPC client provides that guarantee.
type ArtifactStream interface {
	Recv() (*controlv1.FetchArtifactResponse, error)
}

// SiteObjectStream is a FetchSiteObjects response stream from the control
// plane (same cancellation guarantee as ArtifactStream).
type SiteObjectStream interface {
	Recv() (*controlv1.FetchSiteObjectsResponse, error)
}

// SiteObjectControlPlane is implemented by control planes that serve site
// runtime v8 objects; GeneratedControlClient does.
type SiteObjectControlPlane interface {
	FetchSiteObjects(context.Context, *controlv1.FetchSiteObjectsRequest) (SiteObjectStream, error)
}

// CertificateRecoveryControlPlane is implemented by control planes that
// re-issue expired node certificates (ADR 0013 GW-02); GeneratedControlClient does.
type CertificateRecoveryControlPlane interface {
	RecoverNodeCertificate(context.Context, *controlv1.RecoverNodeCertificateRequest) (*controlv1.RecoverNodeCertificateResponse, error)
}

// ControlPlane deliberately mirrors only decisions represented by the
// versioned ControlInternal protobuf contract.
type ControlPlane interface {
	AuthorizeEnrollment(context.Context, *controlv1.AuthorizeEnrollmentRequest) (*controlv1.AuthorizeEnrollmentResponse, error)
	CompleteEnrollment(context.Context, *controlv1.CompleteEnrollmentRequest) (*controlv1.CompleteEnrollmentResponse, error)
	RenewNodeCertificate(context.Context, *controlv1.RenewNodeCertificateRequest) (*controlv1.RenewNodeCertificateResponse, error)
	GetNodeAuthorization(context.Context, *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error)
	FetchArtifact(context.Context, *controlv1.FetchArtifactRequest) (ArtifactStream, error)
}

// GeneratedControlClient adapts the generated gRPC client without exposing a
// database, cache, or message bus to the Gateway.
type GeneratedControlClient struct {
	Client controlv1.ControlInternalServiceClient
}

func (c GeneratedControlClient) AuthorizeEnrollment(ctx context.Context, request *controlv1.AuthorizeEnrollmentRequest) (*controlv1.AuthorizeEnrollmentResponse, error) {
	return c.Client.AuthorizeEnrollment(ctx, request)
}

func (c GeneratedControlClient) CompleteEnrollment(ctx context.Context, request *controlv1.CompleteEnrollmentRequest) (*controlv1.CompleteEnrollmentResponse, error) {
	return c.Client.CompleteEnrollment(ctx, request)
}

func (c GeneratedControlClient) RenewNodeCertificate(ctx context.Context, request *controlv1.RenewNodeCertificateRequest) (*controlv1.RenewNodeCertificateResponse, error) {
	return c.Client.RenewNodeCertificate(ctx, request)
}

func (c GeneratedControlClient) RecoverNodeCertificate(ctx context.Context, request *controlv1.RecoverNodeCertificateRequest) (*controlv1.RecoverNodeCertificateResponse, error) {
	return c.Client.RecoverNodeCertificate(ctx, request)
}

func (c GeneratedControlClient) GetNodeAuthorization(ctx context.Context, request *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	return c.Client.GetNodeAuthorization(ctx, request)
}

func (c GeneratedControlClient) FetchArtifact(ctx context.Context, request *controlv1.FetchArtifactRequest) (ArtifactStream, error) {
	return c.Client.FetchArtifact(ctx, request)
}

func (c GeneratedControlClient) FetchSiteObjects(ctx context.Context, request *controlv1.FetchSiteObjectsRequest) (SiteObjectStream, error) {
	return c.Client.FetchSiteObjects(ctx, request)
}
