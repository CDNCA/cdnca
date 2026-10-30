package gateway

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type renewalErrorControl struct {
	ControlPlane
	err error
}

func (control renewalErrorControl) RenewNodeCertificate(
	context.Context,
	*controlv1.RenewNodeCertificateRequest,
) (*controlv1.RenewNodeCertificateResponse, error) {
	return nil, control.err
}

func TestRenewCertificatePreservesControlRetryDetails(t *testing.T) {
	retryAt := time.Date(2026, 9, 16, 1, 7, 21, 0, time.UTC)
	base := status.New(codes.FailedPrecondition, "operation is not currently allowed")
	detailed, err := base.WithDetails(
		&errdetails.ErrorInfo{
			Reason: "renewal_request_expired",
			Domain: "cdnca.com/node-certificate-renewal",
			Metadata: map[string]string{
				"retry_at": retryAt.Format(time.RFC3339),
			},
		},
		&errdetails.RetryInfo{RetryDelay: durationpb.New(0)},
	)
	if err != nil {
		t.Fatal(err)
	}
	control := renewalErrorControl{ControlPlane: defaultFakeControl(), err: detailed.Err()}
	servers := startTestServers(t, control)
	connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, rpcErr := agentv1.NewAgentGatewayServiceClient(connection).RenewCertificate(ctx, &agentv1.RenewCertificateRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: uuid.NewString(),
			SentTime:  timestamppb.Now(),
		},
		CurrentSerialNumber:          "a",
		CertificateSigningRequestDer: []byte{1},
	})
	got := status.Convert(rpcErr)
	if got.Code() != codes.FailedPrecondition || got.Message() != base.Message() {
		t.Fatalf("RenewCertificate() status = %s %q", got.Code(), got.Message())
	}
	var gotInfo *errdetails.ErrorInfo
	var gotRetry *errdetails.RetryInfo
	for _, detail := range got.Details() {
		switch typed := detail.(type) {
		case *errdetails.ErrorInfo:
			gotInfo = typed
		case *errdetails.RetryInfo:
			gotRetry = typed
		}
	}
	if gotInfo == nil || gotInfo.GetReason() != "renewal_request_expired" ||
		gotInfo.GetDomain() != "cdnca.com/node-certificate-renewal" ||
		gotInfo.GetMetadata()["retry_at"] != retryAt.Format(time.RFC3339) {
		t.Fatalf("ErrorInfo = %#v", gotInfo)
	}
	if gotRetry == nil || gotRetry.GetRetryDelay() == nil || gotRetry.GetRetryDelay().AsDuration() != 0 {
		t.Fatalf("RetryInfo = %#v", gotRetry)
	}
}
