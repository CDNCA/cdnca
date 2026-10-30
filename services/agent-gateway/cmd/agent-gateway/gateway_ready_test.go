package main

import (
	"context"
	"testing"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc"
)

type readyClient struct {
	controlv1.ControlInternalServiceClient
	installationID string
	request        *controlv1.ReportGatewayReadyRequest
}

func (c *readyClient) ReportGatewayReady(_ context.Context, request *controlv1.ReportGatewayReadyRequest, _ ...grpc.CallOption) (*controlv1.ReportGatewayReadyResponse, error) {
	c.request = request
	return &controlv1.ReportGatewayReadyResponse{InstallationId: c.installationID}, nil
}

// The tunnel audience comes from ControlInternal, not from the Gateway's
// instance ID (a bound Gateway's instance ID is its gateway_id).
func TestReportGatewayReadyReturnsTheInstallationAudience(t *testing.T) {
	const instance = "11111111-1111-4111-8111-111111111111"
	client := &readyClient{installationID: "22222222-2222-4222-8222-222222222222"}
	audience, err := reportGatewayReady(t.Context(), client, instance, "1.0.35")
	if err != nil || audience != client.installationID {
		t.Fatalf("audience = %q, %v", audience, err)
	}
	if client.request.GetGatewayInstanceId() != instance || client.request.GetVersion() != "1.0.35" || client.request.GetRequest().GetRequestId() == "" {
		t.Fatalf("request = %v", client.request)
	}
	for _, bad := range []string{"", "not-a-uuid", "00000000-0000-0000-0000-000000000000", "22222222-2222-4222-8222-22222222222A"} {
		client.installationID = bad
		if _, err := reportGatewayReady(t.Context(), client, instance, "1.0.35"); err == nil {
			t.Errorf("installation ID %q accepted", bad)
		}
	}
}
