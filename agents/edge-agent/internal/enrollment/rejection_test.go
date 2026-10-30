package enrollment

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func enrollmentCapabilities() *agentv1.AgentCapabilities {
	return &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "test", OperatingSystem: "linux", Architecture: "amd64",
		Features: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 4},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE, ApiVersion: 1},
		}}
}

// An enrollment the control plane refuses is not retried, also not with a smaller capability set for a control
// plane whose table predates them (the baseline is 1.0.35).
func TestRunDoesNotRetryRejections(t *testing.T) {
	for _, test := range []struct {
		name         string
		capabilities *agentv1.AgentCapabilities
		err          error
	}{
		{"unknown capability", enrollmentCapabilities(), status.Error(codes.InvalidArgument, "request is invalid")},
		{"consumed token", enrollmentCapabilities(), status.Error(codes.Unauthenticated, "enrollment credential is invalid")},
		{"transport", enrollmentCapabilities(), errors.New("connection lost after commit")},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			config := fixture.config(t)
			config.Capabilities = test.capabilities
			attempts := 0
			config.Dial = func(context.Context, Config) (RPC, io.Closer, error) {
				return rpcFunc(func(context.Context, *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
					attempts++
					return nil, test.err
				}), io.NopCloser(bytes.NewReader(nil)), nil
			}
			if _, err := Run(context.Background(), config, testToken); !errors.Is(err, ErrEnrollmentRejected) {
				t.Fatalf("Run() error = %v", err)
			}
			if attempts != 1 {
				t.Fatalf("attempts = %d, want 1", attempts)
			}
		})
	}
}
