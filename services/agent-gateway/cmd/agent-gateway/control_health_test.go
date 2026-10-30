package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

func TestVerifyControlHealthRequiresNamedServiceToBeServing(t *testing.T) {
	tests := []struct {
		name     string
		status   healthv1.HealthCheckResponse_ServingStatus
		register bool
		wantErr  bool
	}{
		{name: "serving", status: healthv1.HealthCheckResponse_SERVING, register: true},
		{name: "not serving", status: healthv1.HealthCheckResponse_NOT_SERVING, register: true, wantErr: true},
		{name: "service unknown", status: healthv1.HealthCheckResponse_SERVICE_UNKNOWN, register: true, wantErr: true},
		{name: "health unregistered", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := grpc.NewServer()
			if test.register {
				healthServer := health.NewServer()
				healthServer.SetServingStatus(controlv1.ControlInternalService_ServiceDesc.ServiceName, test.status)
				healthv1.RegisterHealthServer(server, healthServer)
			}
			connection := dialHealthTestServer(t, server)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := verifyControlHealth(ctx, connection)
			if test.wantErr && err == nil {
				t.Fatal("unhealthy ControlInternal service was accepted")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("serving ControlInternal service rejected: %v", err)
			}
		})
	}
}

func TestVerifyControlHealthHonorsContextDeadline(t *testing.T) {
	server := grpc.NewServer()
	healthv1.RegisterHealthServer(server, blockingHealthServer{})
	connection := dialHealthTestServer(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	if err := verifyControlHealth(ctx, connection); err == nil {
		t.Fatal("timed-out health check was accepted")
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("health check ignored its deadline: %s", elapsed)
	}
}

func TestControlHealthStartupErrorIsSanitized(t *testing.T) {
	err := stageError{stage: "ControlInternal health check failed", err: errors.New("rpc detail do-not-log")}
	if err.Error() != "ControlInternal health check failed" || strings.Contains(err.Error(), "do-not-log") {
		t.Fatalf("health startup error leaked RPC details: %v", err)
	}
}

type blockingHealthServer struct {
	healthv1.UnimplementedHealthServer
}

func (blockingHealthServer) Check(ctx context.Context, _ *healthv1.HealthCheckRequest) (*healthv1.HealthCheckResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func dialHealthTestServer(t *testing.T, server *grpc.Server) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		<-serveDone
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := grpc.DialContext(
		ctx,
		"passthrough:///control-health",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}
