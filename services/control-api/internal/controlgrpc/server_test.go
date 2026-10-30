package controlgrpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func TestServerAcceptsOnlyTrustedTLS13GatewayClients(t *testing.T) {
	pki := newTestPKI(t)
	service := &fakeControlService{}
	server := newTestServer(t, pki.config(t), service)
	cancel, serveDone := startTestServer(t, server)

	trustedTLS := clientTLS(t, pki, true)
	connection := newTestClient(t, server.Address(), trustedTLS)
	response, err := controlv1.NewControlInternalServiceClient(connection).AuthorizeEnrollment(
		context.Background(), &controlv1.AuthorizeEnrollmentRequest{},
	)
	if err != nil {
		t.Fatalf("trusted Gateway request failed: %v", err)
	}
	if response == nil || service.calls.Load() != 1 {
		t.Fatal("registered ControlInternal service was not invoked")
	}
	healthResponse, err := healthv1.NewHealthClient(connection).Check(context.Background(), &healthv1.HealthCheckRequest{
		Service: controlv1.ControlInternalService_ServiceDesc.ServiceName,
	})
	if err != nil || healthResponse.GetStatus() != healthv1.HealthCheckResponse_SERVING {
		t.Fatalf("ControlInternal health = (%v, %v)", healthResponse, err)
	}
	_ = connection.Close()

	untrustedPKI := newTestPKI(t)
	untrustedTLS := clientTLS(t, pki, false)
	untrustedCertificate, err := tls.LoadX509KeyPair(untrustedPKI.gatewayFile, untrustedPKI.gatewayKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	untrustedTLS.Certificates = []tls.Certificate{untrustedCertificate}
	assertHandshakeRejected(t, server.Address(), untrustedTLS)

	missingCertificateTLS := clientTLS(t, pki, false)
	assertHandshakeRejected(t, server.Address(), missingCertificateTLS)

	oldTLS := clientTLS(t, pki, true)
	oldTLS.MinVersion = tls.VersionTLS12
	oldTLS.MaxVersion = tls.VersionTLS12
	assertHandshakeRejected(t, server.Address(), oldTLS)
	if service.calls.Load() != 1 {
		t.Fatalf("untrusted handshakes reached service, calls = %d", service.calls.Load())
	}

	cancel()
	if err := waitServe(t, serveDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve cancellation error = %v, want context.Canceled", err)
	}
	if err := server.Ready(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("readiness after cancellation = %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close error = %v", err)
	}
	if err := server.Serve(context.Background()); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve after Close error = %v, want ErrServerClosed", err)
	}
}

func TestServerEnforcesReceiveAndSendMessageLimits(t *testing.T) {
	pki := newTestPKI(t)
	config := pki.config(t)
	config.MaxReceiveMessageBytes = 1024
	config.MaxSendMessageBytes = 1024
	service := &fakeControlService{
		response: &controlv1.AuthorizeEnrollmentResponse{ArtifactEncryptionKeyId: strings.Repeat("x", 2048)},
	}
	server := newTestServer(t, config, service)
	cancel, serveDone := startTestServer(t, server)
	defer func() {
		cancel()
		_ = waitServe(t, serveDone)
	}()

	connection := newTestClient(t, server.Address(), clientTLS(t, pki, true))
	defer connection.Close()
	client := controlv1.NewControlInternalServiceClient(connection)
	ctx, cancelCall := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelCall()
	_, err := client.AuthorizeEnrollment(ctx, &controlv1.AuthorizeEnrollmentRequest{
		EnrollmentToken: strings.Repeat("x", 2048),
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized receive status = %v", status.Code(err))
	}
	if service.calls.Load() != 0 {
		t.Fatal("oversized request reached service")
	}

	_, err = client.AuthorizeEnrollment(ctx, &controlv1.AuthorizeEnrollmentRequest{})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized send status = %v", status.Code(err))
	}
	if service.calls.Load() != 1 {
		t.Fatal("small request did not reach service")
	}
}

func TestServerReportsUnexpectedListenerFailure(t *testing.T) {
	pki := newTestPKI(t)
	server := newTestServer(t, pki.config(t), &fakeControlService{})
	_, serveDone := startTestServer(t, server)
	if err := server.listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitServe(t, serveDone); !errors.Is(err, ErrServeFailed) {
		t.Fatalf("Serve error = %v, want ErrServeFailed", err)
	}
	if err := server.Ready(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("readiness after listener failure = %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerGracefulStopIsBoundedAndCloseIsConcurrentSafe(t *testing.T) {
	pki := newTestPKI(t)
	config := pki.config(t)
	config.ShutdownTimeout = 30 * time.Millisecond
	service := &fakeControlService{started: make(chan struct{}), release: make(chan struct{})}
	server := newTestServer(t, config, service)
	cancel, serveDone := startTestServer(t, server)

	connection := newTestClient(t, server.Address(), clientTLS(t, pki, true))
	requestDone := make(chan error, 1)
	go func() {
		_, err := controlv1.NewControlInternalServiceClient(connection).AuthorizeEnrollment(
			context.Background(), &controlv1.AuthorizeEnrollmentRequest{},
		)
		requestDone <- err
	}()
	select {
	case <-service.started:
	case <-time.After(time.Second):
		t.Fatal("blocking request did not reach service")
	}

	startedAt := time.Now()
	cancel()
	err := waitServe(t, serveDone)
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("forced shutdown exceeded bound: %s", elapsed)
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrGracefulStopTimedOut) {
		t.Fatalf("Serve error = %v, want cancellation and graceful timeout", err)
	}
	close(service.release)
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request goroutine remained blocked after forced shutdown")
	}
	_ = connection.Close()

	var wait sync.WaitGroup
	errorsSeen := make(chan error, 32)
	for index := 0; index < 16; index++ {
		wait.Add(2)
		go func() {
			defer wait.Done()
			errorsSeen <- server.Close()
		}()
		go func() {
			defer wait.Done()
			_ = server.Ready()
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for closeErr := range errorsSeen {
		if !errors.Is(closeErr, ErrGracefulStopTimedOut) {
			t.Fatalf("idempotent Close error = %v", closeErr)
		}
	}
	if err := server.Ready(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("readiness after Close = %v", err)
	}
}

func TestNewRejectsOccupiedListenerAndCanceledStartup(t *testing.T) {
	pki := newTestPKI(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	config := pki.config(t)
	config.ListenAddress = listener.Addr().String()
	_, err = NewWithClock(context.Background(), config, &fakeControlService{}, func() time.Time { return testNow })
	if err == nil || err.Error() != "bind ControlInternal gRPC listener" {
		t.Fatalf("occupied listener error = %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	config.ListenAddress = unusedAddress(t)
	_, err = NewWithClock(canceled, config, &fakeControlService{}, func() time.Time { return testNow })
	if err == nil || err.Error() != "start ControlInternal gRPC server" {
		t.Fatalf("canceled startup error = %v", err)
	}
}

func TestServerRejectsConcurrentServeAndTypedNilService(t *testing.T) {
	pki := newTestPKI(t)
	server := newTestServer(t, pki.config(t), &fakeControlService{})
	cancel, serveDone := startTestServer(t, server)
	if err := server.Serve(context.Background()); !errors.Is(err, ErrAlreadyServed) {
		t.Fatalf("second Serve error = %v, want ErrAlreadyServed", err)
	}
	cancel()
	_ = waitServe(t, serveDone)

	var service *fakeControlService
	_, err := NewWithClock(context.Background(), pki.config(t), service, func() time.Time { return testNow })
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("typed nil service error = %v", err)
	}
}

type fakeControlService struct {
	controlv1.UnimplementedControlInternalServiceServer

	calls    atomic.Int32
	started  chan struct{}
	release  chan struct{}
	response *controlv1.AuthorizeEnrollmentResponse
}

func (s *fakeControlService) AuthorizeEnrollment(context.Context, *controlv1.AuthorizeEnrollmentRequest) (*controlv1.AuthorizeEnrollmentResponse, error) {
	s.calls.Add(1)
	if s.started != nil {
		close(s.started)
		<-s.release
	}
	if s.response != nil {
		return s.response, nil
	}
	return &controlv1.AuthorizeEnrollmentResponse{}, nil
}

func newTestServer(t *testing.T, config Config, service controlv1.ControlInternalServiceServer) *Server {
	t.Helper()
	server, err := NewWithClock(context.Background(), config, service, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func startTestServer(t *testing.T, server *Server) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	deadline := time.Now().Add(time.Second)
	for server.Ready() != nil {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("server did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	return cancel, done
}

func waitServe(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within the test bound")
		return nil
	}
}

func clientTLS(t *testing.T, pki testPKI, includeCertificate bool) *tls.Config {
	t.Helper()
	rootPEM, err := os.ReadFile(pki.rootFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("failed to load test server root")
	}
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: "localhost",
	}
	if includeCertificate {
		certificate, err := tls.LoadX509KeyPair(pki.gatewayFile, pki.gatewayKeyFile)
		if err != nil {
			t.Fatal(err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config
}

func newTestClient(t *testing.T, address string, tlsConfig *tls.Config) *grpc.ClientConn {
	t.Helper()
	connection, err := grpc.NewClient(
		"passthrough:///"+address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func assertHandshakeRejected(t *testing.T, address string, tlsConfig *tls.Config) {
	t.Helper()
	connection := newTestClient(t, address, tlsConfig)
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := controlv1.NewControlInternalServiceClient(connection).AuthorizeEnrollment(
		ctx, &controlv1.AuthorizeEnrollmentRequest{},
	)
	if err == nil {
		t.Fatal("untrusted TLS handshake reached the service")
	}
}

func unusedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
