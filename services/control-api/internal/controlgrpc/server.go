package controlgrpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

var (
	ErrNotReady             = errors.New("ControlInternal gRPC server is not ready")
	ErrAlreadyServed        = errors.New("ControlInternal gRPC server was already served")
	ErrServerClosed         = errors.New("ControlInternal gRPC server is closed")
	ErrServeFailed          = errors.New("ControlInternal gRPC server stopped unexpectedly")
	ErrGracefulStopTimedOut = errors.New("ControlInternal gRPC graceful shutdown timed out")
)

type Server struct {
	grpcServer      *grpc.Server
	healthServer    *health.Server
	listener        net.Listener
	remote          net.Listener
	remoteCancel    context.CancelFunc
	shutdownTimeout time.Duration

	ready atomic.Bool
	mu    sync.Mutex
	state serverState

	stopOnce sync.Once
	stopErr  error
	stopDone chan struct{}
}

type serverState uint8

const (
	serverCreated serverState = iota
	serverServing
	serverClosed
)

func New(ctx context.Context, config Config, service controlv1.ControlInternalServiceServer) (*Server, error) {
	return NewWithClock(ctx, config, service, time.Now)
}

func NewWithClock(ctx context.Context, config Config, service controlv1.ControlInternalServiceServer, now func() time.Time) (*Server, error) {
	if ctx == nil {
		return nil, invalidConfig("startup context is required")
	}
	if nilService(service) {
		return nil, invalidConfig("ControlInternal service is required")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	startupContext, cancel := context.WithTimeout(ctx, config.StartupTimeout)
	defer cancel()
	if err := startupContext.Err(); err != nil {
		return nil, stageError{stage: "start ControlInternal gRPC server", cause: err}
	}
	tlsConfig, err := LoadTLS(config, now)
	if err != nil {
		return nil, err
	}
	if err := startupContext.Err(); err != nil {
		return nil, stageError{stage: "start ControlInternal gRPC server", cause: err}
	}
	grpcServer := newGRPCServer(config, tlsConfig)
	controlv1.RegisterControlInternalServiceServer(grpcServer, service)
	healthServer := health.NewServer()
	healthServer.SetServingStatus(controlv1.ControlInternalService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_NOT_SERVING)
	healthv1.RegisterHealthServer(grpcServer, healthServer)

	listener, err := (&net.ListenConfig{}).Listen(startupContext, "tcp", config.ListenAddress)
	if err != nil {
		grpcServer.Stop()
		return nil, stageError{stage: "bind ControlInternal gRPC listener", cause: err}
	}
	return &Server{
		grpcServer: grpcServer, healthServer: healthServer, listener: listener,
		shutdownTimeout: config.ShutdownTimeout, stopDone: make(chan struct{}),
	}, nil
}

func newGRPCServer(config Config, tlsConfig *tls.Config) *grpc.Server {
	return grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.MaxRecvMsgSize(config.MaxReceiveMessageBytes),
		grpc.MaxSendMsgSize(config.MaxSendMessageBytes),
		grpc.MaxConcurrentStreams(config.MaxConcurrentStreams),
		grpc.ConnectionTimeout(config.ConnectionTimeout),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time: config.KeepaliveTime, Timeout: config.KeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: config.MinimumClientPingTime, PermitWithoutStream: false,
		}),
	)
}

// AttachRemote binds the standalone Gateway listener (GW-09) before Serve.
// The allow list is loaded once now and refreshed in the background.
func (s *Server) AttachRemote(ctx context.Context, config RemoteConfig) error {
	if s == nil || ctx == nil || config.AllowedSources == nil {
		return invalidConfig("remote listener requires a context and an allow list")
	}
	if err := validateRemoteListenAddress(config.ListenAddress); err != nil {
		return err
	}
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 15 * time.Second
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != serverCreated || s.remote != nil {
		return ErrAlreadyServed
	}
	filter := &sourceFilter{}
	loadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := config.AllowedSources(loadCtx)
	cancel()
	if err != nil {
		return stageError{stage: "load ControlInternal remote allow list", cause: err}
	}
	filter.set(ips)
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", config.ListenAddress)
	if err != nil {
		return stageError{stage: "bind ControlInternal remote listener", cause: err}
	}
	refreshCtx, refreshCancel := context.WithCancel(context.Background())
	go filter.refresh(refreshCtx, config.AllowedSources, config.RefreshInterval)
	s.remote, s.remoteCancel = &filteredListener{Listener: listener, filter: filter}, refreshCancel
	return nil
}

// RemoteAddress is the bound remote listener address ("" when not attached).
func (s *Server) RemoteAddress() string {
	if s == nil || s.remote == nil {
		return ""
	}
	return s.remote.Addr().String()
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || ctx == nil {
		return invalidConfig("serve context and server are required")
	}
	if err := s.beginServing(); err != nil {
		return err
	}
	serveResult := make(chan error, 2)
	go func() {
		serveResult <- s.grpcServer.Serve(s.listener)
	}()
	if s.remote != nil {
		go func() {
			serveResult <- s.grpcServer.Serve(s.remote)
		}()
	}

	select {
	case <-ctx.Done():
		s.ready.Store(false)
		shutdownErr := s.shutdown(true)
		if shutdownErr == nil {
			<-serveResult
		}
		if shutdownErr != nil {
			return errors.Join(ctx.Err(), shutdownErr)
		}
		return ctx.Err()
	case <-s.stopDone:
		if s.stopErr == nil {
			<-serveResult
		}
		return s.stopErr
	case err := <-serveResult:
		s.ready.Store(false)
		if s.isClosing() {
			return s.shutdown(true)
		}
		_ = s.shutdown(false)
		if err == nil || errors.Is(err, grpc.ErrServerStopped) {
			return ErrServeFailed
		}
		return fmt.Errorf("%w: %v", ErrServeFailed, err)
	}
}

func (s *Server) Ready() error {
	if s == nil || !s.ready.Load() {
		return ErrNotReady
	}
	return nil
}

func (s *Server) Address() string {
	if s == nil || s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	return s.shutdown(true)
}

func (s *Server) beginServing() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case serverCreated:
		s.state = serverServing
		s.healthServer.SetServingStatus(controlv1.ControlInternalService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_SERVING)
		s.ready.Store(true)
		return nil
	case serverServing:
		return ErrAlreadyServed
	default:
		return ErrServerClosed
	}
}

func (s *Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == serverClosed
}

func (s *Server) shutdown(graceful bool) error {
	s.stopOnce.Do(func() {
		defer close(s.stopDone)
		s.ready.Store(false)
		s.healthServer.SetServingStatus(controlv1.ControlInternalService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_NOT_SERVING)
		s.mu.Lock()
		s.state = serverClosed
		s.mu.Unlock()
		if s.remoteCancel != nil {
			s.remoteCancel()
		}
		if !graceful {
			_ = s.listener.Close()
			if s.remote != nil {
				_ = s.remote.Close()
			}
			go s.grpcServer.Stop()
			return
		}

		stopped := make(chan struct{})
		go func() {
			s.grpcServer.GracefulStop()
			close(stopped)
		}()
		timer := time.NewTimer(s.shutdownTimeout)
		defer timer.Stop()
		select {
		case <-stopped:
		case <-timer.C:
			s.stopErr = ErrGracefulStopTimedOut
			go s.grpcServer.Stop()
		}
		_ = s.listener.Close()
		if s.remote != nil {
			_ = s.remote.Close()
		}
	})
	return s.stopErr
}

func nilService(service controlv1.ControlInternalServiceServer) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	return value.Kind() == reflect.Pointer && value.IsNil()
}
