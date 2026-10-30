package identityverificationissuerhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maximumTLSMaterialBytes   = 4 << 20
	minimumServerCertValidity = time.Hour
	listenerStartupTimeout    = 10 * time.Second
	listenerShutdownTimeout   = 10 * time.Second
)

var (
	ErrListenerInvalidConfig = errors.New("identity verification issuer listener configuration is invalid")
	ErrListenerNotReady      = errors.New("identity verification issuer listener is not ready")
	ErrListenerAlreadyRun    = errors.New("identity verification issuer listener was already run")
	ErrListenerStopped       = errors.New("identity verification issuer listener stopped unexpectedly")
)

type ListenerConfig struct {
	ListenAddress         string
	ServerCertificateFile string
	ServerPrivateKeyFile  string
	ClientCAFile          string
	Clock                 Clock
}

type Listener struct {
	server   *http.Server
	listener net.Listener
	ready    atomic.Bool
	started  atomic.Bool
	closed   atomic.Bool
	closeMu  sync.Mutex
}

func NewListener(ctx context.Context, config ListenerConfig, handler http.Handler) (*Listener, error) {
	if ctx == nil || nilInterface(handler) {
		return nil, ErrListenerInvalidConfig
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if err := validateListenerConfig(config); err != nil {
		return nil, err
	}
	tlsConfig, err := loadListenerTLS(config)
	if err != nil {
		return nil, err
	}
	startup, cancel := context.WithTimeout(ctx, listenerStartupTimeout)
	defer cancel()
	listener, err := (&net.ListenConfig{}).Listen(startup, "tcp", config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: bind listener", ErrListenerInvalidConfig)
	}
	return &Listener{
		server: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		},
		listener: tls.NewListener(listener, tlsConfig),
	}, nil
}

func (listener *Listener) Run(ctx context.Context) error {
	if listener == nil || ctx == nil || listener.server == nil || listener.listener == nil {
		return ErrListenerInvalidConfig
	}
	if !listener.started.CompareAndSwap(false, true) {
		return ErrListenerAlreadyRun
	}
	if listener.closed.Load() {
		return ErrListenerStopped
	}
	result := make(chan error, 1)
	listener.ready.Store(true)
	go func() {
		result <- listener.server.Serve(listener.listener)
	}()
	select {
	case err := <-result:
		listener.ready.Store(false)
		if listener.closed.Load() && (errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)) {
			return nil
		}
		if err == nil {
			return ErrListenerStopped
		}
		return fmt.Errorf("%w: %v", ErrListenerStopped, err)
	case <-ctx.Done():
		listener.ready.Store(false)
		shutdown, cancel := context.WithTimeout(context.Background(), listenerShutdownTimeout)
		err := listener.server.Shutdown(shutdown)
		cancel()
		if err != nil {
			_ = listener.server.Close()
		}
		serveErr := <-result
		if err != nil {
			return fmt.Errorf("%w: shutdown", ErrListenerStopped)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			return fmt.Errorf("%w: %v", ErrListenerStopped, serveErr)
		}
		return ctx.Err()
	}
}

func (listener *Listener) Ready() error {
	if listener == nil || !listener.ready.Load() || listener.closed.Load() {
		return ErrListenerNotReady
	}
	return nil
}

func (listener *Listener) Address() string {
	if listener == nil || listener.listener == nil {
		return ""
	}
	return listener.listener.Addr().String()
}

func (listener *Listener) Close() error {
	if listener == nil {
		return nil
	}
	listener.closeMu.Lock()
	defer listener.closeMu.Unlock()
	if listener.closed.Swap(true) {
		return nil
	}
	listener.ready.Store(false)
	serverErr := listener.server.Close()
	listenerErr := listener.listener.Close()
	if errors.Is(serverErr, http.ErrServerClosed) {
		serverErr = nil
	}
	if errors.Is(listenerErr, net.ErrClosed) {
		listenerErr = nil
	}
	return errors.Join(serverErr, listenerErr)
}

func validateListenerConfig(config ListenerConfig) error {
	if config.Clock == nil || config.Clock().IsZero() {
		return ErrListenerInvalidConfig
	}
	host, portText, err := net.SplitHostPort(config.ListenAddress)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || host == "" || port < 1 || port > 65535 ||
		strings.TrimSpace(config.ListenAddress) != config.ListenAddress {
		return ErrListenerInvalidConfig
	}
	for _, path := range []string{config.ServerCertificateFile, config.ServerPrivateKeyFile, config.ClientCAFile} {
		if path == "" || strings.TrimSpace(path) != path {
			return ErrListenerInvalidConfig
		}
	}
	return nil
}

func loadListenerTLS(config ListenerConfig) (*tls.Config, error) {
	now := config.Clock().UTC()
	certificatePEM, err := readTLSMaterial(config.ServerCertificateFile, false)
	if err != nil {
		return nil, ErrListenerInvalidConfig
	}
	privateKeyPEM, err := readTLSMaterial(config.ServerPrivateKeyFile, true)
	if err != nil {
		return nil, ErrListenerInvalidConfig
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, ErrListenerInvalidConfig
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.IsCA || now.Before(leaf.NotBefore) ||
		!now.Add(minimumServerCertValidity).Before(leaf.NotAfter) ||
		!certificateAllowsUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return nil, ErrListenerInvalidConfig
	}
	child := leaf
	for _, rawIssuer := range certificate.Certificate[1:] {
		issuer, err := x509.ParseCertificate(rawIssuer)
		if err != nil || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) || child.CheckSignatureFrom(issuer) != nil {
			return nil, ErrListenerInvalidConfig
		}
		child = issuer
	}
	certificate.Leaf = leaf
	clientCAs, err := loadListenerClientCAs(config.ClientCAFile, now)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		Time:         config.Clock,
	}, nil
}

func readTLSMaterial(path string, private bool) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumTLSMaterialBytes ||
		private && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrListenerInvalidConfig
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumTLSMaterialBytes+1))
	if err != nil || len(contents) == 0 || len(contents) > maximumTLSMaterialBytes {
		return nil, ErrListenerInvalidConfig
	}
	return contents, nil
}

func loadListenerClientCAs(path string, now time.Time) (*x509.CertPool, error) {
	contents, err := readTLSMaterial(path, false)
	if err != nil {
		return nil, ErrListenerInvalidConfig
	}
	pool := x509.NewCertPool()
	count := 0
	for remaining := bytes.TrimSpace(contents); len(remaining) > 0; {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrListenerInvalidConfig
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
			!certificateAllowsUsage(certificate, x509.ExtKeyUsageClientAuth) {
			return nil, ErrListenerInvalidConfig
		}
		pool.AddCert(certificate)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, ErrListenerInvalidConfig
	}
	return pool, nil
}

func certificateAllowsUsage(certificate *x509.Certificate, required x509.ExtKeyUsage) bool {
	if certificate == nil {
		return false
	}
	if len(certificate.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == required || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
