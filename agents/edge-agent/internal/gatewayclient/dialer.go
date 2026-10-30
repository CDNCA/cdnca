package gatewayclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewaytunnel"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Connection interface {
	Client() agentv1.AgentGatewayServiceClient
	Close() error
}

type Dialer interface {
	Dial(context.Context) (Connection, error)
}

type MTLSDialerConfig struct {
	Address               string
	ServerName            string
	RootCAFile            string
	ClientCertificateFile string
	ClientPrivateKeyFile  string
	MaximumReceiveBytes   int
	MaximumSendBytes      int
	// Transport is "grpc" (direct, default) or "ws" (WebSocket tunnel to
	// the same address, ADR 0013 §4.2). TunnelHost is the outer SNI/Host
	// (CDN name; empty = Address host) and TunnelAudience the installation
	// ID signed into the upgrade token.
	Transport      string
	TunnelHost     string
	TunnelAudience string
}

type mtlsDialer struct {
	address string
	options []grpc.DialOption
}

type grpcConnection struct {
	connection *grpc.ClientConn
	client     agentv1.AgentGatewayServiceClient
}

func (c *grpcConnection) Client() agentv1.AgentGatewayServiceClient { return c.client }
func (c *grpcConnection) Close() error                              { return c.connection.Close() }

func NewMTLSDialer(config MTLSDialerConfig) (Dialer, error) {
	if config.Address == "" || config.ServerName == "" || config.MaximumReceiveBytes <= 0 || config.MaximumSendBytes <= 0 {
		return nil, fmt.Errorf("%w: incomplete mTLS dialer configuration", ErrInvalidConfiguration)
	}
	rootPEM, err := readSecureRegularFile(config.RootCAFile, false)
	if err != nil {
		return nil, err
	}
	certificatePEM, err := readSecureRegularFile(config.ClientCertificateFile, false)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := readSecureRegularFile(config.ClientPrivateKeyFile, false)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("%w: gateway CA file contains no certificate", ErrInvalidConfiguration)
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   config.ServerName,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
	}
	options := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(config.MaximumReceiveBytes),
			grpc.MaxCallSendMsgSize(config.MaximumSendBytes),
		),
	}
	address := config.Address
	if config.Transport == gatewaytunnel.TransportWS {
		tunnel, err := gatewaytunnel.NodeTunnel(config.Address, config.TunnelHost, config.TunnelAudience, rootPEM, certificate)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
		}
		options = append(options, grpc.WithContextDialer(tunnel))
		address = "passthrough:///" + config.Address
	} else if !gatewaytunnel.ValidTransport(config.Transport) {
		return nil, fmt.Errorf("%w: gateway transport must be grpc or ws", ErrInvalidConfiguration)
	}
	return &mtlsDialer{address: address, options: options}, nil
}

func (d *mtlsDialer) Dial(ctx context.Context) (Connection, error) {
	connection, err := grpc.DialContext(ctx, d.address, append(d.options, grpc.WithBlock(), grpc.WithReturnConnectionError())...)
	if err != nil {
		return nil, err
	}
	return &grpcConnection{connection: connection, client: agentv1.NewAgentGatewayServiceClient(connection)}, nil
}

func validateSecureRegularFile(path string, readOnly bool) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: security file path must be absolute and clean", ErrInvalidConfiguration)
	}
	if err := validateSecureDirectory(filepath.Dir(path), false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect security file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: security file is not an owner-only regular file", ErrInvalidConfiguration)
	}
	if readOnly && info.Mode().Perm()&0o222 != 0 {
		return fmt.Errorf("%w: trust anchor file must be read-only", ErrInvalidConfiguration)
	}
	return nil
}

func readSecureRegularFile(path string, readOnly bool) ([]byte, error) {
	if err := validateSecureRegularFile(path, readOnly); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open security file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || readOnly && info.Mode().Perm()&0o222 != 0 || info.Size() < 0 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("%w: security file changed or exceeds its limit", ErrInvalidConfiguration)
	}
	content, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(content) > 1<<20 {
		return nil, fmt.Errorf("read security file")
	}
	return content, nil
}

func validateSecureDirectory(path string, create bool) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("%w: secure directory path must be absolute and clean", ErrInvalidConfiguration)
	}
	if err := rejectSymlinkPathComponents(path, create); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && create {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create secure directory: %w", err)
		}
		if err := rejectSymlinkPathComponents(path, false); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect secure directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: directory must be owner-only and not a symlink", ErrInvalidConfiguration)
	}
	return nil
}

func rejectSymlinkPathComponents(path string, allowMissing bool) error {
	volume := filepath.VolumeName(path)
	root := volume + string(filepath.Separator)
	relative := path[len(root):]
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) && allowMissing {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect secure directory path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: secure directory path contains a symlink", ErrInvalidConfiguration)
		}
	}
	return nil
}

var _ io.Closer = (*grpcConnection)(nil)
