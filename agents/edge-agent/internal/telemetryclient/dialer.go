package telemetryclient

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
	// Transport, TunnelHost, TunnelAudience: see gatewayclient.MTLSDialerConfig.
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
	rootPEM, err := readSecureFile(config.RootCAFile)
	if err != nil {
		return nil, err
	}
	certificatePEM, err := readSecureFile(config.ClientCertificateFile)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := readSecureFile(config.ClientPrivateKeyFile)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load telemetry client certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("%w: telemetry gateway CA file contains no certificate", ErrInvalidConfiguration)
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: config.ServerName,
		RootCAs: roots, Certificates: []tls.Certificate{certificate},
	}
	options := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(config.MaximumReceiveBytes), grpc.MaxCallSendMsgSize(config.MaximumSendBytes)),
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

func readSecureFile(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: security file path must be absolute and clean", ErrInvalidConfiguration)
	}
	if err := rejectSymlinkComponents(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: security file must be owner-only and regular", ErrInvalidConfiguration)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open telemetry security file")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("%w: security file changed or exceeds its limit", ErrInvalidConfiguration)
	}
	content, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(content) > 1<<20 {
		return nil, fmt.Errorf("read telemetry security file")
	}
	return content, nil
}

func rejectSymlinkComponents(path string) error {
	volume := filepath.VolumeName(path)
	root := volume + string(filepath.Separator)
	current := root
	for _, component := range strings.Split(strings.TrimPrefix(path, root), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: security path contains an unsafe component", ErrInvalidConfiguration)
		}
	}
	return nil
}

var _ Dialer = (*mtlsDialer)(nil)
