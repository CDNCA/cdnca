// Package gatewaytunnel dials the gateway WebSocket tunnel (ADR 0013 §4.2).
// The tunnel carries the unchanged inner TLS 1.3 gRPC connection, so the
// node identity stays the inner client certificate; the signed upgrade token
// (§4.6) only admits the upgrade.
package gatewaytunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	TransportGRPC = "grpc"
	TransportWS   = "ws"

	TunnelPath     = "/agent/v1/tunnel"
	EnrollmentPath = "/agent/v1/enroll"

	certificateHeader = "Cdnca-Node-Cert"
	authHeader        = "Cdnca-Node-Auth"
	nodeSPIFFEPrefix  = "spiffe://cdn-platform/node/"
)

// ValidTransport reports whether value is a configured transport; empty
// means grpc.
func ValidTransport(value string) bool {
	return value == "" || value == TransportGRPC || value == TransportWS
}

// SignedText is the token signing input; the gateway pins the same vector.
func SignedText(audience, path, nodeID, serialHex string, iat int64, nonce string) []byte {
	return []byte(strings.Join([]string{"cdnca-gw-auth-v1", audience, path, nodeID, serialHex, strconv.FormatInt(iat, 10), nonce}, "\n"))
}

// TokenHeader signs an upgrade token for path with the node key.
func TokenHeader(leaf *x509.Certificate, key ed25519.PrivateKey, audience, path string, now time.Time, random io.Reader) (http.Header, error) {
	if leaf == nil || len(leaf.URIs) != 1 || !strings.HasPrefix(leaf.URIs[0].String(), nodeSPIFFEPrefix) || leaf.SerialNumber == nil {
		return nil, errors.New("node certificate has no node identity")
	}
	if audience == "" {
		return nil, errors.New("tunnel audience is required")
	}
	if random == nil {
		random = rand.Reader
	}
	raw := make([]byte, 16)
	if _, err := io.ReadFull(random, raw); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(raw)
	nodeID := strings.TrimPrefix(leaf.URIs[0].String(), nodeSPIFFEPrefix)
	iat := now.Unix()
	signature := ed25519.Sign(key, SignedText(audience, path, nodeID, strings.ToLower(leaf.SerialNumber.Text(16)), iat, nonce))
	header := http.Header{}
	header.Set(certificateHeader, base64.StdEncoding.EncodeToString(leaf.Raw))
	header.Set(authHeader, fmt.Sprintf("v1.%d.%s.%s", iat, nonce, base64.StdEncoding.EncodeToString(signature)))
	return header, nil
}

// OuterRoots trusts the system roots (CDN edge certificates) plus the
// installation root CA (direct tunnel to the gateway port).
func OuterRoots(installationPEM []byte) *x509.CertPool {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	roots.AppendCertsFromPEM(installationPEM)
	return roots
}

type DialConfig struct {
	// Address is host:port of the tunnel entrance (CDN 443 or gateway port).
	Address string
	// Host is the outer SNI and Host header; empty = host part of Address.
	Host    string
	Path    string
	Roots   *x509.CertPool
	Header  func(time.Time) (http.Header, error)
	Timeout time.Duration
}

// Dial opens the WebSocket and returns it as a net.Conn of binary frames.
func Dial(ctx context.Context, config DialConfig) (net.Conn, error) {
	host := config.Host
	if host == "" {
		parsed, _, err := net.SplitHostPort(config.Address)
		if err != nil {
			return nil, fmt.Errorf("tunnel address is invalid: %w", err)
		}
		host = parsed
	}
	var header http.Header
	if config.Header != nil {
		value, err := config.Header(time.Now())
		if err != nil {
			return nil, err
		}
		header = value
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: config.Roots, NextProtos: []string{"http/1.1"}},
		HandshakeTimeout: config.Timeout,
		ReadBufferSize:   32 << 10, WriteBufferSize: 32 << 10,
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, config.Address)
		},
	}
	url := "wss://" + net.JoinHostPort(host, portOf(config.Address)) + config.Path
	ws, response, err := dialer.DialContext(ctx, url, header)
	if err != nil {
		if response != nil {
			return nil, fmt.Errorf("gateway tunnel upgrade %s: %w", response.Status, err)
		}
		return nil, fmt.Errorf("gateway tunnel: %w", err)
	}
	return &conn{ws: ws}, nil
}

func portOf(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "443"
	}
	return port
}

type conn struct {
	ws     *websocket.Conn
	reader io.Reader
	rmu    sync.Mutex
	wmu    sync.Mutex
}

func (c *conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		if c.reader == nil {
			kind, reader, err := c.ws.NextReader()
			if err != nil {
				return 0, err
			}
			if kind != websocket.BinaryMessage {
				continue
			}
			c.reader = reader
		}
		n, err := c.reader.Read(p)
		if errors.Is(err, io.EOF) {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *conn) Close() error         { return c.ws.Close() }
func (c *conn) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *conn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }

// gorilla/websocket stores the write deadline without locking; set it under
// the write lock so it never races a concurrent Write.
func (c *conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *conn) SetReadDeadline(t time.Time) error { return c.ws.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.ws.SetWriteDeadline(t)
}

// NodeTunnel returns a gRPC context dialer that opens the agent tunnel at
// address, signing a fresh token with the node certificate for every dial.
func NodeTunnel(address, host, audience string, installationRootPEM []byte, certificate tls.Certificate) (func(context.Context, string) (net.Conn, error), error) {
	if audience == "" {
		return nil, errors.New("gateway tunnel audience is required for the ws transport")
	}
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("node certificate is required for the ws transport")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("node key must be Ed25519 for the ws transport")
	}
	roots := OuterRoots(installationRootPEM)
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return Dial(ctx, DialConfig{Address: address, Host: host, Path: TunnelPath, Roots: roots,
			Header: func(now time.Time) (http.Header, error) {
				return TokenHeader(leaf, key, audience, TunnelPath, now, nil)
			}})
	}, nil
}

// EnrollmentTunnel returns a gRPC context dialer for the enrollment tunnel
// (no token; the gateway rate limits by source address).
func EnrollmentTunnel(address, host string, installationRootPEM []byte) func(context.Context, string) (net.Conn, error) {
	roots := OuterRoots(installationRootPEM)
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return Dial(ctx, DialConfig{Address: address, Host: host, Path: EnrollmentPath, Roots: roots})
	}
}
