// Package mtlstunnel carries an unchanged mTLS connection through a CDN that
// only proxies 443 and terminates TLS at the edge (protocol T1). The outer layer is wss://<host>:443
// /mtls/v1/tunnel/<target> with subprotocol cdnca-mtls-tunnel.v1; the server
// bridges raw TCP bytes to a fixed local port, so the inner TLS 1.3 handshake
// (client certificate, CA pinning, SAN check) runs end to end between the
// original client and the original mTLS server.
package mtlstunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Protocol constants shared byte for byte by every T1 client and server.
const (
	Subprotocol   = "cdnca-mtls-tunnel.v1"
	PathPrefix    = "/mtls/v1/tunnel/"
	MaxFrameBytes = 64 << 10
	IdleTimeout   = 120 * time.Second
	// PerSourceLimit caps concurrent tunnels per client IP; DefaultTotalLimit
	// is the server-wide default.
	PerSourceLimit    = 64
	DefaultTotalLimit = 1024

	TargetPluginRuntime = "plugin-runtime"
	TargetMarketLicense = "market-license"
	TargetMarketMember  = "market-member"
	TargetMarketAdmin   = "market-admin"

	ModeTunnel = "tunnel"
	ModeDirect = "direct"
)

// ParseMode reads a <组件>_MTLS_TRANSPORT value; empty means tunnel.
func ParseMode(value string) (string, error) {
	switch value {
	case "", ModeTunnel:
		return ModeTunnel, nil
	case ModeDirect:
		return ModeDirect, nil
	}
	return "", fmt.Errorf("mTLS transport %q is not direct or tunnel", value)
}

// DialFunc is an http.Transport.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Client opens tunnels for one original mTLS origin.
type Client struct {
	// Entrance is host:port of the outer wss endpoint (CDN 443).
	Entrance string
	// Host is the outer SNI and Host header (the original host name).
	Host   string
	Target string
	// Origin is the original host:port the inner connection is for; dials for
	// any other address are refused, so a redirect or a second origin never
	// rides this tunnel.
	Origin string
	// Roots verifies the outer certificate; nil = system roots.
	Roots   *x509.CertPool
	Timeout time.Duration
}

// NewClient derives the tunnel for originURL (https://host[:port]); the
// entrance is host:443 unless tunnelURL (https://host[:port], no path)
// overrides it.
func NewClient(originURL, tunnelURL, target string) (*Client, error) {
	origin, err := url.Parse(originURL)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" {
		return nil, fmt.Errorf("mTLS tunnel origin %q is not an https URL", originURL)
	}
	if !validTarget(target) {
		return nil, fmt.Errorf("mTLS tunnel target %q is invalid", target)
	}
	originPort := origin.Port()
	if originPort == "" {
		originPort = "443"
	}
	client := &Client{Host: origin.Hostname(), Target: target, Origin: net.JoinHostPort(origin.Hostname(), originPort),
		Entrance: net.JoinHostPort(origin.Hostname(), "443")}
	if tunnelURL != "" {
		entrance, err := url.Parse(tunnelURL)
		if err != nil || entrance.Scheme != "https" || entrance.Hostname() == "" || entrance.User != nil ||
			strings.TrimRight(entrance.Path, "/") != "" || entrance.RawQuery != "" || entrance.Fragment != "" {
			return nil, fmt.Errorf("mTLS tunnel URL %q must be https://host[:port]", tunnelURL)
		}
		port := entrance.Port()
		if port == "" {
			port = "443"
		}
		client.Host, client.Entrance = entrance.Hostname(), net.JoinHostPort(entrance.Hostname(), port)
	}
	return client, nil
}

func validTarget(target string) bool {
	if target == "" || len(target) > 64 {
		return false
	}
	for _, r := range target {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// DialContext opens the outer WebSocket and returns it as a net.Conn; the
// caller runs the inner TLS over it (http.Transport does with its
// TLSClientConfig, ServerName = the original host).
func (c *Client) DialContext(ctx context.Context, _ string, address string) (net.Conn, error) {
	if address != c.Origin {
		return nil, fmt.Errorf("mTLS tunnel for %s refuses %s", c.Origin, address)
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	roots := c.Roots
	if roots == nil {
		var err error
		if roots, err = x509.SystemCertPool(); err != nil {
			return nil, fmt.Errorf("mTLS tunnel system roots: %w", err)
		}
	}
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.Host, RootCAs: roots, NextProtos: []string{"http/1.1"}},
		HandshakeTimeout: timeout,
		ReadBufferSize:   32 << 10, WriteBufferSize: 32 << 10,
		Subprotocols: []string{Subprotocol},
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, c.Entrance)
		},
	}
	_, port, _ := net.SplitHostPort(c.Entrance)
	ws, response, err := dialer.DialContext(ctx, "wss://"+net.JoinHostPort(c.Host, port)+PathPrefix+c.Target, nil)
	if err != nil {
		if response != nil {
			return nil, fmt.Errorf("mTLS tunnel upgrade %s: %w", response.Status, err)
		}
		return nil, fmt.Errorf("mTLS tunnel: %w", err)
	}
	if ws.Subprotocol() != Subprotocol {
		_ = ws.Close()
		return nil, errors.New("mTLS tunnel server did not confirm the subprotocol")
	}
	return newWSConn(ws), nil
}

// Dialer returns the DialContext for originURL under mode: nil for direct
// (the transport's own dialer), the tunnel otherwise.
func Dialer(mode, originURL, tunnelURL, target string) (DialFunc, error) {
	mode, err := ParseMode(mode)
	if err != nil {
		return nil, err
	}
	if mode == ModeDirect {
		return nil, nil
	}
	client, err := NewClient(originURL, tunnelURL, target)
	if err != nil {
		return nil, err
	}
	return client.DialContext, nil
}

// Apply installs dial on transport (nil leaves it direct). The inner TLS is
// still the transport's: TLSClientConfig, client certificate and root
// pinning are unchanged.
func Apply(transport *http.Transport, dial DialFunc) *http.Transport {
	if dial != nil {
		transport.DialContext = dial
	}
	return transport
}
