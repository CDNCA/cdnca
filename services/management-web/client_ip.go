package main

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

// Origin authentication (protocol T2): behind a CDN the TCP peer is a CDN
// edge. A request that carries the origin-auth header with the shared secret
// came through our CDN, so its real-ip header names the client; anything else
// is identified by the TCP peer.
const (
	defaultOriginAuthHeader = "X-Cdnca-Origin-Key"
	minOriginAuthSecret     = 32
	maxForwardedForBytes    = 1024
	clientSourceTCP         = "tcp"
	clientSourceCDN         = "cdn"
)

type clientIPResolver struct {
	authHeader   string
	secret       []byte // empty: T2 disabled, only the TCP peer counts
	realIPHeader string
}

// loadOriginAuthSecret reads the shared secret. A missing file disables T2
// (ok=false, nil error); a file readable by others or shorter than 32 bytes
// is a configuration error.
func loadOriginAuthSecret(path string) ([]byte, bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, false, fmt.Errorf("%s must be a regular file with mode 0600", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	secret := bytes.TrimRight(content, "\r\n")
	if len(secret) < minOriginAuthSecret {
		return nil, false, fmt.Errorf("%s must hold at least %d bytes", path, minOriginAuthSecret)
	}
	return secret, true, nil
}

func parseSingleIP(value string) (netip.Addr, bool) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func socketPeer(request *http.Request) (netip.Addr, string, bool) {
	host, port, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, "", false
	}
	address, ok := parseSingleIP(host)
	return address, port, ok
}

func (resolver clientIPResolver) authenticated(request *http.Request) bool {
	values := request.Header.Values(resolver.authHeader)
	return len(resolver.secret) > 0 && len(values) == 1 &&
		subtle.ConstantTimeCompare([]byte(values[0]), resolver.secret) == 1
}

// fromHeader reads the client from the real-ip header. X-Forwarded-For takes
// the right-most hop (protocol T2): the CDN appends the address it
// accepted the connection from, so anything the client sent sits to the left
// of it and cannot reach the right-most position. Every other header must
// hold exactly one address.
func (resolver clientIPResolver) fromHeader(request *http.Request) (netip.Addr, bool) {
	values := request.Header.Values(resolver.realIPHeader)
	if len(values) == 0 {
		return netip.Addr{}, false
	}
	if strings.EqualFold(resolver.realIPHeader, "X-Forwarded-For") {
		joined := strings.Join(values, ",")
		if len(joined) > maxForwardedForBytes {
			return netip.Addr{}, false
		}
		hops := strings.Split(joined, ",")
		return parseSingleIP(hops[len(hops)-1])
	}
	if len(values) != 1 {
		return netip.Addr{}, false
	}
	return parseSingleIP(values[0])
}

// resolve returns the client address and its source (tcp|cdn).
func (resolver clientIPResolver) resolve(request *http.Request) (netip.Addr, string, bool) {
	if resolver.realIPHeader != "" && resolver.authenticated(request) {
		if address, ok := resolver.fromHeader(request); ok {
			return address, clientSourceCDN, true
		}
	}
	address, _, ok := socketPeer(request)
	return address, clientSourceTCP, ok
}

// apply resolves the client, removes every inbound identity header (the
// origin-auth secret never reaches the upstream or a log) and rewrites
// RemoteAddr, which the proxy's X-Forwarded-For/X-Real-IP, the download gate
// and the tunnel limits all read.
func (resolver clientIPResolver) apply(request *http.Request) string {
	address, source, ok := resolver.resolve(request)
	request.Header.Del(resolver.authHeader)
	if resolver.realIPHeader != "" {
		request.Header.Del(resolver.realIPHeader)
		request.Header.Del("X-Forwarded-For")
		request.Header.Del("X-Real-IP")
	}
	if ok && source == clientSourceCDN {
		_, port, _ := socketPeer(request)
		if port == "" {
			port = "0"
		}
		request.RemoteAddr = net.JoinHostPort(address.String(), port)
	}
	return source
}
