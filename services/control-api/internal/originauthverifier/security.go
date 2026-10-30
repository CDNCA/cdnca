package originauthverifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxDNSAnswers          = 16
	maxEndpointBytes       = 2048
	maxBucketBytes         = 255
	maxObjectBytes         = 1024
	maxResponseHeaderBytes = 16 << 10
)

var (
	bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)
	objectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

	forbiddenPrefixes = mustPrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
		"2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	)
)

type resolvedProbe struct {
	endpoint   *url.URL
	serverName string
	port       string
	addresses  []netip.Addr
}

func validateConfig(config Config) error {
	if !validDuration(config.ConnectTimeout) || !validDuration(config.TLSHandshakeTimeout) ||
		!validDuration(config.ResponseHeaderTimeout) || config.RequestTimeout <= 0 ||
		config.RequestTimeout > 30*time.Second || config.ConnectTimeout > config.RequestTimeout ||
		config.TLSHandshakeTimeout > config.RequestTimeout || config.ResponseHeaderTimeout > config.RequestTimeout ||
		config.MaxResponseBytes < 1 || config.MaxResponseBytes > 64<<10 ||
		config.MaxAttempts < 1 || config.MaxAttempts > 3 ||
		config.MaxConcurrent < 1 || config.MaxConcurrent > 20 || config.Now == nil {
		return ErrInvalidConfiguration
	}
	enabled := 0
	for _, probe := range []Probe{config.S3, config.OSS, config.COS} {
		if !probe.Enabled {
			continue
		}
		enabled++
		if validateProbe(probe) != nil {
			return ErrInvalidConfiguration
		}
	}
	if enabled == 0 {
		return ErrInvalidConfiguration
	}
	return nil
}

func validDuration(value time.Duration) bool {
	return value > 0 && value <= 30*time.Second
}

func validateProbe(probe Probe) error {
	if len(probe.Endpoint) == 0 || len(probe.Endpoint) > maxEndpointBytes ||
		strings.ContainsAny(probe.Endpoint, "\r\n\t") {
		return ErrInvalidConfiguration
	}
	parsed, err := url.Parse(probe.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Host == "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.RawFragment != "" || parsed.RawPath != "" || parsed.Path != "" && parsed.Path != "/" ||
		parsed.Port() != "" && parsed.Port() != "443" {
		return ErrInvalidConfiguration
	}
	hostname := strings.ToLower(parsed.Hostname())
	if !validHostname(hostname) || net.ParseIP(hostname) != nil || hostname == "localhost" ||
		strings.HasSuffix(hostname, ".localhost") || strings.HasSuffix(hostname, ".local") ||
		strings.HasSuffix(hostname, ".internal") {
		return ErrInvalidConfiguration
	}
	if len(probe.Region) == 0 || len(probe.Region) > 64 || !safeToken(probe.Region) ||
		len(probe.Bucket) < 3 || len(probe.Bucket) > maxBucketBytes || !bucketPattern.MatchString(probe.Bucket) ||
		strings.Contains(probe.Bucket, "..") || len(probe.Object) == 0 || len(probe.Object) > maxObjectBytes ||
		!objectPattern.MatchString(probe.Object) || strings.ContainsAny(probe.Object, `%\\?#`) {
		return ErrInvalidConfiguration
	}
	for _, segment := range strings.Split(probe.Object, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ErrInvalidConfiguration
		}
	}
	return nil
}

func safeToken(value string) bool {
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 || strings.HasSuffix(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func resolveProbe(ctx context.Context, probe Probe, resolver Resolver) (resolvedProbe, error) {
	if ctx == nil || resolver == nil || validateProbe(probe) != nil {
		return resolvedProbe{}, ErrInvalidConfiguration
	}
	parsed, _ := url.Parse(probe.Endpoint)
	hostname := strings.ToLower(parsed.Hostname())
	addresses, err := resolver.LookupNetIP(ctx, "ip", hostname)
	if err != nil || len(addresses) == 0 || len(addresses) > maxDNSAnswers {
		return resolvedProbe{}, ErrProviderUnavailable
	}
	unique := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !publicAddress(address) {
			return resolvedProbe{}, ErrInvalidConfiguration
		}
		if _, found := seen[address]; found {
			continue
		}
		seen[address] = struct{}{}
		unique = append(unique, address)
	}
	parsed.Scheme = "https"
	parsed.Host = hostname
	parsed.Path = ""
	return resolvedProbe{endpoint: parsed, serverName: hostname, port: "443", addresses: unique}, nil
}

func publicAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range forbiddenPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic(fmt.Sprintf("invalid built-in prefix %q", value))
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

type boundedTransport struct {
	base             *http.Transport
	maxAttempts      int64
	maxResponseBytes int64
	attempts         atomic.Int64
	failureMu        sync.Mutex
	failure          error
}

func (transport *boundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !validTransportRequest(request) || request.Method != http.MethodHead ||
		request.Body != nil && request.Body != http.NoBody || request.ContentLength > 0 {
		transport.setFailure(ErrInvalidConfiguration)
		return nil, ErrInvalidConfiguration
	}
	if errors.Is(transport.Failure(), ErrInvalidConfiguration) {
		return nil, ErrInvalidConfiguration
	}
	if transport.attempts.Add(1) > transport.maxAttempts {
		transport.setFailure(ErrProviderUnavailable)
		return nil, ErrProviderUnavailable
	}
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		transport.setFailure(classifyTransportFailure(err))
		return nil, err
	}
	if response.ContentLength > transport.maxResponseBytes {
		response.Body.Close()
		transport.setFailure(ErrProviderUnavailable)
		return nil, ErrProviderUnavailable
	}
	response.Body = &boundedBody{reader: response.Body, remaining: transport.maxResponseBytes}
	return response, nil
}

func validTransportRequest(request *http.Request) bool {
	if request == nil || request.URL == nil || request.URL.Scheme != "https" || request.URL.Opaque != "" ||
		request.URL.User != nil || request.URL.Host == "" || request.URL.Fragment != "" || request.URL.RawFragment != "" ||
		request.URL.Port() != "" && request.URL.Port() != "443" {
		return false
	}
	hostname := request.URL.Hostname()
	return hostname == strings.ToLower(hostname) && validHostname(hostname) && net.ParseIP(hostname) == nil
}

func (transport *boundedTransport) CloseIdleConnections() { transport.base.CloseIdleConnections() }

func (transport *boundedTransport) setFailure(err error) {
	if !errors.Is(err, ErrInvalidConfiguration) {
		return
	}
	transport.failureMu.Lock()
	defer transport.failureMu.Unlock()
	transport.failure = ErrInvalidConfiguration
}

func (transport *boundedTransport) Failure() error {
	transport.failureMu.Lock()
	defer transport.failureMu.Unlock()
	return transport.failure
}

func classifyTransportFailure(err error) error {
	var hostnameError x509.HostnameError
	var authorityError x509.UnknownAuthorityError
	var certificateError x509.CertificateInvalidError
	var verificationError *tls.CertificateVerificationError
	if errors.Is(err, ErrInvalidConfiguration) || errors.As(err, &hostnameError) ||
		errors.As(err, &authorityError) || errors.As(err, &certificateError) || errors.As(err, &verificationError) {
		return ErrInvalidConfiguration
	}
	return ErrProviderUnavailable
}

type boundedBody struct {
	reader    io.ReadCloser
	remaining int64
}

func (body *boundedBody) Read(buffer []byte) (int, error) {
	if body.remaining <= 0 {
		var extra [1]byte
		read, err := body.reader.Read(extra[:])
		if read > 0 {
			return 0, ErrProviderUnavailable
		}
		return 0, err
	}
	if int64(len(buffer)) > body.remaining {
		buffer = buffer[:body.remaining]
	}
	read, err := body.reader.Read(buffer)
	body.remaining -= int64(read)
	return read, err
}

func (body *boundedBody) Close() error { return body.reader.Close() }

func newPinnedClient(config Config, target resolvedProbe, dial dialContextFunc) *http.Client {
	pinnedDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, ErrInvalidConfiguration
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(strings.TrimSuffix(host, "."), target.serverName) || port != target.port {
			return nil, ErrInvalidConfiguration
		}
		var lastErr error
		for _, pinned := range target.addresses {
			connection, dialErr := dial(ctx, "tcp", net.JoinHostPort(pinned.String(), target.port))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			return nil, ErrProviderUnavailable
		}
		return nil, lastErr
	}
	base := &http.Transport{
		Proxy: nil, DialContext: pinnedDial, ForceAttemptHTTP2: true, DisableCompression: true,
		DisableKeepAlives: true, MaxConnsPerHost: config.MaxConcurrent,
		TLSHandshakeTimeout: config.TLSHandshakeTimeout, ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, ServerName: target.serverName, RootCAs: cloneRoots(config.RootCAs),
		},
	}
	transport := &boundedTransport{
		base: base, maxAttempts: int64(config.MaxAttempts), maxResponseBytes: config.MaxResponseBytes,
	}
	return &http.Client{
		Transport: transport, Timeout: config.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func cloneRoots(roots *x509.CertPool) *x509.CertPool {
	if roots == nil {
		return nil
	}
	return roots.Clone()
}
