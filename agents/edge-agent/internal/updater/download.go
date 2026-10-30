package updater

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
	"strconv"
	"strings"
	"time"
)

type HostPolicy struct {
	Addresses []netip.Addr
	Ports     []uint16
}

type HTTPSPolicy struct {
	Hosts          map[string]HostPolicy
	AllowRedirects bool
	MaxRedirects   int
	Timeout        time.Duration
	RootCAs        *x509.CertPool
}

type HTTPSDownloader struct {
	client *http.Client
	policy HTTPSPolicy
}

func NewHTTPSDownloader(policy HTTPSPolicy) (*HTTPSDownloader, error) {
	if len(policy.Hosts) == 0 || policy.Timeout <= 0 || policy.MaxRedirects < 0 {
		return nil, fmt.Errorf("%w: incomplete HTTPS policy", ErrDownloadPolicy)
	}
	normalized := make(map[string]HostPolicy, len(policy.Hosts))
	for host, rule := range policy.Hosts {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host == "" || strings.ContainsAny(host, `/\\@`) || len(rule.Addresses) == 0 || len(rule.Ports) == 0 {
			return nil, fmt.Errorf("%w: invalid host policy", ErrDownloadPolicy)
		}
		addresses := make([]netip.Addr, 0, len(rule.Addresses))
		for _, address := range rule.Addresses {
			if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
				return nil, fmt.Errorf("%w: invalid fixed address", ErrDownloadPolicy)
			}
			addresses = append(addresses, address.Unmap())
		}
		ports := append([]uint16(nil), rule.Ports...)
		for _, port := range ports {
			if port == 0 {
				return nil, fmt.Errorf("%w: invalid fixed port", ErrDownloadPolicy)
			}
		}
		normalized[host] = HostPolicy{Addresses: addresses, Ports: ports}
	}
	policy.Hosts = normalized
	dialer := &net.Dialer{Timeout: policy.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   policy.Timeout,
		ResponseHeaderTimeout: policy.Timeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: policy.RootCAs},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				return nil, ErrDownloadPolicy
			}
			rule, exists := policy.Hosts[strings.ToLower(strings.TrimSuffix(host, "."))]
			if !exists {
				return nil, ErrDownloadPolicy
			}
			portValue, err := strconv.ParseUint(portText, 10, 16)
			if err != nil || !allowedPort(rule.Ports, uint16(portValue)) {
				return nil, ErrDownloadPolicy
			}
			var lastError error
			for _, fixed := range rule.Addresses {
				connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(fixed.String(), portText))
				if dialErr == nil {
					return connection, nil
				}
				lastError = dialErr
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			_ = lastError
			return nil, ErrDownload
		},
	}
	downloader := &HTTPSDownloader{policy: policy}
	downloader.client = &http.Client{
		Transport: transport,
		Timeout:   policy.Timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if !policy.AllowRedirects || len(via) > policy.MaxRedirects {
				return ErrDownloadPolicy
			}
			return downloader.validateURL(request.URL)
		},
	}
	return downloader, nil
}

func (d *HTTPSDownloader) Download(ctx context.Context, request DownloadRequest, destination io.Writer) error {
	if destination == nil || request.MaxBytes <= 0 {
		return fmt.Errorf("%w: invalid request", ErrDownload)
	}
	parsed, err := url.Parse(request.URL)
	if err != nil || d.validateURL(parsed) != nil {
		return ErrDownloadPolicy
	}
	host := strings.ToLower(parsed.Hostname())
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return fmt.Errorf("%w: construct request for host %s", ErrDownload, host)
	}
	httpRequest.Header.Set("Accept-Encoding", "identity")
	response, err := d.client.Do(httpRequest)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrDownloadPolicy) {
			return ErrDownloadPolicy
		}
		return fmt.Errorf("%w: request to host %s", ErrDownload, host)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: host %s returned status %d", ErrDownload, host, response.StatusCode)
	}
	if response.ContentLength > request.MaxBytes {
		return ErrArtifactTooLarge
	}
	written, err := io.Copy(destination, io.LimitReader(response.Body, request.MaxBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: response body from host %s", ErrDownload, host)
	}
	if written > request.MaxBytes {
		return ErrArtifactTooLarge
	}
	return nil
}

func (d *HTTPSDownloader) validateURL(parsed *url.URL) error {
	if parsed == nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" || parsed.Host == "" {
		return ErrDownloadPolicy
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	rule, exists := d.policy.Hosts[host]
	if !exists {
		return ErrDownloadPolicy
	}
	port := uint16(443)
	if parsed.Port() != "" {
		value, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || value == 0 {
			return ErrDownloadPolicy
		}
		port = uint16(value)
	}
	if !allowedPort(rule.Ports, port) {
		return ErrDownloadPolicy
	}
	return nil
}

func allowedPort(ports []uint16, candidate uint16) bool {
	for _, port := range ports {
		if port == candidate {
			return true
		}
	}
	return false
}
