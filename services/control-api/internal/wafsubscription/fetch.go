package wafsubscription

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrBlockedAddress is a subscription URL that names or resolves to a
// non-public address (SSRF guard).
var ErrBlockedAddress = errors.New("subscription URL resolves to a non-public address")

// ErrInvalidURL is a subscription URL that is not a plain public https URL.
var ErrInvalidURL = errors.New("subscription URL must be https://host/path without credentials or fragment")

const maxURLBytes = 2048

var blockedPrefixes = func() []netip.Prefix {
	values := []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32",
		"2001:db8::/32", "2002::/16",
	}
	prefixes := make([]netip.Prefix, len(values))
	for index, value := range values {
		prefixes[index] = netip.MustParsePrefix(value)
	}
	return prefixes
}()

// blockedAddress is every address a control plane must not reach on behalf of
// an operator: loopback, private, link-local (cloud metadata), CGNAT,
// multicast, documentation/benchmark, NAT64 / 6to4 / Teredo (may embed
// private IPv4) and reserved ranges.
func blockedAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() {
		return true
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ValidateURL is the save-time check of a subscription URL.
func ValidateURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || len(value) > maxURLBytes {
		return ErrInvalidURL
	}
	return checkURL(parsed, blockedAddress)
}

func checkURL(parsed *url.URL, blocked func(netip.Addr) bool) error {
	if parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return ErrInvalidURL
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return ErrInvalidURL
	}
	if addr, err := netip.ParseAddr(host); err == nil && blocked(addr) {
		return ErrBlockedAddress
	}
	return nil
}

// fetcher downloads a subscription document. Only the control plane uses it;
// every connection is checked against blocked at dial time (after DNS), so
// a name that rebinds to an internal address is refused. No proxy, at most
// three https redirects, MaxDocumentBytes of body.
type fetcher struct {
	client  *http.Client
	dialer  *net.Dialer
	blocked func(netip.Addr) bool
}

// NewFetcher is the production fetcher (system trust roots).
func NewFetcher() *fetcher { return newFetcher(blockedAddress, nil) }

func newFetcher(blocked func(netip.Addr) bool, tlsConfig *tls.Config) *fetcher {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return ErrBlockedAddress
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || blocked(addr) {
			return ErrBlockedAddress
		}
		return nil
	}}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
		MaxResponseHeaderBytes: 64 << 10, IdleConnTimeout: 30 * time.Second}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig.Clone()
	}
	result := &fetcher{blocked: blocked, dialer: dialer}
	result.client = &http.Client{Transport: transport, Timeout: 60 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return checkURL(request.URL, blocked)
		}}
	return result
}

func (f *fetcher) fetch(ctx context.Context, value string) ([]byte, error) {
	parsed, err := url.Parse(value)
	if err != nil || len(value) > maxURLBytes {
		return nil, ErrInvalidURL
	}
	if err := checkURL(parsed, f.blocked); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, ErrInvalidURL
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "cdnca-control-waf-subscription/1")
	response, err := f.client.Do(request)
	if err != nil {
		if errors.Is(err, ErrBlockedAddress) {
			return nil, ErrBlockedAddress
		}
		return nil, fmt.Errorf("fetch subscription: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch subscription: HTTP %d", response.StatusCode)
	}
	if response.ContentLength > MaxDocumentBytes {
		return nil, fmt.Errorf("fetch subscription: response larger than %d bytes", MaxDocumentBytes)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch subscription: read body: %w", err)
	}
	if len(body) > MaxDocumentBytes {
		return nil, fmt.Errorf("fetch subscription: response larger than %d bytes", MaxDocumentBytes)
	}
	return body, nil
}
