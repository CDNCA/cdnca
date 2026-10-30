package domainownership

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
)

// TXTObserver is the part of dnspropagation.WireSource the TXT check uses.
type TXTObserver interface {
	Observe(context.Context, string, dnspropagation.Resolver, string, []dnscheck.RecordType) (dnspropagation.Observation, error)
}

// DefaultResolvers are the public recursive resolvers of the plan (§2.6 #12).
var DefaultResolvers = []dnspropagation.Resolver{
	{ID: "1.1.1.1:53", Name: "cloudflare"},
	{ID: "8.8.8.8:53", Name: "google"},
	{ID: "223.5.5.5:53", Name: "alidns"},
}

// NetworkVerifier checks TXT records through several public resolvers (a
// quorum must see the token) and HTTP files through a dialer that refuses
// non-public addresses.
type NetworkVerifier struct {
	observer  TXTObserver
	resolvers []dnspropagation.Resolver
	quorum    int
	client    *http.Client
}

func NewNetworkVerifier(observer TXTObserver, resolvers []dnspropagation.Resolver, quorum int, client *http.Client) (*NetworkVerifier, error) {
	if observer == nil || len(resolvers) == 0 || quorum < 1 || quorum > len(resolvers) {
		return nil, ErrInvalidInput
	}
	if client == nil {
		client = SafeHTTPClient(nil)
	}
	return &NetworkVerifier{observer: observer, resolvers: append([]dnspropagation.Resolver(nil), resolvers...),
		quorum: quorum, client: client}, nil
}

// NewDefaultNetworkVerifier uses the default public resolvers with a 2/3 quorum.
func NewDefaultNetworkVerifier() (*NetworkVerifier, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	source, err := dnspropagation.NewWireSource(dnspropagation.WireSourceConfig{
		Bootstrap: DefaultResolvers, DialContext: dialer.DialContext,
		QueryTimeout: 5 * time.Second, MaximumResponseBytes: 4096, Now: time.Now,
	})
	if err != nil {
		return nil, err
	}
	return NewNetworkVerifier(source, DefaultResolvers, 2, nil)
}

func (v *NetworkVerifier) VerifyTXT(ctx context.Context, name, token string) (bool, string, error) {
	votes, answered := 0, 0
	for _, resolver := range v.resolvers {
		observation, err := v.observer.Observe(ctx, "domain-ownership", resolver, name+".",
			[]dnscheck.RecordType{dnscheck.RecordTXT})
		if err != nil {
			if ctx.Err() != nil {
				return false, "", ctx.Err()
			}
			continue
		}
		answered++
		if observation.Status != dnspropagation.ResponseAnswer {
			continue
		}
		for _, set := range observation.Records {
			if set.Type != dnscheck.RecordTXT {
				continue
			}
			for _, value := range set.Values {
				if strings.TrimSpace(value) == token {
					votes++
					goto next
				}
			}
		}
	next:
	}
	switch {
	case votes >= v.quorum:
		return true, "", nil
	case answered < v.quorum:
		return false, "resolver_unavailable", nil
	case votes > 0:
		return false, "txt_quorum_pending", nil
	default:
		return false, "txt_not_found", nil
	}
}

func (v *NetworkVerifier) VerifyHTTP(ctx context.Context, apex, token string) (bool, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL(apex, token), nil)
	if err != nil {
		return false, "", err
	}
	request.Header.Set("User-Agent", "cdnca-domain-verify/1")
	response, err := v.client.Do(request)
	if err != nil {
		if errors.Is(err, errUnsafeAddress) {
			return false, "http_unsafe_address", nil
		}
		return false, "http_unreachable", nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, "http_status", nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil {
		return false, "http_unreachable", nil
	}
	if strings.TrimSpace(string(body)) != token {
		return false, "http_mismatch", nil
	}
	return true, "", nil
}

var errUnsafeAddress = errors.New("refusing non-public address")

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() &&
		!address.IsLinkLocalUnicast() && !address.IsMulticast() && !address.IsUnspecified() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(address) && !netip.MustParsePrefix("198.18.0.0/15").Contains(address)
}

// SafeHTTPClient resolves the target itself and only dials public unicast
// addresses, without proxies, with bounded time and at most two same-host
// redirects (http -> https).
func SafeHTTPClient(resolver *net.Resolver) *http.Client {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, err := resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, candidate := range addresses {
				if !publicAddress(candidate) {
					return nil, fmt.Errorf("%w: %s", errUnsafeAddress, candidate)
				}
			}
			if len(addresses) == 0 {
				return nil, errUnsafeAddress
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].Unmap().String(), port))
		},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > 2 || request.URL.Hostname() != via[0].URL.Hostname() ||
				request.URL.Path != via[0].URL.Path {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
