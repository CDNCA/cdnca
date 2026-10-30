package acmehttp01

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type httpProbe struct {
	baseURL string
	client  *http.Client
}

func newHTTPProbe(address string, timeout time.Duration) (*httpProbe, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return nil, ErrInvalidStateRoot
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, ErrInvalidStateRoot
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	return &httpProbe{
		baseURL: "http://" + net.JoinHostPort(host, port),
		client:  &http.Client{Transport: transport, Timeout: timeout},
	}, nil
}

func (p *httpProbe) Check(ctx context.Context, host, token string, expected *string) error {
	if p == nil || p.client == nil || !validHost(host) || !tokenPattern.MatchString(token) {
		return ErrHealthFailed
	}
	target, err := url.Parse(p.baseURL + ChallengePathPrefix + token)
	if err != nil {
		return ErrHealthFailed
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return ErrHealthFailed
	}
	request.Host = host
	request.Header.Set("Accept", "text/plain")
	response, err := p.client.Do(request)
	if err != nil {
		return ErrHealthFailed
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(body) > 1024 {
		return ErrHealthFailed
	}
	if expected == nil {
		if response.StatusCode != http.StatusNotFound {
			return ErrHealthFailed
		}
		return nil
	}
	if response.StatusCode != http.StatusOK || string(body) != *expected {
		return ErrHealthFailed
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if mediaType != "" && mediaType != "text/plain" {
		return fmt.Errorf("%w: unexpected challenge media type", ErrHealthFailed)
	}
	return nil
}
