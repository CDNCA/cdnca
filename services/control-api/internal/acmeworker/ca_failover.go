package acmeworker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CAPolicyCandidate struct {
	DirectoryURL  string
	AccountKeyRef string
}

type CAPolicyUsage struct {
	AccountAttempts    int
	DomainAttempts     int
	AccountAvailableAt time.Time
	DomainAvailableAt  time.Time
	RetryAfterUntil    time.Time
}

type CAPolicyFacts struct {
	PinnedDirectoryURL string
	Usage              map[string]CAPolicyUsage
}

type CAPolicyFactStore interface {
	LoadCAPolicyFacts(
		context.Context,
		IssueRequest,
		[]CAPolicyCandidate,
		time.Time,
		time.Duration,
		time.Duration,
	) (CAPolicyFacts, error)
}

type CAProbeResult struct {
	Available    bool
	FailoverSafe bool
	Failure      error
}

type CADirectoryProbe interface {
	Probe(context.Context, string, time.Time) CAProbeResult
}

type CAEndpoint struct {
	DirectoryURL  string
	AccountKeyRef string
	Issuer        CertificateIssuer
}

type CAFailoverConfig struct {
	Clock              Clock
	Facts              CAPolicyFactStore
	Probe              CADirectoryProbe
	AccountWindow      time.Duration
	DomainWindow       time.Duration
	MaxAccountAttempts int
	MaxDomainAttempts  int
	BackoffBase        time.Duration
	BackoffMaximum     time.Duration
	MaxRetryAfter      time.Duration
}

func DefaultCAFailoverConfig() CAFailoverConfig {
	return CAFailoverConfig{
		Clock:              time.Now,
		AccountWindow:      time.Hour,
		DomainWindow:       7 * 24 * time.Hour,
		MaxAccountAttempts: 20,
		MaxDomainAttempts:  5,
		BackoffBase:        time.Minute,
		BackoffMaximum:     time.Hour,
		MaxRetryAfter:      24 * time.Hour,
	}
}

type CAFailoverIssuer struct {
	config     CAFailoverConfig
	endpoints  []CAEndpoint
	candidates []CAPolicyCandidate
}

func NewCAFailoverIssuer(config CAFailoverConfig, endpoints []CAEndpoint) (*CAFailoverIssuer, error) {
	if config.Clock == nil || config.Facts == nil || config.Probe == nil ||
		config.AccountWindow <= 0 || config.AccountWindow > 30*24*time.Hour ||
		config.DomainWindow <= 0 || config.DomainWindow > 90*24*time.Hour ||
		config.MaxAccountAttempts < 1 || config.MaxAccountAttempts > 10000 ||
		config.MaxDomainAttempts < 1 || config.MaxDomainAttempts > 10000 ||
		config.BackoffBase <= 0 || config.BackoffMaximum < config.BackoffBase ||
		config.BackoffMaximum > 24*time.Hour || config.MaxRetryAfter <= 0 ||
		config.MaxRetryAfter > 7*24*time.Hour || len(endpoints) < 1 || len(endpoints) > 4 {
		return nil, failure(CodeInvalidInput, nil)
	}
	issuer := &CAFailoverIssuer{config: config, endpoints: make([]CAEndpoint, len(endpoints))}
	issuer.candidates = make([]CAPolicyCandidate, len(endpoints))
	seen := make(map[string]struct{}, len(endpoints))
	for index, endpoint := range endpoints {
		if !validCADirectoryURL(endpoint.DirectoryURL) || endpoint.Issuer == nil ||
			len(endpoint.AccountKeyRef) < 1 || len(endpoint.AccountKeyRef) > 200 ||
			endpoint.AccountKeyRef != strings.TrimSpace(endpoint.AccountKeyRef) ||
			containsControl(endpoint.AccountKeyRef) {
			return nil, failure(CodeInvalidInput, nil)
		}
		if _, exists := seen[endpoint.DirectoryURL]; exists {
			return nil, failure(CodeInvalidInput, nil)
		}
		seen[endpoint.DirectoryURL] = struct{}{}
		issuer.endpoints[index] = endpoint
		issuer.candidates[index] = CAPolicyCandidate{
			DirectoryURL: endpoint.DirectoryURL, AccountKeyRef: endpoint.AccountKeyRef,
		}
	}
	return issuer, nil
}

func (i *CAFailoverIssuer) Issue(ctx context.Context, request IssueRequest) (IssueResult, error) {
	if i == nil || ctx == nil {
		return IssueResult{}, failure(CodeInvalidInput, nil)
	}
	now := i.config.Clock().UTC()
	facts, err := i.config.Facts.LoadCAPolicyFacts(
		ctx, request, i.candidates, now, i.config.AccountWindow, i.config.DomainWindow,
	)
	if err != nil {
		return IssueResult{}, failure(CodeOperationStoreFailed, nil)
	}
	if facts.PinnedDirectoryURL != "" {
		for _, endpoint := range i.endpoints {
			if endpoint.DirectoryURL == facts.PinnedDirectoryURL {
				return endpoint.Issuer.Issue(ctx, caRequestForEndpoint(request, endpoint))
			}
		}
		return IssueResult{}, failure(CodeOperationConflict, nil)
	}

	var retryAfter time.Duration
	var lastFailure error
	for _, endpoint := range i.endpoints {
		if limited, delay := i.rateLimited(facts.Usage[endpoint.DirectoryURL], now); limited {
			retryAfter = max(retryAfter, delay)
			lastFailure = &Error{Code: CodeRateLimited, RetryAfter: retryAfter, Temporary: true}
			continue
		}
		probe := i.config.Probe.Probe(ctx, endpoint.DirectoryURL, now)
		if probe.Available {
			return endpoint.Issuer.Issue(ctx, caRequestForEndpoint(request, endpoint))
		}
		if probe.Failure == nil {
			return IssueResult{}, failure(CodeDirectoryUnavailable, nil)
		}
		if !probe.FailoverSafe {
			return IssueResult{}, probe.Failure
		}
		lastFailure = probe.Failure
		var classified *Error
		if errors.As(probe.Failure, &classified) {
			retryAfter = max(retryAfter, classified.RetryAfter)
		}
	}
	if retryAfter > 0 {
		return IssueResult{}, &Error{
			Code: CodeRateLimited, RetryAfter: min(retryAfter, i.config.MaxRetryAfter), Temporary: true,
		}
	}
	if lastFailure != nil {
		return IssueResult{}, lastFailure
	}
	return IssueResult{}, &Error{Code: CodeDirectoryUnavailable, Temporary: true}
}

func (i *CAFailoverIssuer) rateLimited(usage CAPolicyUsage, now time.Time) (bool, time.Duration) {
	accountLimited := usage.AccountAttempts >= i.config.MaxAccountAttempts
	domainLimited := usage.DomainAttempts >= i.config.MaxDomainAttempts
	deadline := usage.RetryAfterUntil
	if accountLimited && usage.AccountAvailableAt.After(deadline) {
		deadline = usage.AccountAvailableAt
	}
	if domainLimited && usage.DomainAvailableAt.After(deadline) {
		deadline = usage.DomainAvailableAt
	}
	if deadline.After(now) {
		return true, min(deadline.Sub(now), i.config.MaxRetryAfter)
	}
	if !accountLimited && !domainLimited {
		return false, 0
	}
	excess := max(usage.AccountAttempts-i.config.MaxAccountAttempts,
		usage.DomainAttempts-i.config.MaxDomainAttempts) + 1
	delay := i.config.BackoffBase
	for attempt := 1; attempt < excess && delay < i.config.BackoffMaximum; attempt++ {
		if delay > i.config.BackoffMaximum/2 {
			delay = i.config.BackoffMaximum
			break
		}
		delay *= 2
	}
	return true, min(delay, min(i.config.BackoffMaximum, i.config.MaxRetryAfter))
}

func caRequestForEndpoint(request IssueRequest, endpoint CAEndpoint) IssueRequest {
	request.DirectoryURL = endpoint.DirectoryURL
	request.AccountKeyRef = endpoint.AccountKeyRef
	return request
}

func validCADirectoryURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && value == strings.TrimSpace(value) && parsed.Scheme == "https" &&
		parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

type HTTPDirectoryProbe struct {
	client        *http.Client
	maxRetryAfter time.Duration
}

func NewHTTPDirectoryProbe(client *http.Client, maxRetryAfter time.Duration) (*HTTPDirectoryProbe, error) {
	if client == nil || maxRetryAfter <= 0 || maxRetryAfter > 7*24*time.Hour {
		return nil, failure(CodeInvalidInput, nil)
	}
	return &HTTPDirectoryProbe{client: client, maxRetryAfter: maxRetryAfter}, nil
}

func (p *HTTPDirectoryProbe) Probe(ctx context.Context, directoryURL string, now time.Time) CAProbeResult {
	if p == nil || ctx == nil || !validCADirectoryURL(directoryURL) {
		return CAProbeResult{Failure: failure(CodeInvalidInput, nil)}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL, nil)
	if err != nil {
		return CAProbeResult{Failure: failure(CodeInvalidInput, nil)}
	}
	response, err := p.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return CAProbeResult{Failure: contextFailure(ctx.Err())}
		}
		return CAProbeResult{
			FailoverSafe: true,
			Failure:      &Error{Code: CodeDirectoryUnavailable, Temporary: true},
		}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return CAProbeResult{Available: true}
	}
	if response.StatusCode == http.StatusTooManyRequests {
		delay := min(parseRetryAfter(response.Header.Get("Retry-After"), now.UTC()), p.maxRetryAfter)
		return CAProbeResult{
			FailoverSafe: true,
			Failure:      &Error{Code: CodeRateLimited, RetryAfter: delay, Temporary: true},
		}
	}
	if response.StatusCode >= 500 {
		return CAProbeResult{
			FailoverSafe: true,
			Failure:      &Error{Code: CodeDirectoryUnavailable, Temporary: true},
		}
	}
	return CAProbeResult{Failure: failure(CodeDirectoryUnavailable, nil)}
}
