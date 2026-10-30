package acmeworker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type dns08FactStore struct {
	facts  CAPolicyFacts
	err    error
	calls  int
	asOf   time.Time
	policy []CAPolicyCandidate
}

func (s *dns08FactStore) LoadCAPolicyFacts(
	_ context.Context,
	_ IssueRequest,
	policy []CAPolicyCandidate,
	asOf time.Time,
	_, _ time.Duration,
) (CAPolicyFacts, error) {
	s.calls++
	s.asOf = asOf
	s.policy = append([]CAPolicyCandidate(nil), policy...)
	return s.facts, s.err
}

type dns08Probe struct {
	results map[string]CAProbeResult
	calls   []string
}

func (p *dns08Probe) Probe(_ context.Context, directoryURL string, _ time.Time) CAProbeResult {
	p.calls = append(p.calls, directoryURL)
	if result, found := p.results[directoryURL]; found {
		return result
	}
	return CAProbeResult{Available: true}
}

type dns08Issuer struct {
	calls    int
	requests []IssueRequest
	result   IssueResult
	err      error
	lkg      string
}

func (i *dns08Issuer) Issue(_ context.Context, request IssueRequest) (IssueResult, error) {
	i.calls++
	i.requests = append(i.requests, request)
	if i.err == nil && i.result.Certificate.LeafFingerprint != "" {
		i.lkg = i.result.Certificate.LeafFingerprint
	}
	return i.result, i.err
}

func TestDNS08FailsOverOnlyBeforeDurableIssuanceStarts(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	primary := &dns08Issuer{}
	backup := &dns08Issuer{result: IssueResult{OrderURI: "https://backup.example/order/1"}}
	facts := &dns08FactStore{}
	probe := &dns08Probe{results: map[string]CAProbeResult{
		"https://primary.example/directory": {
			FailoverSafe: true,
			Failure:      &Error{Code: CodeDirectoryUnavailable, Temporary: true},
		},
	}}
	issuer := dns08FailoverIssuer(t, now, facts, probe, primary, backup)

	result, err := issuer.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "example.test"))
	if err != nil || result.OrderURI != "https://backup.example/order/1" {
		t.Fatalf("Issue()=(%+v,%v)", result, err)
	}
	if primary.calls != 0 || backup.calls != 1 || len(probe.calls) != 2 {
		t.Fatalf("primary=%d backup=%d probes=%v", primary.calls, backup.calls, probe.calls)
	}
	request := backup.requests[0]
	if request.DirectoryURL != "https://backup.example/directory" || request.AccountKeyRef != "account/backup" ||
		!facts.asOf.Equal(now) {
		t.Fatalf("backup request=%+v facts as_of=%s", request, facts.asOf)
	}
}

func TestDNS08PinnedOrStartedOperationNeverSwitchesCA(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	primary := &dns08Issuer{err: &Error{Code: CodeOrderUncertain}}
	backup := &dns08Issuer{}
	facts := &dns08FactStore{facts: CAPolicyFacts{PinnedDirectoryURL: "https://primary.example/directory"}}
	probe := &dns08Probe{}
	issuer := dns08FailoverIssuer(t, now, facts, probe, primary, backup)
	request := validIssueRequest(ChallengeDNS01, "response-loss.example.test")

	for attempt := 0; attempt < 2; attempt++ {
		if _, err := issuer.Issue(t.Context(), request); ErrorCodeOf(err) != CodeOrderUncertain {
			t.Fatalf("Issue(%d) error=%v", attempt, err)
		}
	}
	if primary.calls != 2 || backup.calls != 0 || len(probe.calls) != 0 {
		t.Fatalf("primary=%d backup=%d probes=%v", primary.calls, backup.calls, probe.calls)
	}
}

func TestDNS08RateWindowsUseFixedClockAndBoundedBackoff(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	primaryURL := "https://primary.example/directory"
	backupURL := "https://backup.example/directory"
	t.Run("account budget selects backup", func(t *testing.T) {
		primary := &dns08Issuer{}
		backup := &dns08Issuer{}
		facts := &dns08FactStore{facts: CAPolicyFacts{Usage: map[string]CAPolicyUsage{
			primaryURL: {AccountAttempts: 2, AccountAvailableAt: now.Add(37 * time.Second)},
		}}}
		probe := &dns08Probe{}
		issuer := dns08FailoverIssuer(t, now, facts, probe, primary, backup)

		if _, err := issuer.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "account-window.example.test")); err != nil {
			t.Fatal(err)
		}
		if primary.calls != 0 || backup.calls != 1 || len(probe.calls) != 1 || probe.calls[0] != backupURL {
			t.Fatalf("primary=%d backup=%d probes=%v", primary.calls, backup.calls, probe.calls)
		}
	})

	t.Run("domain budgets fail closed at latest availability", func(t *testing.T) {
		facts := &dns08FactStore{facts: CAPolicyFacts{Usage: map[string]CAPolicyUsage{
			primaryURL: {DomainAttempts: 2, DomainAvailableAt: now.Add(4 * time.Minute)},
			backupURL:  {DomainAttempts: 2, DomainAvailableAt: now.Add(9 * time.Minute)},
		}}}
		probe := &dns08Probe{}
		issuer := dns08FailoverIssuer(t, now, facts, probe, &dns08Issuer{}, &dns08Issuer{})

		_, err := issuer.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "domain-window.example.test"))
		var policyErr *Error
		if !errors.As(err, &policyErr) || policyErr.Code != CodeRateLimited || policyErr.RetryAfter != 9*time.Minute ||
			len(probe.calls) != 0 {
			t.Fatalf("Issue() error=%+v probes=%v", err, probe.calls)
		}
	})

	t.Run("missing availability uses bounded exponential policy backoff", func(t *testing.T) {
		facts := &dns08FactStore{facts: CAPolicyFacts{Usage: map[string]CAPolicyUsage{
			primaryURL: {AccountAttempts: 4}, backupURL: {AccountAttempts: 4},
		}}}
		issuer := dns08FailoverIssuer(t, now, facts, &dns08Probe{}, &dns08Issuer{}, &dns08Issuer{})
		_, err := issuer.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "backoff.example.test"))
		var policyErr *Error
		if !errors.As(err, &policyErr) || policyErr.RetryAfter != 4*time.Minute {
			t.Fatalf("Issue() error=%+v want 4m backoff", err)
		}
	})
}

func TestDNS08DoesNotFailOverAfterValidationPermissionOrStoreFailure(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	t.Run("authorization validation", func(t *testing.T) {
		primary := &dns08Issuer{err: &Error{Code: CodeAuthorizationInvalid}}
		backup := &dns08Issuer{}
		issuer := dns08FailoverIssuer(t, now, &dns08FactStore{}, &dns08Probe{}, primary, backup)
		if _, err := issuer.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "invalid.example.test")); ErrorCodeOf(err) != CodeAuthorizationInvalid || primary.calls != 1 || backup.calls != 0 {
			t.Fatalf("error=%v primary=%d backup=%d", err, primary.calls, backup.calls)
		}
	})

	t.Run("directory permission", func(t *testing.T) {
		primary := &dns08Issuer{}
		backup := &dns08Issuer{}
		probe := &dns08Probe{results: map[string]CAProbeResult{
			"https://primary.example/directory": {
				Failure: &Error{Code: CodeDirectoryUnavailable},
			},
		}}
		issuer := dns08FailoverIssuer(t, now, &dns08FactStore{}, probe, primary, backup)
		if _, err := issuer.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "forbidden.example.test")); ErrorCodeOf(err) != CodeDirectoryUnavailable || primary.calls != 0 || backup.calls != 0 || len(probe.calls) != 1 {
			t.Fatalf("error=%v primary=%d backup=%d probes=%v", err, primary.calls, backup.calls, probe.calls)
		}
	})

	t.Run("policy facts unavailable", func(t *testing.T) {
		primary := &dns08Issuer{}
		backup := &dns08Issuer{}
		issuer := dns08FailoverIssuer(t, now, &dns08FactStore{err: errors.New("database unavailable")},
			&dns08Probe{}, primary, backup)
		if _, err := issuer.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "store.example.test")); ErrorCodeOf(err) != CodeOperationStoreFailed || primary.calls != 0 || backup.calls != 0 {
			t.Fatalf("error=%v primary=%d backup=%d", err, primary.calls, backup.calls)
		}
	})
}

func TestDNS08SelectedWorkerKeepsExactDNSCleanupAndLKG(t *testing.T) {
	now := testNow
	protocol := newProtocolServer(t, now, protocolOptions{})
	records := &challengeRecords{waitError: errors.New("propagation unavailable")}
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	backup := &dns08Issuer{}
	config := dns08Config(now, &dns08FactStore{}, &dns08Probe{})
	issuer, err := NewCAFailoverIssuer(config, []CAEndpoint{
		{DirectoryURL: protocol.url("/directory"), AccountKeyRef: "account-key", Issuer: worker},
		{DirectoryURL: "https://backup.example/directory", AccountKeyRef: "account/backup", Issuer: backup},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = issuer.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "*.cleanup.example.test"))
	if ErrorCodeOf(err) != CodeChallengePropagationFailed || len(records.identities) != 1 || len(records.deleted) != 1 ||
		backup.calls != 0 {
		t.Fatalf("error=%v identities=%+v deletes=%v backup=%d", err, records.identities, records.deleted, backup.calls)
	}
	identity := records.identities[0]
	wantDelete := identity.ProviderRef + "|record/" + identity.AttemptID.String() + "|" + identity.ExactValue
	if records.deleted[0] != wantDelete {
		t.Fatalf("delete=%q want=%q", records.deleted[0], wantDelete)
	}

	primary := &dns08Issuer{err: &Error{Code: CodeFinalizeFailed, Temporary: true}, lkg: "sha256:lkg"}
	lkgIssuer := dns08FailoverIssuer(t, now, &dns08FactStore{}, &dns08Probe{}, primary, &dns08Issuer{})
	if _, err := lkgIssuer.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "lkg.example.test")); ErrorCodeOf(err) != CodeFinalizeFailed || primary.lkg != "sha256:lkg" {
		t.Fatalf("error=%v lkg=%q", err, primary.lkg)
	}
}

func TestDNS08HTTPDirectoryProbeClassifiesFailoverBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name         string
		response     *http.Response
		err          error
		available    bool
		failoverSafe bool
		code         ErrorCode
		retryAfter   time.Duration
	}{
		{name: "success", response: dns08HTTPResponse(http.StatusOK, ""), available: true},
		{name: "connection", err: errors.New("connection refused"), failoverSafe: true, code: CodeDirectoryUnavailable},
		{name: "server error", response: dns08HTTPResponse(http.StatusBadGateway, ""), failoverSafe: true, code: CodeDirectoryUnavailable},
		{name: "rate limit", response: dns08HTTPResponse(http.StatusTooManyRequests, "120"), failoverSafe: true,
			code: CodeRateLimited, retryAfter: time.Minute},
		{name: "permission", response: dns08HTTPResponse(http.StatusForbidden, ""), code: CodeDirectoryUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: dns08RoundTripper{response: test.response, err: test.err}}
			probe, err := NewHTTPDirectoryProbe(client, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			result := probe.Probe(t.Context(), "https://ca.example/directory", now)
			if result.Available != test.available || result.FailoverSafe != test.failoverSafe ||
				ErrorCodeOf(result.Failure) != test.code {
				t.Fatalf("Probe()=%+v", result)
			}
			var probeErr *Error
			if result.Failure != nil && (!errors.As(result.Failure, &probeErr) || probeErr.RetryAfter != test.retryAfter) {
				t.Fatalf("Probe() failure=%+v", result.Failure)
			}
		})
	}
}

type dns08RoundTripper struct {
	response *http.Response
	err      error
}

func (r dns08RoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return r.response, r.err
}

func dns08HTTPResponse(status int, retryAfter string) *http.Response {
	response := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"directory":"response"}`)),
	}
	if retryAfter != "" {
		response.Header.Set("Retry-After", retryAfter)
	}
	return response
}

func dns08FailoverIssuer(
	t *testing.T,
	now time.Time,
	facts CAPolicyFactStore,
	probe CADirectoryProbe,
	primary, backup CertificateIssuer,
) *CAFailoverIssuer {
	t.Helper()
	issuer, err := NewCAFailoverIssuer(dns08Config(now, facts, probe), []CAEndpoint{
		{DirectoryURL: "https://primary.example/directory", AccountKeyRef: "account/primary", Issuer: primary},
		{DirectoryURL: "https://backup.example/directory", AccountKeyRef: "account/backup", Issuer: backup},
	})
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func dns08Config(now time.Time, facts CAPolicyFactStore, probe CADirectoryProbe) CAFailoverConfig {
	config := DefaultCAFailoverConfig()
	config.Clock = func() time.Time { return now }
	config.Facts = facts
	config.Probe = probe
	config.MaxAccountAttempts = 2
	config.MaxDomainAttempts = 2
	config.BackoffBase = time.Minute
	config.BackoffMaximum = 10 * time.Minute
	config.MaxRetryAfter = 30 * time.Minute
	return config
}
