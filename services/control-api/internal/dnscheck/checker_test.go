package dnscheck

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCheckerStableClassifications(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	authorityOne := testEndpoint(t, "192.0.2.1", 53)
	authorityTwo := testEndpoint(t, "192.0.2.2", 53)
	publicOne := testEndpoint(t, "198.51.100.1", 53)
	publicTwo := testEndpoint(t, "198.51.100.2", 53)
	authoritative := []NamedResolver{{Name: "ns1.example.test", Endpoint: authorityOne}, {Name: "ns2.example.test", Endpoint: authorityTwo}}
	public := []NamedResolver{{Name: "recursive-a", Endpoint: publicOne}, {Name: "recursive-b", Endpoint: publicTwo}}
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	nxdomainSOA := []DNSRecord{{Name: "example.test.", Type: RecordSOA, TTL: 90}}

	tests := []struct {
		name      string
		authority []DNSResponse
		public    []DNSResponse
		startedAt *time.Time
		want      Classification
	}{
		{name: "healthy", authority: []DNSResponse{answerResponse(true, query.Name, RecordA, "192.0.2.10"), answerResponse(true, query.Name, RecordA, "192.0.2.10")}, public: []DNSResponse{answerResponse(false, query.Name, RecordA, "192.0.2.10"), answerResponse(false, query.Name, RecordA, "192.0.2.10")}, want: ClassificationHealthy},
		{name: "missing", authority: []DNSResponse{{Authoritative: true}, {Authoritative: true}}, public: []DNSResponse{{}, {}}, want: ClassificationMissing},
		{name: "wrong value", authority: []DNSResponse{answerResponse(true, query.Name, RecordA, "192.0.2.20"), answerResponse(true, query.Name, RecordA, "192.0.2.20")}, public: []DNSResponse{answerResponse(false, query.Name, RecordA, "192.0.2.20"), answerResponse(false, query.Name, RecordA, "192.0.2.20")}, want: ClassificationWrongValue},
		{name: "nxdomain", authority: []DNSResponse{{Authoritative: true, RCode: 3, Authority: nxdomainSOA}, {Authoritative: true, RCode: 3, Authority: nxdomainSOA}}, public: []DNSResponse{{RCode: 3, Authority: nxdomainSOA}, {RCode: 3, Authority: nxdomainSOA}}, want: ClassificationNXDOMAIN},
		{name: "servfail", authority: []DNSResponse{{Authoritative: true, RCode: 2}, {Authoritative: true, RCode: 2}}, public: []DNSResponse{{RCode: 2}, {RCode: 2}}, want: ClassificationSERVFAIL},
		{name: "servfail without aa", authority: []DNSResponse{{RCode: 2}, {RCode: 2}}, public: []DNSResponse{{RCode: 2}, {RCode: 2}}, want: ClassificationSERVFAIL},
		{name: "split authority", authority: []DNSResponse{answerResponse(true, query.Name, RecordA, "192.0.2.10"), answerResponse(true, query.Name, RecordA, "192.0.2.20")}, public: []DNSResponse{answerResponse(false, query.Name, RecordA, "192.0.2.10"), answerResponse(false, query.Name, RecordA, "192.0.2.10")}, want: ClassificationAuthorityInconsistent},
		{name: "propagating", authority: []DNSResponse{answerResponse(true, query.Name, RecordA, "192.0.2.10"), answerResponse(true, query.Name, RecordA, "192.0.2.10")}, public: []DNSResponse{answerResponse(false, query.Name, RecordA, "192.0.2.20"), answerResponse(false, query.Name, RecordA, "192.0.2.20")}, startedAt: timePointer(now.Add(-time.Minute)), want: ClassificationPublicPropagating},
		{name: "propagation failed", authority: []DNSResponse{answerResponse(true, query.Name, RecordA, "192.0.2.10"), answerResponse(true, query.Name, RecordA, "192.0.2.10")}, public: []DNSResponse{answerResponse(false, query.Name, RecordA, "192.0.2.20"), answerResponse(false, query.Name, RecordA, "192.0.2.20")}, startedAt: timePointer(now.Add(-10 * time.Minute)), want: ClassificationPublicPropagationFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := newFakeResolver()
			for index, endpoint := range []ResolverEndpoint{authorityOne, authorityTwo} {
				resolver.set(endpoint, query, responseHandler(test.authority[index]))
			}
			for index, endpoint := range []ResolverEndpoint{publicOne, publicTwo} {
				resolver.set(endpoint, query, responseHandler(test.public[index]))
			}
			checker := testChecker(t, resolver, authoritative, public, now, 1, 4)
			request := baseRequest(now, RecordA, "192.0.2.10")
			request.PropagationStartedAt = test.startedAt
			result, err := checker.Check(context.Background(), request)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if result.Status != test.want {
				t.Fatalf("status = %q, want %q; observations = %#v", result.Status, test.want, result.Observations)
			}
			if (result.Compliant) != (test.want == ClassificationHealthy) {
				t.Fatalf("compliant = %t", result.Compliant)
			}
		})
	}
}

func TestCheckerTreatsOnlyAuthoritativeTTLDifferencesAsSplit(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	authorityOne := testEndpoint(t, "192.0.2.16", 53)
	authorityTwo := testEndpoint(t, "192.0.2.17", 53)
	publicOne := testEndpoint(t, "198.51.100.16", 53)
	publicTwo := testEndpoint(t, "198.51.100.17", 53)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	resolver := newFakeResolver()
	responses := []struct {
		endpoint      ResolverEndpoint
		authoritative bool
		ttl           uint32
	}{
		{endpoint: authorityOne, authoritative: true, ttl: 60},
		{endpoint: authorityTwo, authoritative: true, ttl: 120},
		{endpoint: publicOne, ttl: 30},
		{endpoint: publicTwo, ttl: 45},
	}
	for _, item := range responses {
		response := answerResponse(item.authoritative, query.Name, RecordA, "192.0.2.10")
		response.Answers[0].TTL = item.ttl
		resolver.set(item.endpoint, query, responseHandler(response))
	}
	checker := testChecker(t, resolver,
		[]NamedResolver{{Name: "ns1.example.test", Endpoint: authorityOne}, {Name: "ns2.example.test", Endpoint: authorityTwo}},
		[]NamedResolver{{Name: "public-a", Endpoint: publicOne}, {Name: "public-b", Endpoint: publicTwo}}, now, 1, 4)
	result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
	if err != nil || result.Status != ClassificationAuthorityInconsistent {
		t.Fatalf("Check() = (%#v, %v)", result, err)
	}
	publicOutcomes := []resolverOutcome{
		{status: ClassificationHealthy, observations: []Observation{{RecordType: RecordA, Status: ClassificationHealthy, Values: []string{"192.0.2.10"}, MinimumTTL: 30}}},
		{status: ClassificationHealthy, observations: []Observation{{RecordType: RecordA, Status: ClassificationHealthy, Values: []string{"192.0.2.10"}, MinimumTTL: 45}}},
	}
	if status := aggregateOutcomes(publicOutcomes, false); status != ClassificationHealthy {
		t.Fatalf("public recursive TTL delta status = %q", status)
	}
}

func TestRecordsForOwnerPreservesZeroMinimumTTL(t *testing.T) {
	values, _, minimumTTL, observed, malformed := recordsForOwner([]DNSRecord{
		{Name: "www.example.test.", Type: RecordA, TTL: 60, Value: "192.0.2.10"},
		{Name: "www.example.test.", Type: RecordA, TTL: 0, Value: "192.0.2.11"},
	}, "www.example.test.", RecordA)
	if malformed || !observed || minimumTTL != 0 || len(values) != 2 {
		t.Fatalf("recordsForOwner() = (%#v, %d, %t, %t)", values, minimumTTL, observed, malformed)
	}
}

func TestCheckerRetriesTimeoutAndHonorsCancellation(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	authority := testEndpoint(t, "192.0.2.10", 53)
	public := testEndpoint(t, "198.51.100.10", 53)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	resolver := newFakeResolver()
	var mu sync.Mutex
	authorityCalls := 0
	resolver.set(authority, query, func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		authorityCalls++
		if authorityCalls == 1 {
			return DNSResponse{}, context.DeadlineExceeded
		}
		return answerResponse(true, query.Name, RecordA, "192.0.2.10"), nil
	})
	resolver.set(public, query, responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10")))
	checker := testChecker(t, resolver, []NamedResolver{{Name: "ns1.example.test", Endpoint: authority}}, []NamedResolver{{Name: "public", Endpoint: public}}, now, 2, 4)
	result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
	if err != nil || result.Status != ClassificationHealthy || resolver.callCount(authority, query) != 2 {
		t.Fatalf("retry Check() = (%#v, %v), calls = %d", result, err, resolver.callCount(authority, query))
	}

	blocking := newFakeResolver()
	blocking.set(authority, query, func(ctx context.Context, _ ResolverEndpoint, _ DNSQuery) (DNSResponse, error) {
		<-ctx.Done()
		return DNSResponse{}, ctx.Err()
	})
	blocking.set(public, query, responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10")))
	cancelChecker := testChecker(t, blocking, []NamedResolver{{Name: "ns1.example.test", Endpoint: authority}}, []NamedResolver{{Name: "public", Endpoint: public}}, now, 3, 4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = cancelChecker.Check(ctx, baseRequest(now, RecordA, "192.0.2.10"))
	if !errors.Is(err, context.Canceled) || blocking.callCount(authority, query) != 0 {
		t.Fatalf("cancel Check() error = %v, calls = %d", err, blocking.callCount(authority, query))
	}

	inFlightContext, inFlightCancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, checkErr := cancelChecker.Check(inFlightContext, baseRequest(now, RecordA, "192.0.2.10"))
		done <- checkErr
	}()
	deadline := time.Now().Add(time.Second)
	for blocking.callCount(authority, query) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	inFlightCancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) || blocking.callCount(authority, query) != 1 {
			t.Fatalf("in-flight cancel error = %v, calls = %d", err, blocking.callCount(authority, query))
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight cancellation did not stop the check")
	}
}

func TestCheckerClassifiesTerminalTimeout(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	authority := testEndpoint(t, "192.0.2.11", 53)
	public := testEndpoint(t, "198.51.100.11", 53)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	resolver := newFakeResolver()
	resolver.set(authority, query, func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
		return DNSResponse{}, context.DeadlineExceeded
	})
	resolver.set(public, query, responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10")))
	checker := testChecker(t, resolver, []NamedResolver{{Name: "ns1.example.test", Endpoint: authority}}, []NamedResolver{{Name: "public", Endpoint: public}}, now, 2, 4)
	result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
	if err != nil || result.Status != ClassificationTimeout || result.Observations[0].Attempts != 2 {
		t.Fatalf("Check() = (%#v, %v)", result, err)
	}
}

func TestCheckerCNAMEChainLoopAndDepth(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	authority := testEndpoint(t, "192.0.2.12", 53)
	public := testEndpoint(t, "198.51.100.12", 53)
	authoritative := []NamedResolver{{Name: "ns1.example.test", Endpoint: authority}}
	publicResolvers := []NamedResolver{{Name: "public", Endpoint: public}}

	t.Run("chain", func(t *testing.T) {
		resolver := newFakeResolver()
		ownerQuery := DNSQuery{Name: "www.example.test.", Type: RecordA}
		aliasQuery := DNSQuery{Name: "edge.example.test.", Type: RecordA}
		resolver.set(authority, ownerQuery, responseHandler(answerResponse(true, ownerQuery.Name, RecordCNAME, "edge.example.test.")))
		resolver.set(authority, aliasQuery, responseHandler(answerResponse(true, aliasQuery.Name, RecordA, "192.0.2.10")))
		resolver.set(public, ownerQuery, responseHandler(answerResponse(false, ownerQuery.Name, RecordCNAME, "edge.example.test.")))
		resolver.set(public, aliasQuery, responseHandler(answerResponse(false, aliasQuery.Name, RecordA, "192.0.2.10")))
		checker := testChecker(t, resolver, authoritative, publicResolvers, now, 1, 4)
		result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
		if err != nil || result.Status != ClassificationCNAMEChain {
			t.Fatalf("chain Check() = (%#v, %v)", result, err)
		}
	})

	t.Run("loop", func(t *testing.T) {
		resolver := newFakeResolver()
		ownerQuery := DNSQuery{Name: "www.example.test.", Type: RecordA}
		aliasQuery := DNSQuery{Name: "edge.example.test.", Type: RecordA}
		for _, endpoint := range []ResolverEndpoint{authority, public} {
			isAuthority := endpoint == authority
			resolver.set(endpoint, ownerQuery, responseHandler(answerResponse(isAuthority, ownerQuery.Name, RecordCNAME, "edge.example.test.")))
			resolver.set(endpoint, aliasQuery, responseHandler(answerResponse(isAuthority, aliasQuery.Name, RecordCNAME, "www.example.test.")))
		}
		checker := testChecker(t, resolver, authoritative, publicResolvers, now, 1, 4)
		result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
		if err != nil || result.Status != ClassificationCNAMELoop {
			t.Fatalf("loop Check() = (%#v, %v)", result, err)
		}
	})

	t.Run("direct cname self loop", func(t *testing.T) {
		resolver := newFakeResolver()
		query := DNSQuery{Name: "www.example.test.", Type: RecordCNAME}
		resolver.set(authority, query, responseHandler(answerResponse(true, query.Name, RecordCNAME, query.Name)))
		resolver.set(public, query, responseHandler(answerResponse(false, query.Name, RecordCNAME, query.Name)))
		checker := testChecker(t, resolver, authoritative, publicResolvers, now, 1, 4)
		request := baseRequest(now, RecordCNAME, "www.example.test")
		result, err := checker.Check(context.Background(), request)
		if err != nil || result.Status != ClassificationCNAMELoop {
			t.Fatalf("self-loop Check() = (%#v, %v)", result, err)
		}
	})

	t.Run("depth", func(t *testing.T) {
		resolver := newFakeResolver()
		queries := []DNSQuery{{Name: "www.example.test.", Type: RecordA}, {Name: "one.example.test.", Type: RecordA}}
		for _, endpoint := range []ResolverEndpoint{authority, public} {
			isAuthority := endpoint == authority
			resolver.set(endpoint, queries[0], responseHandler(answerResponse(isAuthority, queries[0].Name, RecordCNAME, "one.example.test.")))
			resolver.set(endpoint, queries[1], responseHandler(answerResponse(isAuthority, queries[1].Name, RecordCNAME, "two.example.test.")))
		}
		checker := testChecker(t, resolver, authoritative, publicResolvers, now, 1, 1)
		result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
		if err != nil || result.Status != ClassificationCNAMEDepthExceeded {
			t.Fatalf("depth Check() = (%#v, %v)", result, err)
		}
	})
}

func TestCheckerTenantScopesRemainIsolatedUnderConcurrency(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	authority := testEndpoint(t, "192.0.2.13", 53)
	public := testEndpoint(t, "198.51.100.13", 53)
	resolver := newFakeResolver()
	for _, name := range []string{"a.example.test.", "b.example.test."} {
		query := DNSQuery{Name: name, Type: RecordA}
		resolver.set(authority, query, responseHandler(answerResponse(true, name, RecordA, "192.0.2.10")))
		resolver.set(public, query, responseHandler(answerResponse(false, name, RecordA, "192.0.2.10")))
	}
	checker := testChecker(t, resolver, []NamedResolver{{Name: "ns1.example.test", Endpoint: authority}}, []NamedResolver{{Name: "public", Endpoint: public}}, now, 1, 4)

	requests := []CheckRequest{baseRequest(now, RecordA, "192.0.2.10"), baseRequest(now, RecordA, "192.0.2.10")}
	requests[0].Name = "a.example.test"
	requests[0].Provider.Records[0].Name = "a.example.test"
	requests[1].TenantID = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	requests[1].SiteID = uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	requests[1].Name = "b.example.test"
	requests[1].Provider.TenantID = requests[1].TenantID
	requests[1].Provider.SiteID = requests[1].SiteID
	requests[1].Provider.Records[0].Name = "b.example.test"

	results := make([]CheckResult, len(requests))
	var group sync.WaitGroup
	for index := range requests {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			var err error
			results[index], err = checker.Check(context.Background(), requests[index])
			if err != nil {
				t.Errorf("Check(%d) error = %v", index, err)
			}
		}(index)
	}
	group.Wait()
	for index := range requests {
		if results[index].TenantID != requests[index].TenantID || results[index].SiteID != requests[index].SiteID || results[index].Name != requests[index].Name+"." {
			t.Fatalf("scope %d leaked: %#v", index, results[index])
		}
	}
}

func TestCheckerRejectsUnconfiguredAuthoritativeName(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	authority := testEndpoint(t, "192.0.2.14", 53)
	public := testEndpoint(t, "198.51.100.14", 53)
	checker := testChecker(t, newFakeResolver(), []NamedResolver{{Name: "ns1.example.test", Endpoint: authority}}, []NamedResolver{{Name: "public", Endpoint: public}}, now, 1, 4)
	request := baseRequest(now, RecordA, "192.0.2.10")
	request.AuthoritativeNS = []string{"attacker.example"}
	_, err := checker.Check(context.Background(), request)
	if !errors.Is(err, ErrResolverNameAbsent) {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestCheckerDoesNotCallProviderSnapshotHealthyWhenPlanHasChanges(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	authority := testEndpoint(t, "192.0.2.15", 53)
	public := testEndpoint(t, "198.51.100.15", 53)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	resolver := newFakeResolver()
	resolver.set(authority, query, responseHandler(answerResponse(true, query.Name, RecordA, "192.0.2.10")))
	resolver.set(public, query, responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10")))
	checker := testChecker(t, resolver, []NamedResolver{{Name: "ns1.example.test", Endpoint: authority}}, []NamedResolver{{Name: "public", Endpoint: public}}, now, 1, 4)
	request := baseRequest(now, RecordA, "192.0.2.10")
	request.Provider.Records[0].Value = "192.0.2.20"
	result, err := checker.Check(context.Background(), request)
	if err != nil || result.Status != ClassificationHealthy || result.Compliant || len(result.RepairPlan.Operations) != 1 {
		t.Fatalf("Check() = (%#v, %v)", result, err)
	}
}

func timePointer(value time.Time) *time.Time { return &value }
