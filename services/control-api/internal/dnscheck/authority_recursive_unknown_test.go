package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestReconcilerResolverDependencyUnknownKeepsLKG(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	tests := []struct {
		name        string
		authorityFn func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error)
		publicFn    func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error)
	}{
		{name: "authority-servfail", authorityFn: func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
			return DNSResponse{Authoritative: true, RCode: 2}, nil
		}, publicFn: responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10"))},
		{name: "authority-timeout", authorityFn: func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
			return DNSResponse{}, context.DeadlineExceeded
		}, publicFn: responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10"))},
		{name: "authority-transport", authorityFn: func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
			return DNSResponse{}, errors.New("resolver transport failed")
		}, publicFn: responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10"))},
		{name: "authority-malformed", authorityFn: func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
			return DNSResponse{Authoritative: true, Answers: []DNSRecord{
				{Name: query.Name, Type: RecordCNAME, TTL: 60, Value: "one.example.test."},
				{Name: query.Name, Type: RecordCNAME, TTL: 60, Value: "two.example.test."},
			}}, nil
		}, publicFn: responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10"))},
		{name: "recursive-servfail", authorityFn: responseHandler(answerResponse(true, query.Name, RecordA, "192.0.2.10")), publicFn: func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
			return DNSResponse{RCode: 2}, nil
		}},
		{name: "recursive-timeout", authorityFn: responseHandler(answerResponse(true, query.Name, RecordA, "192.0.2.10")), publicFn: func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
			return DNSResponse{}, context.DeadlineExceeded
		}},
		{name: "recursive-transport", authorityFn: responseHandler(answerResponse(true, query.Name, RecordA, "192.0.2.10")), publicFn: func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
			return DNSResponse{}, errors.New("recursive transport failed")
		}},
		{name: "recursive-malformed", authorityFn: responseHandler(answerResponse(true, query.Name, RecordA, "192.0.2.10")), publicFn: func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
			return DNSResponse{Answers: []DNSRecord{
				{Name: query.Name, Type: RecordCNAME, TTL: 60, Value: "one.example.test."},
				{Name: query.Name, Type: RecordCNAME, TTL: 60, Value: "two.example.test."},
			}}, nil
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := testEndpoint(t, "192.0.2.201", 53)
			public := testEndpoint(t, "198.51.100.201", 53)
			resolver := newFakeResolver()
			resolver.set(authority, query, test.authorityFn)
			resolver.set(public, query, test.publicFn)
			checker := testChecker(t, resolver,
				[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
				[]NamedResolver{{Name: "recursive-a", Endpoint: public}}, now, 1, 4)
			request := baseRequest(now, RecordA, "192.0.2.10")
			request.Provider.Records[0].Value = "192.0.2.20"
			provider := &fakeProviderAdapter{revision: request.Provider.Revision}
			reconciler := newTestReconciler(t, checker, provider, now, func(config *ReconcilerConfig) {
				config.PollAttempts = 1
				config.RequiredConsecutive = 1
			})

			result, err := reconciler.Apply(context.Background(), ReconcileRequest{
				IdempotencyKey: "resolver-unknown-" + test.name, Check: request,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != TaskPropagating || result.ErrorClass != ProviderErrorTransient ||
				result.ErrorCode != "dependency_unavailable" || result.CompensationPlan != nil ||
				len(result.Propagation) != 1 || !result.Propagation[0].DependencyUnavailable {
				t.Fatalf("resolver unknown result = %#v, want propagating dependency LKG", result)
			}
			if result.LastCheck == nil || len(result.LastCheck.Observations) == 0 {
				t.Fatalf("resolver unknown result lost observations: %#v", result)
			}
		})
	}
}

func TestReconcilerCommitResolverDependencyUnknownKeepsReadyToCommit(t *testing.T) {
	now := time.Date(2026, 8, 6, 11, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	envelope := ReconcileRequest{IdempotencyKey: "commit-resolver-unknown", Check: request}
	applied, err := reconciler.Apply(context.Background(), envelope)
	if err != nil || applied.Status != TaskReadyToCommit {
		t.Fatalf("Apply() = (%#v, %v), want ready to commit", applied, err)
	}

	authority := testEndpoint(t, "192.0.2.81", 53)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	resolver := checker.resolver.(*fakeResolver)
	resolver.set(authority, query, func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
		return DNSResponse{Authoritative: true, RCode: 2}, nil
	})

	committed, commitErr := reconciler.Commit(context.Background(), CommitRequest{
		TenantID: applied.TenantID, SiteID: applied.SiteID,
		IdempotencyKey: envelope.IdempotencyKey, PayloadDigest: applied.PayloadDigest,
	})
	if !errors.Is(commitErr, ErrCommitNotReady) || committed.Status != TaskReadyToCommit ||
		committed.ErrorClass != ProviderErrorTransient || committed.ErrorCode != "dependency_unavailable" ||
		committed.CompensationPlan != nil {
		t.Fatalf("Commit() = (%#v, %v), want recoverable dependency unavailable", committed, commitErr)
	}
}

func TestCheckHasDependencyUnavailableTreatsUnknownObservationAsUnavailable(t *testing.T) {
	for _, status := range []Classification{"future_status", ""} {
		t.Run(fmt.Sprintf("status-%q", status), func(t *testing.T) {
			check := CheckResult{Observations: []Observation{{Role: ResolverPublic, Status: status}}}
			if !checkHasDependencyUnavailable(check) {
				t.Fatalf("checkHasDependencyUnavailable(%q) = false, want true", status)
			}
		})
	}
}

func TestReconcilerMixedQuorumUnknownDoesNotCarryHealthyConsecutiveAcrossResume(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	authority := []NamedResolver{
		{Name: "ns1.example.test", Endpoint: testEndpoint(t, "192.0.2.211", 53)},
		{Name: "ns2.example.test", Endpoint: testEndpoint(t, "192.0.2.212", 53)},
		{Name: "ns3.example.test", Endpoint: testEndpoint(t, "192.0.2.213", 53)},
	}
	public := []NamedResolver{
		{Name: "recursive-a", Endpoint: testEndpoint(t, "198.51.100.211", 53)},
		{Name: "recursive-b", Endpoint: testEndpoint(t, "198.51.100.212", 53)},
	}
	resolver := newFakeResolver()
	unknownCalls := 0
	unknownHandler := func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
		unknownCalls++
		if unknownCalls == 1 || unknownCalls == 3 {
			return DNSResponse{Authoritative: true, RCode: 2}, nil
		}
		return answerResponse(true, query.Name, RecordA, "192.0.2.10"), nil
	}
	resolver.set(authority[0].Endpoint, query, responseHandler(answerResponse(true, query.Name, RecordA, "192.0.2.10")))
	resolver.set(authority[1].Endpoint, query, responseHandler(answerResponse(true, query.Name, RecordA, "192.0.2.10")))
	resolver.set(authority[2].Endpoint, query, unknownHandler)
	for _, item := range public {
		resolver.set(item.Endpoint, query, responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10")))
	}
	checker := testChecker(t, resolver, authority, public, now, 1, 4)
	request := baseRequest(now, RecordA, "192.0.2.10")
	request.Provider.Records[0].Value = "192.0.2.20"
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	reconciler := newTestReconciler(t, checker, provider, now, func(config *ReconcilerConfig) {
		config.PollAttempts = 2
		config.RequiredConsecutive = 2
	})
	envelope := ReconcileRequest{IdempotencyKey: "mixed-quorum-resume", Check: request}
	prepared, err := reconciler.PrepareApply(envelope)
	if err != nil {
		t.Fatal(err)
	}
	first, err := reconciler.Apply(context.Background(), envelope)
	if err != nil || first.Status != TaskPropagating || first.ErrorCode != "dependency_unavailable" ||
		len(first.Propagation) != 1 || !first.Propagation[0].DependencyUnavailable || first.Propagation[0].ConsecutiveHealthy != 0 {
		t.Fatalf("mixed quorum first Apply() = (%#v, %v), want dependency with zero consecutive", first, err)
	}
	resumed, err := reconciler.ResumeApply(context.Background(), prepared, first, nil)
	if err != nil || resumed.Status != TaskPropagating || resumed.ErrorCode != "dependency_unavailable" ||
		len(resumed.Propagation) != 3 || resumed.Propagation[1].ConsecutiveHealthy != 1 ||
		resumed.Propagation[2].ConsecutiveHealthy != 0 {
		t.Fatalf("mixed quorum ResumeApply() = (%#v, %v), want healthy then unknown without commit", resumed, err)
	}

	unknownCalls = 0
	legacy := first
	legacy.Propagation[0].DependencyUnavailable = false
	legacy.Propagation[0].ConsecutiveHealthy = 9
	legacyResumed, err := reconciler.ResumeApply(context.Background(), prepared, legacy, nil)
	if err != nil || legacyResumed.Status != TaskPropagating || legacyResumed.ErrorCode != "dependency_unavailable" ||
		legacyResumed.Propagation[len(legacyResumed.Propagation)-1].ConsecutiveHealthy != 0 {
		t.Fatalf("legacy dependency ResumeApply() = (%#v, %v), want reset consecutive", legacyResumed, err)
	}
}
