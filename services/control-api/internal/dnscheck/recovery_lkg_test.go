package dnscheck

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReconcilerProviderRecoveryPendingKeepsLKGAndResumesByClientRequestID(t *testing.T) {
	now := time.Date(2026, 8, 5, 15, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	provider.mutate = func(provider *fakeProviderAdapter, call int, mutation ProviderMutation) (ProviderMutationResult, error) {
		if call == 1 {
			return ProviderMutationResult{}, &ProviderError{
				Class: ProviderErrorTransient, Code: "provider_recovery_pending",
				ProviderRequestID: "recovery-request-1", RetryAfter: time.Minute,
			}
		}
		return provider.succeed(call, mutation)
	}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	requestEnvelope := ReconcileRequest{IdempotencyKey: "recovery-lkg", Check: request}
	prepared, err := reconciler.PrepareApply(requestEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	first, err := reconciler.Apply(context.Background(), requestEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != TaskPropagating || first.ErrorCode != "provider_recovery_pending" || len(first.CompensationPlan) != 0 {
		t.Fatalf("unknown provider outcome = %#v, want propagating LKG", first)
	}
	resumed, err := reconciler.ResumeApply(context.Background(), prepared, first, nil)
	if err != nil || resumed.Status != TaskReadyToCommit || resumed.Operations[0].Status != OperationSucceeded {
		t.Fatalf("recovered ResumeApply() = (%#v, %v)", resumed, err)
	}
	_, _, mutations := provider.snapshot()
	if len(mutations) != 2 || mutations[0].ClientRequestID != mutations[1].ClientRequestID {
		t.Fatalf("recovery mutations = %#v, want deterministic replay id", mutations)
	}
}

func TestReconcilerCommitRecoveryPendingKeepsNonterminalAndResumes(t *testing.T) {
	for _, code := range []string{"provider_recovery_pending", "provider_recovery_persistence_failed"} {
		t.Run(code, func(t *testing.T) {
			now := time.Date(2026, 8, 5, 16, 0, 0, 0, time.UTC)
			checker, request := newHealthyReconcileFixture(t, now)
			request.Provider.Records = []ProviderRecord{
				{RecordID: "record-stable", Name: request.Name, Type: RecordA, Value: "192.0.2.10", TTL: request.TTL},
				{RecordID: "record-old-1", Name: request.Name, Type: RecordA, Value: "192.0.2.11", TTL: request.TTL},
				{RecordID: "record-old-2", Name: request.Name, Type: RecordA, Value: "192.0.2.12", TTL: request.TTL},
				{RecordID: "record-old-3", Name: request.Name, Type: RecordA, Value: "192.0.2.13", TTL: request.TTL},
			}
			provider := &fakeProviderAdapter{revision: request.Provider.Revision}
			provider.mutate = func(provider *fakeProviderAdapter, call int, mutation ProviderMutation) (ProviderMutationResult, error) {
				if call == 2 {
					return ProviderMutationResult{}, &ProviderError{
						Class: ProviderErrorTransient, Code: code,
						ProviderRequestID: "provider-unknown-delete", RetryAfter: time.Minute,
					}
				}
				return provider.succeed(call, mutation)
			}
			reconciler := newTestReconciler(t, checker, provider, now, nil)
			prepared, err := reconciler.PrepareApply(ReconcileRequest{
				IdempotencyKey: "commit-recovery-" + code, Check: request,
			})
			if err != nil {
				t.Fatal(err)
			}
			applied, err := reconciler.ResumeApply(t.Context(), prepared, prepared.Result, nil)
			if err != nil || applied.Status != TaskReadyToCommit || len(applied.Operations) != 0 ||
				len(applied.DeferredDeletes) != 3 {
				t.Fatalf("ResumeApply() = (%#v,%v), want three deferred deletes", applied, err)
			}
			untouchedThird := applied.DeferredDeletes[2]

			first, err := reconciler.ResumeCommit(t.Context(), prepared, applied, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, _, mutations := provider.snapshot()
			if first.Status != TaskReadyToCommit || first.ErrorClass != ProviderErrorTransient ||
				first.ErrorCode != code || len(first.CompensationPlan) != 0 || len(mutations) != 2 {
				t.Fatalf("first ResumeCommit() = %#v; mutations=%#v", first, mutations)
			}
			if first.DeferredDeletes[0].Status != OperationSucceeded ||
				first.DeferredDeletes[1].Status != OperationRunning ||
				first.DeferredDeletes[1].ErrorClass != ProviderErrorTransient ||
				first.DeferredDeletes[1].ErrorCode != code || first.DeferredDeletes[2] != untouchedThird {
				t.Fatalf("first deferred deletes = %#v, want succeeded/running/untouched", first.DeferredDeletes)
			}
			unknownRequestID := first.DeferredDeletes[1].ClientRequestID
			if unknownRequestID == "" || mutations[1].ClientRequestID != unknownRequestID {
				t.Fatalf("unknown request identity = %q; mutations=%#v", unknownRequestID, mutations)
			}

			resumed, err := reconciler.ResumeCommit(t.Context(), prepared, first, nil)
			if err != nil || resumed.Status != TaskCommitted || resumed.ErrorClass != ProviderErrorNone ||
				resumed.ErrorCode != "" || len(resumed.CompensationPlan) != 0 {
				t.Fatalf("resumed ResumeCommit() = (%#v,%v)", resumed, err)
			}
			_, _, mutations = provider.snapshot()
			if len(mutations) != 4 ||
				mutations[0].Operation.RecordID != applied.DeferredDeletes[0].Operation.RecordID ||
				mutations[1].Operation.RecordID != applied.DeferredDeletes[1].Operation.RecordID ||
				mutations[2].Operation.RecordID != applied.DeferredDeletes[1].Operation.RecordID ||
				mutations[3].Operation.RecordID != applied.DeferredDeletes[2].Operation.RecordID ||
				mutations[2].ClientRequestID != unknownRequestID {
				t.Fatalf("resumed mutations = %#v, want first/second/second/third", mutations)
			}
			for index, item := range resumed.DeferredDeletes {
				if item.Status != OperationSucceeded {
					t.Fatalf("resumed delete[%d] = %#v, want succeeded", index, item)
				}
			}
		})
	}
}

func TestReconcilerDependencyUnavailableKeepsPropagatingLKG(t *testing.T) {
	now := time.Date(2026, 8, 5, 15, 0, 0, 0, time.UTC)
	authority := testEndpoint(t, "192.0.2.121", 53)
	public := testEndpoint(t, "198.51.100.121", 53)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	resolver := newFakeResolver()
	resolver.set(authority, query, func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
		return DNSResponse{}, ErrDependencyUnavailable
	})
	resolver.set(public, query, responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10")))
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
	result, err := reconciler.Apply(context.Background(), ReconcileRequest{IdempotencyKey: "dependency-lkg", Check: request})
	if err != nil || result.Status != TaskPropagating || result.ErrorCode != "dependency_unavailable" || len(result.CompensationPlan) != 0 {
		t.Fatalf("dependency unavailable = (%#v, %v), want propagating LKG", result, err)
	}
	if errors.Is(err, ErrCommitNotReady) {
		t.Fatal("dependency failure became a commit error")
	}
}

func TestReconcilerDependencyUnavailableDoesNotConsumePollBudgetAcrossResumes(t *testing.T) {
	now := time.Date(2026, 8, 5, 15, 0, 0, 0, time.UTC)
	authority := testEndpoint(t, "192.0.2.122", 53)
	public := testEndpoint(t, "198.51.100.122", 53)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	resolver := newFakeResolver()
	resolver.set(authority, query, func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
		return DNSResponse{}, ErrDependencyUnavailable
	})
	resolver.set(public, query, responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10")))
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
	envelope := ReconcileRequest{IdempotencyKey: "dependency-budget", Check: request}
	prepared, err := reconciler.PrepareApply(envelope)
	if err != nil {
		t.Fatal(err)
	}
	result, err := reconciler.Apply(context.Background(), envelope)
	if err != nil || result.Status != TaskPropagating {
		t.Fatalf("initial Apply() = (%#v, %v)", result, err)
	}
	for index := range result.Propagation {
		result.Propagation[index].DependencyUnavailable = false
	}
	for attempt := 0; attempt < 3; attempt++ {
		result, err = reconciler.ResumeApply(context.Background(), prepared, result, nil)
		if err != nil || result.Status != TaskPropagating || result.ErrorCode != "dependency_unavailable" {
			t.Fatalf("ResumeApply(%d) = (%#v, %v), want propagating", attempt, result, err)
		}
	}
	for index, attempt := range result.Propagation {
		if !attempt.DependencyUnavailable {
			t.Fatalf("legacy propagation[%d] was not migrated: %#v", index, attempt)
		}
	}
}
