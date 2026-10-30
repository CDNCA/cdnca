package dnsproviderremote

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

type postMutationRetryAfterAuthority struct {
	*fakeReconcileAuthority
	recoveryNotBefore time.Time
	persistenceFailed bool
	recoveryReady     bool
	leaseExpiresAt    time.Time
	leaseTransitioned bool
}

func (authority *postMutationRetryAfterAuthority) AcquireMutationClaim(ctx context.Context,
	mutation dnscheck.ProviderMutation) (MutationClaim, error) {
	providerRequestID := deterministicProviderRequestID(mutation.ClientRequestID)
	if authority.persistenceFailed && authority.fakeReconcileAuthority.claimState == MutationClaimed &&
		!authority.leaseExpiresAt.IsZero() && authority.leaseExpiresAt.After(time.Now()) {
		return MutationClaim{}, providerRecoveryPending(providerRequestID)
	}
	if authority.persistenceFailed && authority.fakeReconcileAuthority.claimState == MutationClaimed &&
		!authority.leaseExpiresAt.IsZero() && !authority.leaseExpiresAt.After(time.Now()) && !authority.leaseTransitioned {
		authority.fakeReconcileAuthority.claimState = MutationUncertain
		authority.fakeReconcileAuthority.claimStateExplicit = true
		authority.leaseTransitioned = true
	}
	claim, err := authority.fakeReconcileAuthority.AcquireMutationClaim(ctx, mutation)
	claim.RecoveryNotBefore = authority.recoveryNotBefore
	claim.RecoveryReady = authority.recoveryReady
	claim.LeaseExpiresAt = authority.leaseExpiresAt
	return claim, err
}

func (authority *postMutationRetryAfterAuthority) MarkMutationUncertain(ctx context.Context,
	mutation dnscheck.ProviderMutation, claim MutationClaim, providerRequestID string) error {
	authority.fakeReconcileAuthority.uncertain++
	authority.fakeReconcileAuthority.uncertainCtx = ctx.Err()
	if authority.fakeReconcileAuthority.uncertainErr != nil {
		authority.persistenceFailed = true
		authority.fakeReconcileAuthority.claimState = MutationClaimed
		authority.fakeReconcileAuthority.claimStateExplicit = true
		authority.leaseExpiresAt = time.Now().Add(time.Minute)
		authority.recoveryNotBefore = time.Now().Add(time.Minute)
		authority.recoveryReady = false
		return authority.fakeReconcileAuthority.uncertainErr
	}
	authority.fakeReconcileAuthority.claimState = MutationUncertain
	authority.fakeReconcileAuthority.claimStateExplicit = true
	authority.recoveryNotBefore = time.Now().Add(time.Minute)
	return nil
}

func (authority *postMutationRetryAfterAuthority) FinalizeMutationClaim(ctx context.Context,
	mutation dnscheck.ProviderMutation, claim MutationClaim, outcome MutationClaimState,
	providerRequestID, providerRecordID string) (int64, error) {
	if outcome == MutationNotApplied {
		authority.fakeReconcileAuthority.finalized++
		return mutation.ExpectedRevision + 1, nil
	}
	return authority.fakeReconcileAuthority.FinalizeMutationClaim(
		ctx, mutation, claim, outcome, providerRequestID, providerRecordID,
	)
}

type postMutationRetryAfterRemote struct {
	lookups     []ReconcileLookup
	postErr     error
	calls       int
	postErrUsed bool
	mutates     int
}

func (remote *postMutationRetryAfterRemote) Lookup(context.Context, ProviderConfig,
	dnscheck.ProviderOperation) (ReconcileLookup, error) {
	remote.calls++
	if len(remote.lookups) > 0 {
		lookup := remote.lookups[0]
		remote.lookups = remote.lookups[1:]
		return lookup, nil
	}
	if !remote.postErrUsed {
		remote.postErrUsed = true
		return ReconcileLookup{}, remote.postErr
	}
	return ReconcileLookup{}, nil
}

func (remote *postMutationRetryAfterRemote) Mutate(context.Context, ProviderConfig,
	dnscheck.ProviderOperation) (string, error) {
	remote.mutates++
	return "record-1", nil
}

func assertPostMutationRecoveryError(t *testing.T, err error, code string, retryAfter time.Duration,
	providerRequestID string) {
	t.Helper()
	var providerErr *dnscheck.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Class != dnscheck.ProviderErrorTransient ||
		providerErr.Code != code || providerErr.RetryAfter != retryAfter ||
		providerErr.ProviderRequestID != providerRequestID {
		t.Fatalf("error=%v, want transient %s retry-after=%s request=%s", err, code, retryAfter, providerRequestID)
	}
}

func TestReconcileAdapterPostMutationRateLimitRetryAfterPreservesUnknownAndNoReplay(t *testing.T) {
	authority := &postMutationRetryAfterAuthority{
		fakeReconcileAuthority: &fakeReconcileAuthority{revision: 7, providerType: providerCloudflare},
	}
	remote := &postMutationRetryAfterRemote{
		lookups: []ReconcileLookup{{}, {}},
		postErr: &Error{Code: CodeRateLimited, RetryAfter: 37 * time.Second, Temporary: true},
	}
	adapter, err := NewReconcileAdapter(authority, remote)
	if err != nil {
		t.Fatal(err)
	}
	mutation := testAdapterMutation("post-mutation-rate-limit")
	providerRequestID := "dns-reconcile-475b822119de42c2e1bd1e546b4da6f2"
	_, err = adapter.Mutate(t.Context(), mutation)
	assertPostMutationRecoveryError(t, err, "provider_recovery_pending", 37*time.Second, providerRequestID)
	if authority.claimState != MutationUncertain || authority.uncertain != 1 || remote.mutates != 1 {
		t.Fatalf("state=%s uncertain=%d mutations=%d", authority.claimState, authority.uncertain, remote.mutates)
	}

	_, err = adapter.Mutate(t.Context(), mutation)
	if err == nil || remote.mutates != 1 || authority.uncertain != 1 || remote.calls != 3 {
		t.Fatalf("replay error=%v uncertain=%d mutations=%d lookups=%d", err, authority.uncertain, remote.mutates, remote.calls)
	}
}

func TestReconcileAdapterPostMutationRateLimitPersistenceFailurePreservesRetryAfter(t *testing.T) {
	authority := &postMutationRetryAfterAuthority{
		fakeReconcileAuthority: &fakeReconcileAuthority{
			revision: 7, providerType: providerCloudflare, uncertainErr: errors.New("persist uncertain failed"),
		},
	}
	remote := &postMutationRetryAfterRemote{
		lookups: []ReconcileLookup{{}, {}},
		postErr: &Error{Code: CodeRateLimited, RetryAfter: 37 * time.Second, Temporary: true},
	}
	adapter, err := NewReconcileAdapter(authority, remote)
	if err != nil {
		t.Fatal(err)
	}
	mutation := testAdapterMutation("post-mutation-rate-limit-persistence")
	providerRequestID := "dns-reconcile-7d063dee0966f2d50c55bb5e44b5ecec"
	_, err = adapter.Mutate(t.Context(), mutation)
	assertPostMutationRecoveryError(t, err, "provider_recovery_persistence_failed", 37*time.Second, providerRequestID)
	if authority.claimState != MutationClaimed || authority.uncertain != 1 || remote.mutates != 1 || remote.calls != 3 ||
		authority.leaseExpiresAt.IsZero() || !authority.leaseExpiresAt.After(time.Now()) ||
		authority.recoveryNotBefore.IsZero() || !authority.recoveryNotBefore.After(time.Now()) || authority.recoveryReady || authority.leaseTransitioned {
		t.Fatalf("claimed fence state=%s uncertain=%d mutations=%d lookups=%d lease=%v recovery-not-before=%v ready=%v transitioned=%v",
			authority.claimState, authority.uncertain, remote.mutates, remote.calls, authority.leaseExpiresAt,
			authority.recoveryNotBefore, authority.recoveryReady, authority.leaseTransitioned)
	}
	_, err = adapter.Mutate(t.Context(), mutation)
	assertPostMutationRecoveryError(t, err, "provider_recovery_pending", time.Second,
		providerRequestID)
	if authority.claimState != MutationClaimed || authority.leaseTransitioned || remote.mutates != 1 || remote.calls != 3 {
		t.Fatalf("live lease error=%v state=%s transitioned=%v mutations=%d lookups=%d", err, authority.claimState,
			authority.leaseTransitioned, remote.mutates, remote.calls)
	}
	authority.leaseExpiresAt = time.Now().Add(-time.Second)
	_, err = adapter.Mutate(t.Context(), mutation)
	assertPostMutationRecoveryError(t, err, "provider_recovery_pending", time.Second, providerRequestID)
	if !authority.leaseTransitioned || authority.claimState != MutationUncertain || authority.recoveryReady || authority.uncertain != 1 || remote.mutates != 1 || remote.calls != 3 ||
		authority.recoveryNotBefore.IsZero() || !authority.recoveryNotBefore.After(time.Now()) {
		t.Fatalf("expired lease gate error=%v transitioned=%v state=%s ready=%v uncertain=%d mutations=%d lookups=%d recovery-not-before=%v",
			err, authority.leaseTransitioned, authority.claimState, authority.recoveryReady, authority.uncertain, remote.mutates,
			remote.calls, authority.recoveryNotBefore)
	}
	authority.recoveryReady = true
	authority.recoveryNotBefore = time.Now().Add(-time.Second)
	_, err = adapter.Mutate(t.Context(), mutation)
	assertPostMutationRecoveryError(t, err, "provider_recovery_pending", time.Second, providerRequestID)
	if !authority.leaseTransitioned || authority.claimState != MutationUncertain || !authority.recoveryReady || authority.uncertain != 1 || remote.mutates != 1 || remote.calls != 5 {
		t.Fatalf("durable recovery error=%v transitioned=%v state=%s ready=%v uncertain=%d mutations=%d lookups=%d",
			err, authority.leaseTransitioned, authority.claimState, authority.recoveryReady, authority.uncertain, remote.mutates, remote.calls)
	}
}

func TestReconcileAdapterPostMutationTransientWithoutRetryAfterUsesDefault(t *testing.T) {
	for _, test := range []struct {
		name       string
		retryAfter time.Duration
		want       time.Duration
	}{
		{name: "zero", retryAfter: 0, want: time.Second},
		{name: "negative", retryAfter: -time.Second, want: time.Second},
		{name: "bounded", retryAfter: 2 * time.Hour, want: maxRetryAfter},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &postMutationRetryAfterAuthority{
				fakeReconcileAuthority: &fakeReconcileAuthority{revision: 7, providerType: providerCloudflare},
			}
			remote := &postMutationRetryAfterRemote{
				lookups: []ReconcileLookup{{}, {}},
				postErr: &Error{Code: CodeUnavailable, RetryAfter: test.retryAfter, Temporary: true},
			}
			adapter, err := NewReconcileAdapter(authority, remote)
			if err != nil {
				t.Fatal(err)
			}
			mutation := testAdapterMutation("post-mutation-default-retry-" + test.name)
			_, err = adapter.Mutate(t.Context(), mutation)
			assertPostMutationRecoveryError(t, err, "provider_recovery_pending", test.want,
				deterministicProviderRequestID(mutation.ClientRequestID))
			if authority.claimState != MutationUncertain || remote.mutates != 1 {
				t.Fatalf("state=%s mutations=%d", authority.claimState, remote.mutates)
			}
		})
	}
}
