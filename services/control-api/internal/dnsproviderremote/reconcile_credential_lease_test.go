package dnsproviderremote

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

type reconcileCredentialLeaseAuthority struct {
	*fakeReconcileAuthority
	acquireErr error
	releaseErr error
	acquired   int
	released   int
	held       bool
}

func (authority *reconcileCredentialLeaseAuthority) AcquireMutationCredentialLease(
	_ context.Context,
	_ dnscheck.ProviderMutation,
	_ MutationClaim,
) (func(context.Context) error, error) {
	authority.acquired++
	if authority.acquireErr != nil {
		return nil, authority.acquireErr
	}
	authority.held = true
	return func(context.Context) error {
		authority.released++
		authority.held = false
		return authority.releaseErr
	}, nil
}

type reconcileCredentialLeaseRemote struct {
	authority      *reconcileCredentialLeaseAuthority
	lookups        int
	mutations      int
	mutatedInLease bool
}

func (remote *reconcileCredentialLeaseRemote) Lookup(
	context.Context,
	ProviderConfig,
	dnscheck.ProviderOperation,
) (ReconcileLookup, error) {
	remote.lookups++
	if remote.lookups == 3 {
		return ReconcileLookup{TargetComplete: true, RecordID: "record-lease"}, nil
	}
	return ReconcileLookup{}, nil
}

func (remote *reconcileCredentialLeaseRemote) Mutate(
	context.Context,
	ProviderConfig,
	dnscheck.ProviderOperation,
) (string, error) {
	remote.mutations++
	remote.mutatedInLease = remote.authority.held
	return "record-lease", nil
}

func TestReconcileCredentialLeaseAcquireFailurePreventsMutation(t *testing.T) {
	authority := &reconcileCredentialLeaseAuthority{
		fakeReconcileAuthority: &fakeReconcileAuthority{revision: 7, providerType: providerCloudflare},
		acquireErr:             errors.New("provider disabled"),
	}
	remote := &reconcileCredentialLeaseRemote{authority: authority}
	adapter, err := NewReconcileAdapter(authority, remote)
	if err != nil {
		t.Fatal(err)
	}
	mutation := testAdapterMutation("credential-lease-acquire")
	_, err = adapter.Mutate(t.Context(), mutation)
	var providerErr *dnscheck.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != "provider_recovery_persistence_failed" ||
		providerErr.ProviderRequestID != deterministicProviderRequestID(mutation.ClientRequestID) ||
		authority.acquired != 1 || authority.released != 0 || remote.mutations != 0 {
		t.Fatalf("Mutate() error=%v acquired/released=%d/%d mutations=%d",
			err, authority.acquired, authority.released, remote.mutations)
	}
}

func TestReconcileCredentialLeaseReleaseFailureIsUncertain(t *testing.T) {
	authority := &reconcileCredentialLeaseAuthority{
		fakeReconcileAuthority: &fakeReconcileAuthority{revision: 7, providerType: providerCloudflare},
		releaseErr:             errors.New("credential lease release failed"),
	}
	remote := &reconcileCredentialLeaseRemote{authority: authority}
	adapter, err := NewReconcileAdapter(authority, remote)
	if err != nil {
		t.Fatal(err)
	}
	mutation := testAdapterMutation("credential-lease-release")
	_, err = adapter.Mutate(t.Context(), mutation)
	var providerErr *dnscheck.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != "provider_recovery_pending" ||
		providerErr.ProviderRequestID != deterministicProviderRequestID(mutation.ClientRequestID) ||
		authority.acquired != 1 || authority.released != 1 || authority.held ||
		authority.uncertain != 1 || remote.mutations != 1 || !remote.mutatedInLease {
		t.Fatalf("Mutate() error=%v acquired/released=%d/%d held=%t uncertain=%d mutations=%d in-lease=%t",
			err, authority.acquired, authority.released, authority.held, authority.uncertain,
			remote.mutations, remote.mutatedInLease)
	}
}
