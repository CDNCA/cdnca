package dnsproviderremote

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

type failureReceiptAuthority struct {
	*fakeReconcileAuthority
	outcomes       []MutationClaimState
	requestIDs     []string
	providerRecord []string
	state          MutationClaimState
}

func (authority *failureReceiptAuthority) FinalizeMutationClaim(ctx context.Context,
	mutation dnscheck.ProviderMutation, claim MutationClaim, outcome MutationClaimState,
	providerRequestID, providerRecordID string) (int64, error) {
	authority.outcomes = append(authority.outcomes, outcome)
	authority.requestIDs = append(authority.requestIDs, providerRequestID)
	authority.providerRecord = append(authority.providerRecord, providerRecordID)
	authority.state = outcome
	if outcome == MutationNotApplied {
		authority.finalized++
		if authority.finalizeErr != nil {
			return 0, authority.finalizeErr
		}
		return mutation.ExpectedRevision + 1, nil
	}
	return authority.fakeReconcileAuthority.FinalizeMutationClaim(ctx, mutation, claim, outcome, providerRequestID, providerRecordID)
}

func TestReconcileAdapterKnownPostMutationFailuresFinalizeWithRequestIdentity(t *testing.T) {
	for _, test := range []struct {
		name      string
		remoteErr *Error
		wantClass dnscheck.ProviderErrorClass
		wantRetry time.Duration
		wantCode  ErrorCode
	}{
		{name: "credentials rejected", remoteErr: &Error{Code: CodeCredentialsRejected}, wantClass: dnscheck.ProviderErrorPermanent, wantCode: CodeCredentialsRejected},
		{name: "rate limited", remoteErr: &Error{Code: CodeRateLimited, RetryAfter: 37 * time.Second, Temporary: true}, wantClass: dnscheck.ProviderErrorTransient, wantRetry: 37 * time.Second, wantCode: CodeRateLimited},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &failureReceiptAuthority{fakeReconcileAuthority: &fakeReconcileAuthority{
				revision: 7, providerType: providerCloudflare,
			}}
			remote := &fakeReconcileRemote{
				lookup:    []ReconcileLookup{{}, {}},
				mutateErr: test.remoteErr,
			}
			adapter, err := NewReconcileAdapter(authority, remote)
			if err != nil {
				t.Fatal(err)
			}
			mutation := testAdapterMutation("failure-receipt-" + test.name)
			_, err = adapter.Mutate(context.Background(), mutation)

			var providerErr *dnscheck.ProviderError
			if !errors.As(err, &providerErr) || providerErr.Class != test.wantClass ||
				providerErr.Code != string(test.wantCode) || providerErr.RetryAfter != test.wantRetry ||
				providerErr.ProviderRequestID != ProviderMutationRequestID(mutation.ClientRequestID) {
				t.Fatalf("error=%v providerError=%+v", err, providerErr)
			}
			if remote.mutate != 1 || authority.finalized != 1 || authority.state != MutationNotApplied || len(authority.outcomes) != 1 ||
				authority.outcomes[0] != MutationNotApplied || len(authority.requestIDs) != 1 ||
				authority.requestIDs[0] != ProviderMutationRequestID(mutation.ClientRequestID) ||
				authority.providerRecord[0] != "" {
				t.Fatalf("mutate=%d finalized=%d outcomes=%v requestIDs=%v records=%v",
					remote.mutate, authority.finalized, authority.outcomes, authority.requestIDs, authority.providerRecord)
			}
		})
	}
}

func TestReconcileAdapterPreMutationKnownFailureOmitsRequestIdentity(t *testing.T) {
	authority := &failureReceiptAuthority{fakeReconcileAuthority: &fakeReconcileAuthority{
		revision: 7, providerType: providerCloudflare,
	}}
	remote := &fakeReconcileRemote{
		lookupErr: &Error{Code: CodeCredentialsRejected},
	}
	adapter, err := NewReconcileAdapter(authority, remote)
	if err != nil {
		t.Fatal(err)
	}

	mutation := testAdapterMutation("pre-mutation-failure")
	_, err = adapter.Mutate(context.Background(), mutation)
	var providerErr *dnscheck.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != string(CodeCredentialsRejected) ||
		providerErr.ProviderRequestID != "" {
		t.Fatalf("error=%v providerError=%+v", err, providerErr)
	}
	if remote.mutate != 0 || authority.finalized != 0 || len(authority.outcomes) != 0 {
		t.Fatalf("mutate=%d finalized=%d outcomes=%v", remote.mutate, authority.finalized, authority.outcomes)
	}
}
