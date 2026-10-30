package dnsproviderremote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

type ReconcileLookup struct {
	TargetComplete bool
	Conflict       bool
	Ambiguous      bool
	RecordID       string
	SnapshotDigest [sha256.Size]byte
}

type RevisionSnapshot struct {
	Revision             int64
	SiteRevision         int64
	ProviderRevision     int64
	Config               ProviderConfig
	OperationDigest      [sha256.Size]byte
	AuthorityDigest      [sha256.Size]byte
	SiteConfigDigest     [sha256.Size]byte
	ProviderConfigDigest [sha256.Size]byte
	CredentialDigest     [sha256.Size]byte
}

type MutationClaimState string

const (
	MutationClaimed                     MutationClaimState = "claimed"
	MutationUncertain                   MutationClaimState = "uncertain"
	MutationSucceeded                   MutationClaimState = "succeeded"
	MutationNotApplied                  MutationClaimState = "not_applied"
	MutationConflict                    MutationClaimState = "conflict"
	MutationVisibilityWindow                               = 2 * time.Minute
	mutationUncertainPersistenceTimeout                    = 5 * time.Second

	// The worst post-fence path is DNS.COM: one bounded full scan before the
	// mutation, the mutation request, then another full scan and exact get.
	MutationClaimLeaseMinimum = time.Duration(2*recoveryMaxPages+4)*requestTimeout + 30*time.Second
)

type MutationClaim struct {
	RevisionSnapshot
	JobID             uuid.UUID
	Phase             string
	OperationOrdinal  int
	ClaimID           uuid.UUID
	State             MutationClaimState
	LeaseExpiresAt    time.Time
	ProviderRequestID string
	ProviderRecordID  string
	FinalRevision     int64
	RecoveryNotBefore time.Time
	RecoveryReady     bool
}

type RevisionAuthority interface {
	CurrentRevision(context.Context, dnscheck.ProviderRevisionRequest) (int64, error)
	AcquireMutationClaim(context.Context, dnscheck.ProviderMutation) (MutationClaim, error)
	ValidateMutationClaim(context.Context, dnscheck.ProviderMutation, MutationClaim) error
	MarkMutationUncertain(context.Context, dnscheck.ProviderMutation, MutationClaim, string) error
	FinalizeMutationClaim(context.Context, dnscheck.ProviderMutation, MutationClaim, MutationClaimState, string, string) (int64, error)
}

type MutationCredentialLease = func(context.Context) error

type MutationCredentialLeaseAuthority interface {
	AcquireMutationCredentialLease(context.Context, dnscheck.ProviderMutation, MutationClaim) (MutationCredentialLease, error)
}

type ReconcileRemote interface {
	Lookup(context.Context, ProviderConfig, dnscheck.ProviderOperation) (ReconcileLookup, error)
	Mutate(context.Context, ProviderConfig, dnscheck.ProviderOperation) (string, error)
}

type ReconcileAdapter struct {
	authority RevisionAuthority
	remote    ReconcileRemote
}

func NewReconcileAdapter(authority RevisionAuthority, remote ReconcileRemote) (*ReconcileAdapter, error) {
	if authority == nil || remote == nil {
		return nil, failure(CodeInvalidInput, false)
	}
	return &ReconcileAdapter{authority: authority, remote: remote}, nil
}

func (adapter *ReconcileAdapter) CurrentRevision(ctx context.Context, request dnscheck.ProviderRevisionRequest) (int64, error) {
	if adapter == nil || adapter.authority == nil || ctx == nil || request.TenantID == [16]byte{} ||
		request.SiteID == [16]byte{} || request.ZoneID == [16]byte{} {
		return 0, failure(CodeInvalidInput, false)
	}
	return adapter.authority.CurrentRevision(ctx, request)
}

func (adapter *ReconcileAdapter) Mutate(ctx context.Context, mutation dnscheck.ProviderMutation) (dnscheck.ProviderMutationResult, error) {
	if adapter == nil || adapter.authority == nil || adapter.remote == nil || !validReconcileMutation(ctx, mutation) {
		return dnscheck.ProviderMutationResult{}, failure(CodeInvalidInput, false)
	}
	claim, err := adapter.authority.AcquireMutationClaim(ctx, mutation)
	if err != nil {
		return dnscheck.ProviderMutationResult{}, err
	}
	defer clearProviderConfig(&claim.Config)
	providerRequestID := deterministicProviderRequestID(mutation.ClientRequestID)
	if claim.ProviderRequestID != providerRequestID {
		return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
	}
	switch claim.State {
	case MutationSucceeded:
		return dnscheck.ProviderMutationResult{
			ProviderRequestID: claim.ProviderRequestID, RecordID: claim.ProviderRecordID, Revision: claim.FinalRevision,
		}, nil
	case MutationConflict:
		return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
	case MutationClaimed, MutationUncertain:
	default:
		return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
	}
	if claim.Revision != mutation.ExpectedRevision && claim.Revision != mutation.ExpectedRevision+1 {
		return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
	}
	if claim.State == MutationUncertain && !claim.RecoveryNotBefore.IsZero() && !claim.RecoveryReady {
		return dnscheck.ProviderMutationResult{}, providerRecoveryPending(providerRequestID)
	}
	lookup, err := adapter.remote.Lookup(ctx, claim.Config, mutation.Operation)
	if err != nil {
		return dnscheck.ProviderMutationResult{}, mapReconcileError(err)
	}
	if lookup.Ambiguous || lookup.Conflict {
		if _, finalizeErr := adapter.authority.FinalizeMutationClaim(
			ctx, mutation, claim, MutationConflict, providerRequestID, "",
		); finalizeErr != nil {
			return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(finalizeErr, providerRequestID)
		}
		return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
	}
	if lookup.TargetComplete {
		if !validReference(lookup.RecordID, 256) {
			return dnscheck.ProviderMutationResult{}, failure(CodeInvalidResponse, false)
		}
		revision, finalizeErr := adapter.authority.FinalizeMutationClaim(
			ctx, mutation, claim, MutationSucceeded, providerRequestID, lookup.RecordID,
		)
		if finalizeErr != nil {
			return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(finalizeErr, providerRequestID)
		}
		return dnscheck.ProviderMutationResult{ProviderRequestID: providerRequestID, RecordID: lookup.RecordID, Revision: revision}, nil
	}
	if claim.State == MutationUncertain {
		repeated, lookupErr := adapter.remote.Lookup(ctx, claim.Config, mutation.Operation)
		if lookupErr != nil {
			return dnscheck.ProviderMutationResult{}, mapReconcileError(lookupErr)
		}
		if repeated.Ambiguous || repeated.Conflict {
			if _, finalizeErr := adapter.authority.FinalizeMutationClaim(
				ctx, mutation, claim, MutationConflict, providerRequestID, "",
			); finalizeErr != nil {
				return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(finalizeErr, providerRequestID)
			}
			return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
		}
		if repeated.TargetComplete {
			if !validReference(repeated.RecordID, 256) {
				return dnscheck.ProviderMutationResult{}, failure(CodeInvalidResponse, false)
			}
			revision, finalizeErr := adapter.authority.FinalizeMutationClaim(
				ctx, mutation, claim, MutationSucceeded, providerRequestID, repeated.RecordID,
			)
			if finalizeErr != nil {
				return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(finalizeErr, providerRequestID)
			}
			return dnscheck.ProviderMutationResult{
				ProviderRequestID: providerRequestID, RecordID: repeated.RecordID, Revision: revision,
			}, nil
		}
		if !sameReconcileLookup(lookup, repeated) {
			if _, finalizeErr := adapter.authority.FinalizeMutationClaim(
				ctx, mutation, claim, MutationConflict, providerRequestID, "",
			); finalizeErr != nil {
				return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(finalizeErr, providerRequestID)
			}
			return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
		}
		if _, finalizeErr := adapter.authority.FinalizeMutationClaim(
			ctx, mutation, claim, MutationNotApplied, providerRequestID, "",
		); finalizeErr != nil {
			return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(finalizeErr, providerRequestID)
		}
		return dnscheck.ProviderMutationResult{}, providerRecoveryPending(providerRequestID)
	}
	if claim.Revision != mutation.ExpectedRevision {
		if _, finalizeErr := adapter.authority.FinalizeMutationClaim(
			ctx, mutation, claim, MutationConflict, providerRequestID, "",
		); finalizeErr != nil {
			return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(finalizeErr, providerRequestID)
		}
		return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
	}
	repeated, err := adapter.remote.Lookup(ctx, claim.Config, mutation.Operation)
	if err != nil {
		return dnscheck.ProviderMutationResult{}, mapReconcileError(err)
	}
	if repeated.TargetComplete || repeated.Ambiguous || repeated.Conflict || !sameReconcileLookup(lookup, repeated) {
		if _, finalizeErr := adapter.authority.FinalizeMutationClaim(
			ctx, mutation, claim, MutationConflict, providerRequestID, "",
		); finalizeErr != nil {
			return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(finalizeErr, providerRequestID)
		}
		return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
	}
	credentialLease, err := adapter.acquireMutationCredentialLease(ctx, mutation, claim)
	if err != nil {
		return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(err, providerRequestID)
	}
	recordID, mutateErr := adapter.remote.Mutate(ctx, claim.Config, mutation.Operation)
	if err := releaseMutationCredentialLease(credentialLease); err != nil {
		if uncertainErr := adapter.markMutationUncertain(mutation, claim, providerRequestID); uncertainErr != nil {
			return dnscheck.ProviderMutationResult{}, providerRecoveryPersistenceFailed(providerRequestID)
		}
		return dnscheck.ProviderMutationResult{}, providerRecoveryPending(providerRequestID)
	}
	if mutateErr != nil {
		if mutationResultUnknown(mutateErr) {
			if uncertainErr := adapter.markMutationUncertain(mutation, claim, providerRequestID); uncertainErr != nil {
				return dnscheck.ProviderMutationResult{}, providerRecoveryPersistenceFailed(providerRequestID)
			}
			return dnscheck.ProviderMutationResult{}, providerRecoveryPending(providerRequestID)
		} else if _, finalizeErr := adapter.authority.FinalizeMutationClaim(
			ctx, mutation, claim, MutationNotApplied, providerRequestID, "",
		); finalizeErr != nil {
			return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(finalizeErr, providerRequestID)
		}
		return dnscheck.ProviderMutationResult{}, mapReconcilePostMutationError(mutateErr, providerRequestID)
	}
	lookup, err = adapter.remote.Lookup(ctx, claim.Config, mutation.Operation)
	if err != nil {
		retryAfter := providerRecoveryRetryAfter(err)
		if uncertainErr := adapter.markMutationUncertain(mutation, claim, providerRequestID); uncertainErr != nil {
			return dnscheck.ProviderMutationResult{}, providerRecoveryPersistenceFailedWithRetryAfter(providerRequestID, retryAfter)
		}
		return dnscheck.ProviderMutationResult{}, providerRecoveryPendingWithRetryAfter(providerRequestID, retryAfter)
	}
	if !lookup.TargetComplete || lookup.Ambiguous || lookup.Conflict ||
		!validReference(lookup.RecordID, 256) || recordID != "" && lookup.RecordID != recordID {
		if uncertainErr := adapter.markMutationUncertain(mutation, claim, providerRequestID); uncertainErr != nil {
			return dnscheck.ProviderMutationResult{}, providerRecoveryPersistenceFailed(providerRequestID)
		}
		return dnscheck.ProviderMutationResult{}, providerRecoveryPending(providerRequestID)
	}
	revision, err := adapter.authority.FinalizeMutationClaim(
		ctx, mutation, claim, MutationSucceeded, providerRequestID, lookup.RecordID,
	)
	if err != nil {
		return dnscheck.ProviderMutationResult{}, providerClaimPersistenceFailure(err, providerRequestID)
	}
	return dnscheck.ProviderMutationResult{ProviderRequestID: providerRequestID, RecordID: lookup.RecordID, Revision: revision}, nil
}

func (adapter *ReconcileAdapter) acquireMutationCredentialLease(ctx context.Context,
	mutation dnscheck.ProviderMutation, claim MutationClaim) (MutationCredentialLease, error) {
	if authority, ok := adapter.authority.(MutationCredentialLeaseAuthority); ok {
		lease, err := authority.AcquireMutationCredentialLease(ctx, mutation, claim)
		if err != nil {
			return nil, err
		}
		if lease == nil {
			return nil, failure(CodeUnavailable, true)
		}
		return lease, nil
	}
	if err := adapter.authority.ValidateMutationClaim(ctx, mutation, claim); err != nil {
		return nil, err
	}
	return func(context.Context) error { return nil }, nil
}

func releaseMutationCredentialLease(lease MutationCredentialLease) error {
	if lease == nil {
		return failure(CodeUnavailable, true)
	}
	ctx, cancel := context.WithTimeout(context.Background(), mutationUncertainPersistenceTimeout)
	defer cancel()
	return lease(ctx)
}

func (adapter *ReconcileAdapter) markMutationUncertain(mutation dnscheck.ProviderMutation,
	claim MutationClaim, providerRequestID string) error {
	persistCtx, cancel := context.WithTimeout(context.Background(), mutationUncertainPersistenceTimeout)
	defer cancel()
	return adapter.authority.MarkMutationUncertain(persistCtx, mutation, claim, providerRequestID)
}

func providerRecoveryPending(providerRequestID string) error {
	return &dnscheck.ProviderError{
		Class: dnscheck.ProviderErrorTransient, Code: "provider_recovery_pending",
		RetryAfter: time.Second, ProviderRequestID: providerRequestID,
	}
}

func providerRecoveryPendingWithRetryAfter(providerRequestID string, retryAfter time.Duration) error {
	return &dnscheck.ProviderError{
		Class: dnscheck.ProviderErrorTransient, Code: "provider_recovery_pending",
		RetryAfter: boundedProviderRecoveryRetryAfter(retryAfter), ProviderRequestID: providerRequestID,
	}
}

func providerRecoveryPersistenceFailed(providerRequestID string) error {
	return &dnscheck.ProviderError{
		Class: dnscheck.ProviderErrorTransient, Code: "provider_recovery_persistence_failed",
		RetryAfter: time.Second, ProviderRequestID: providerRequestID,
	}
}

func providerRecoveryPersistenceFailedWithRetryAfter(providerRequestID string, retryAfter time.Duration) error {
	return &dnscheck.ProviderError{
		Class: dnscheck.ProviderErrorTransient, Code: "provider_recovery_persistence_failed",
		RetryAfter: boundedProviderRecoveryRetryAfter(retryAfter), ProviderRequestID: providerRequestID,
	}
}

func providerRecoveryRetryAfter(err error) time.Duration {
	var remote *Error
	if !errors.As(err, &remote) {
		return time.Second
	}
	return boundedProviderRecoveryRetryAfter(remote.RetryAfter)
}

func boundedProviderRecoveryRetryAfter(retryAfter time.Duration) time.Duration {
	if retryAfter <= 0 {
		return time.Second
	}
	if retryAfter > maxRetryAfter {
		return maxRetryAfter
	}
	return retryAfter
}

func providerClaimPersistenceFailure(err error, providerRequestID string) error {
	if errors.Is(err, dnscheck.ErrProviderRevisionConflict) {
		return err
	}
	return providerRecoveryPersistenceFailed(providerRequestID)
}

func validReconcileMutation(ctx context.Context, mutation dnscheck.ProviderMutation) bool {
	if ctx == nil || ctx.Err() != nil || mutation.TenantID == [16]byte{} || mutation.SiteID == [16]byte{} ||
		mutation.ZoneID == [16]byte{} || mutation.ExpectedRevision < 1 ||
		!validReference(mutation.ClientRequestID, 256) {
		return false
	}
	operation := mutation.Operation
	if operation.Action != dnscheck.ProviderCreate && operation.Action != dnscheck.ProviderUpdate && operation.Action != dnscheck.ProviderDelete {
		return false
	}
	if canonicalDNSName(operation.Name, true) != operation.Name || operation.TTL == 0 || operation.TTL > 7*24*60*60 {
		return false
	}
	if operation.Type != dnscheck.RecordA && operation.Type != dnscheck.RecordAAAA && operation.Type != dnscheck.RecordCNAME {
		return false
	}
	if operation.Action != dnscheck.ProviderCreate && !validReference(operation.RecordID, 256) {
		return false
	}
	return validCanonicalReconcileValue(operation.Type, operation.Value) &&
		(operation.Action != dnscheck.ProviderUpdate ||
			validCanonicalReconcileValue(operation.Type, operation.PreviousValue) && operation.PreviousTTL > 0 && operation.PreviousTTL <= 7*24*60*60)
}

func sameReconcileLookup(left, right ReconcileLookup) bool {
	return left == right
}

func mutationResultUnknown(err error) bool {
	var remote *Error
	return errors.As(err, &remote) &&
		(remote.Code == CodeTimeout || remote.Code == CodeUnavailable || remote.Code == CodeCancelled ||
			remote.Code == CodeInvalidResponse)
}

func deterministicProviderRequestID(clientRequestID string) string {
	digest := sha256.Sum256([]byte("cdnca-dns-reconcile-provider/v1\x00" + clientRequestID))
	return "dns-reconcile-" + hex.EncodeToString(digest[:16])
}

func ProviderMutationRequestID(clientRequestID string) string {
	return deterministicProviderRequestID(clientRequestID)
}

func mapReconcileError(err error) error {
	if errors.Is(err, dnscheck.ErrProviderRevisionConflict) {
		return err
	}
	var remote *Error
	if !errors.As(err, &remote) {
		return &dnscheck.ProviderError{Class: dnscheck.ProviderErrorTransient, Code: "provider_unavailable"}
	}
	class := dnscheck.ProviderErrorPermanent
	if remote.Temporary {
		class = dnscheck.ProviderErrorTransient
	}
	if remote.Code == CodeTimeout {
		class = dnscheck.ProviderErrorTimeout
	}
	if remote.Code == CodeCancelled {
		class = dnscheck.ProviderErrorCancelled
	}
	return &dnscheck.ProviderError{Class: class, Code: string(remote.Code), RetryAfter: remote.RetryAfter}
}

func mapReconcilePostMutationError(err error, providerRequestID string) error {
	mapped := mapReconcileError(err)
	var remote *Error
	if !errors.As(err, &remote) ||
		(remote.Code != CodeCredentialsRejected && remote.Code != CodeRateLimited) {
		return mapped
	}
	var providerErr *dnscheck.ProviderError
	if errors.As(mapped, &providerErr) {
		providerErr.ProviderRequestID = providerRequestID
	}
	return mapped
}

var _ dnscheck.ProviderAdapter = (*ReconcileAdapter)(nil)
