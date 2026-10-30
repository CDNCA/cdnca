package signerrevocationconsumer

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/signercheckpoint"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocation"
	"github.com/google/uuid"
)

type Store interface {
	RestoreV2(context.Context) (signerrevocation.CheckpointLKG, error)
	AcceptV2(context.Context, uuid.UUID, []byte, string, time.Time) (signerrevocation.CheckpointLKG, error)
	RecordCheckpointOutage(context.Context, uuid.UUID, string, time.Time) error
}

type Fetcher interface {
	Fetch(context.Context, KnownCheckpoint) (FetchResult, error)
}

type Runtime interface {
	Replace(signerrevocation.Snapshot) error
}

type Coordinator struct {
	store   Store
	fetcher Fetcher
	runtime Runtime
	gate    chan struct{}
}

type retryableRefreshError struct{ err error }

func (failure *retryableRefreshError) Error() string { return failure.err.Error() }
func (failure *retryableRefreshError) Unwrap() error { return failure.err }

func NewCoordinator(store Store, fetcher Fetcher, runtime Runtime) (*Coordinator, error) {
	if store == nil || fetcher == nil || runtime == nil {
		return nil, ErrInvalidConfiguration
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &Coordinator{store: store, fetcher: fetcher, runtime: runtime, gate: gate}, nil
}

func (coordinator *Coordinator) Startup(ctx context.Context) error {
	if err := coordinator.acquire(ctx); err != nil {
		return err
	}
	defer coordinator.release()
	lkg, err := coordinator.store.RestoreV2(ctx)
	if errors.Is(err, signerrevocation.ErrNoSnapshot) {
		// No checkpoint has ever been accepted: leave the runtime empty so the
		// revocation gate allows, and bootstrap from revision 0 on refresh.
		return nil
	}
	if err != nil {
		return err
	}
	return coordinator.runtime.Replace(lkg.Runtime)
}

func (coordinator *Coordinator) Refresh(ctx context.Context) error {
	if err := coordinator.acquire(ctx); err != nil {
		return err
	}
	defer coordinator.release()

	// Reconcile durable state first so a prior post-commit crash or Replace
	// failure is repaired even when the remote returns 304.
	lkg, err := coordinator.store.RestoreV2(ctx)
	switch {
	case errors.Is(err, signerrevocation.ErrNoSnapshot):
		lkg = signerrevocation.CheckpointLKG{}
	case err != nil:
		return err
	default:
		if err := coordinator.runtime.Replace(lkg.Runtime); err != nil {
			return &retryableRefreshError{err: err}
		}
	}
	result, err := coordinator.fetcher.Fetch(ctx, KnownCheckpoint{
		Revision: lkg.Checkpoint.Revision, SHA256: lkg.Checkpoint.CheckpointSHA256, ETag: lkg.ETag,
	})
	if err != nil {
		var failure *FetchError
		if !errors.As(err, &failure) || failure.OperationID == uuid.Nil || failure.ObservedAt.IsZero() ||
			failure.Reason == "" {
			return err
		}
		if auditErr := coordinator.store.RecordCheckpointOutage(ctx, failure.OperationID,
			failure.Reason, failure.ObservedAt); auditErr != nil {
			return errors.Join(err, auditErr)
		}
		return &retryableRefreshError{err: err}
	}
	if result.NotModified {
		return coordinator.store.RecordCheckpointOutage(ctx, result.OperationID, ReasonNotModified, result.ObservedAt)
	}
	accepted, err := coordinator.store.AcceptV2(ctx, result.OperationID, result.Body, result.ETag, result.ObservedAt)
	if err != nil {
		if !checkpointRejected(err) {
			return err
		}
		// A checkpoint the local trust rejects never replaces the LKG and must
		// not stop the control plane; audit it and retry on the next round.
		if auditErr := coordinator.store.RecordCheckpointOutage(ctx, result.OperationID,
			ReasonInvalidResponse, result.ObservedAt); auditErr != nil {
			return errors.Join(err, auditErr)
		}
		return &retryableRefreshError{err: err}
	}
	if err := coordinator.runtime.Replace(accepted.Runtime); err != nil {
		return &retryableRefreshError{err: err}
	}
	return nil
}

// checkpointRejected reports content-verification failures of a fetched
// candidate. Stored-state, audit and database failures stay terminal.
func checkpointRejected(err error) bool {
	for _, rejection := range []error{
		signercheckpoint.ErrInvalidCheckpoint, signercheckpoint.ErrInvalidEnvelope,
		signercheckpoint.ErrInvalidSignature, signercheckpoint.ErrWrongAuthority,
		signercheckpoint.ErrAuthorityUntrusted, signercheckpoint.ErrAuthorityRevoked,
		signercheckpoint.ErrAuthorityGeneration, signercheckpoint.ErrCheckpointNotCurrent,
		signercheckpoint.ErrManifestNotCurrent, signercheckpoint.ErrChainInvalid,
		signercheckpoint.ErrDigestMismatch, signercheckpoint.ErrRevisionRollback,
		signercheckpoint.ErrRevisionConflict, signercheckpoint.ErrRevisionGap,
		signercheckpoint.ErrLineage, signercheckpoint.ErrPrefixFork,
		signercheckpoint.ErrInvalidKeyset, signercheckpoint.ErrKeysetRollback,
		signercheckpoint.ErrTTLExceeded, signerrevocation.ErrObservedAtOutOfRange,
	} {
		if errors.Is(err, rejection) {
			return true
		}
	}
	return false
}

func (coordinator *Coordinator) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return ErrInvalidConfiguration
	}
	if err := coordinator.Startup(ctx); err != nil {
		return err
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if err := coordinator.Refresh(ctx); err != nil {
				var failure *retryableRefreshError
				if !errors.As(err, &failure) {
					return err
				}
			}
			timer.Reset(interval)
		}
	}
}

func (coordinator *Coordinator) acquire(ctx context.Context) error {
	if coordinator == nil || coordinator.gate == nil {
		return ErrInvalidConfiguration
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-coordinator.gate:
		return nil
	}
}

func (coordinator *Coordinator) release() {
	coordinator.gate <- struct{}{}
}

var _ Store = (*signerrevocation.CheckpointStore)(nil)
var _ Fetcher = (*Client)(nil)
var _ Runtime = (*signerrevocation.Runtime)(nil)
