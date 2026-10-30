package installationban

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/installationlock"
)

// Evaluate derives the installation lock (ADR 0014 §5.2, §5.4): a ban in
// effect (unless a later ticket supersedes it), or a revoked lease, or a lease
// past its grace. A control plane that never installed a lease is not locked
// (first activation), nor is one whose lease is only invalid.
func Evaluate(state State, now time.Time) installationlock.Lock {
	if notice := state.NoticeBody; notice != nil && notice.InEffect(now) &&
		(state.TicketBody == nil || state.TicketBody.Revision < notice.Revision) {
		lock := installationlock.Lock{Locked: true, Reason: installationlock.ReasonBanned, BanID: notice.BanID,
			ReasonCode: notice.ReasonCode, ReasonText: notice.ReasonText}
		if notice.Until != nil {
			until := time.Unix(*notice.Until, 0).UTC()
			lock.Until = &until
		}
		return lock
	}
	if !state.LeasePresent {
		return installationlock.Lock{}
	}
	switch {
	case state.LeaseStatus == "revoked":
		return installationlock.Lock{Locked: true, Reason: installationlock.ReasonLeaseRevoked}
	case state.LeaseStatus == "expired", !state.LeaseGrace.IsZero() && !now.Before(state.LeaseGrace):
		return installationlock.Lock{Locked: true, Reason: installationlock.ReasonLeaseExpired}
	}
	return installationlock.Lock{}
}

// StateStore is what the runtime needs of Store.
type StateStore interface {
	Accept(ctx context.Context, documents Documents, now time.Time) (State, error)
	Current(ctx context.Context, now time.Time) (State, error)
}

// Runtime is one round of the state poll, run from the entitlement revocation
// loop (cmd/control-api entitlement_revocation_runtime.go) every minute.
type Runtime struct {
	Fetcher Fetcher
	Store   StateStore
	Now     func() time.Time
	Logger  *slog.Logger
	// RenewLease renews the lease now: after a ban is lifted the old serial
	// stays revoked and only a renewal unlocks (§4.5). nil = off.
	RenewLease func(context.Context) error
	// Changed is called after a new revision was accepted (node delivery wake).
	Changed func()

	revision uint64
	rebound  bool
}

// CodeMasterIPRebound is the license service refusal for a controller whose
// license was rebound to another server's IP (fix-ipswitch).
const CodeMasterIPRebound = "master_ip_rebound"

func isRebound(err error) bool {
	var httpError *HTTPError
	return errors.As(err, &httpError) && httpError.Code == CodeMasterIPRebound
}

// Restore applies the stored state before the HTTP server starts, so a
// restart while banned stays locked even if the license service is down.
func (runtime *Runtime) Restore(ctx context.Context) error {
	state, err := runtime.Store.Current(ctx, runtime.Now())
	if err != nil {
		return err
	}
	runtime.apply(state)
	return nil
}

// SyncOnce fetches, accepts and applies the state. A remote failure keeps the
// stored state (it is still re-evaluated: a ban's until may have passed).
func (runtime *Runtime) SyncOnce(ctx context.Context) error {
	now := runtime.Now()
	documents, err := runtime.Fetcher.Fetch(ctx, now)
	// Only a definite answer changes the flag; an outage keeps the last one.
	if err == nil || isRebound(err) {
		runtime.rebound = err != nil
	}
	if err == nil {
		// a refused document is reported; the stored state is applied either way
		_, err = runtime.Store.Accept(ctx, documents, now)
	}
	state, currentErr := runtime.Store.Current(ctx, now)
	if currentErr != nil {
		return errors.Join(err, currentErr)
	}
	lock := runtime.apply(state)
	// A lifted ban leaves the old serial revoked; an expired lease (e.g. after
	// the license service was unreachable) unlocks as soon as a renewal lands.
	if lock.Locked && runtime.RenewLease != nil && (lock.Reason == installationlock.ReasonLeaseExpired ||
		lock.Reason == installationlock.ReasonLeaseRevoked && state.NoticeBody != nil && !state.NoticeBody.InEffect(now)) {
		if renewErr := runtime.RenewLease(ctx); renewErr != nil {
			err = errors.Join(err, renewErr)
		} else if renewed, currentErr := runtime.Store.Current(ctx, runtime.Now()); currentErr == nil {
			runtime.apply(renewed)
		}
	}
	return err
}

func (runtime *Runtime) apply(state State) installationlock.Lock {
	lock := Evaluate(state, runtime.Now())
	lock.Rebound = runtime.rebound
	previous := installationlock.Current()
	installationlock.Set(lock)
	if lock.Locked != previous.Locked || lock.Reason != previous.Reason || lock.BanID != previous.BanID ||
		lock.Rebound != previous.Rebound {
		runtime.logger().Warn("installation lock state", "locked", lock.Locked, "reason", lock.Reason, "ban_id", lock.BanID,
			"rebound", lock.Rebound)
	}
	revision := latestRevision(state)
	if revision > runtime.revision {
		runtime.revision = revision
		if runtime.Changed != nil {
			runtime.Changed()
		}
	}
	return lock
}

func (runtime *Runtime) logger() *slog.Logger {
	if runtime.Logger != nil {
		return runtime.Logger
	}
	return slog.Default()
}

func latestRevision(state State) uint64 {
	var revision uint64
	if state.NoticeBody != nil {
		revision = state.NoticeBody.Revision
	}
	if state.TicketBody != nil && state.TicketBody.Revision > revision {
		revision = state.TicketBody.Revision
	}
	return revision
}

// IsRemoteError: the license service or the network may answer next round.
func IsRemoteError(err error) bool {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Retryable()
	}
	var networkErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkErr)
}
