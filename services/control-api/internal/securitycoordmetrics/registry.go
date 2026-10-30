package securitycoordmetrics

import (
	"math"
	"sync/atomic"
)

type Reason uint8

const (
	ReasonNone Reason = iota
	ReasonCapacityRejected
	ReasonScopeRejected
	ReasonDependencyUnavailable
	ReasonInvalidInput
	ReasonConflict
	ReasonFalsePositiveConfirmed
	ReasonPublishTimeout
	ReasonPublishUnknown
	ReasonPubACKMissing
	ReasonPubACKRejected
	ReasonIntegrityRejected
)

type ACKDisposition uint8

const (
	ACKRejected ACKDisposition = iota
	ACKSettled
	ACKReplayed
	ACKRescued
)

type TerminalOutcome uint8

const (
	TerminalNone TerminalOutcome = iota
	TerminalApplied
	TerminalFailed
	TerminalRolledBack
)

type GlobalOutcome uint8

const (
	GlobalNone GlobalOutcome = iota
	GlobalActive
	GlobalPartial
	GlobalFailed
	GlobalRolledBack
)

type CCObserve struct {
	Accepted, Duplicates, Rejected, Queued int
	Reason                                 Reason
}

type CCCoordination struct {
	Claimed, Published, Retryable, ActivationActive, ActivationFailed int
	Reason                                                            Reason
}

type CCRelease struct {
	Replayed bool
	Reason   Reason
}

type FirewallDispatch struct {
	Claimed, Published, Duplicates, Retryable, Exhausted int
	Reason                                               Reason
}

type FirewallACK struct {
	Disposition   ACKDisposition
	Terminal      TerminalOutcome
	Recovery      bool
	GlobalOutcome GlobalOutcome
}

type CCSnapshot struct {
	ObserveRuns, Accepted, Duplicates, Rejected, Queued                       uint64
	CapacityRejected, ScopeRejected, DependencyUnavailable, Invalid, Conflict uint64
	CoordinationRuns, CoordinationClaimed, CoordinationPublished              uint64
	CoordinationRetryable, ActivationActive, ActivationFailed                 uint64
	FalsePositiveReleases, ReleaseReplays, ReleaseRejected                    uint64
}

type FirewallSnapshot struct {
	DispatchRuns, Claimed, Published, PubACKDuplicates, Retryable, Exhausted uint64
	PublishTimeout, PublishUnknown, PubACKMissing, PubACKRejected            uint64
	IntegrityRejected, DependencyUnavailable                                 uint64
	ACKSettled, ACKReplayed, ACKRescued, ACKRejected                         uint64
	Applied, Failed, RolledBack, Recoveries                                  uint64
	GlobalActive, GlobalPartial, GlobalFailed, GlobalRolledBack              uint64
}

type Snapshot struct {
	CC       CCSnapshot
	Firewall FirewallSnapshot
}

type Registry struct {
	ccObserveRuns, ccAccepted, ccDuplicates, ccRejected, ccQueued atomic.Uint64
	ccCapacityRejected, ccScopeRejected, ccDependencyUnavailable  atomic.Uint64
	ccInvalid, ccConflict                                         atomic.Uint64
	ccCoordinationRuns, ccCoordinationClaimed                     atomic.Uint64
	ccCoordinationPublished, ccCoordinationRetryable              atomic.Uint64
	ccActivationActive, ccActivationFailed                        atomic.Uint64
	ccFalsePositiveReleases, ccReleaseReplays, ccReleaseRejected  atomic.Uint64

	fwDispatchRuns, fwClaimed, fwPublished, fwPubACKDuplicates   atomic.Uint64
	fwRetryable, fwExhausted, fwPublishTimeout, fwPublishUnknown atomic.Uint64
	fwPubACKMissing, fwPubACKRejected, fwIntegrityRejected       atomic.Uint64
	fwDependencyUnavailable                                      atomic.Uint64
	fwACKSettled, fwACKReplayed, fwACKRescued, fwACKRejected     atomic.Uint64
	fwApplied, fwFailed, fwRolledBack, fwRecoveries              atomic.Uint64
	fwGlobalActive, fwGlobalPartial, fwGlobalFailed              atomic.Uint64
	fwGlobalRolledBack                                           atomic.Uint64
}

func NewRegistry() *Registry { return &Registry{} }

func (registry *Registry) RecordCCObserve(value CCObserve) {
	if registry == nil {
		return
	}
	add(&registry.ccObserveRuns, 1)
	add(&registry.ccAccepted, positive(value.Accepted))
	add(&registry.ccDuplicates, positive(value.Duplicates))
	add(&registry.ccRejected, positive(value.Rejected))
	add(&registry.ccQueued, positive(value.Queued))
	registry.recordCCReason(value.Reason, maxOne(value.Rejected))
}

func (registry *Registry) RecordCCCoordination(value CCCoordination) {
	if registry == nil {
		return
	}
	add(&registry.ccCoordinationRuns, 1)
	add(&registry.ccCoordinationClaimed, positive(value.Claimed))
	add(&registry.ccCoordinationPublished, positive(value.Published))
	add(&registry.ccCoordinationRetryable, positive(value.Retryable))
	add(&registry.ccActivationActive, positive(value.ActivationActive))
	add(&registry.ccActivationFailed, positive(value.ActivationFailed))
	registry.recordCCReason(value.Reason, 1)
}

func (registry *Registry) RecordCCRelease(value CCRelease) {
	if registry == nil {
		return
	}
	if value.Reason == ReasonFalsePositiveConfirmed {
		add(&registry.ccFalsePositiveReleases, 1)
		if value.Replayed {
			add(&registry.ccReleaseReplays, 1)
		}
		return
	}
	add(&registry.ccReleaseRejected, 1)
	registry.recordCCReason(value.Reason, 1)
}

func (registry *Registry) RecordFirewallDispatch(value FirewallDispatch) {
	if registry == nil {
		return
	}
	add(&registry.fwDispatchRuns, 1)
	add(&registry.fwClaimed, positive(value.Claimed))
	add(&registry.fwPublished, positive(value.Published))
	add(&registry.fwPubACKDuplicates, positive(value.Duplicates))
	add(&registry.fwRetryable, positive(value.Retryable))
	add(&registry.fwExhausted, positive(value.Exhausted))
	registry.RecordFirewallFailure(value.Reason)
}

func (registry *Registry) RecordFirewallFailure(reason Reason) {
	if registry == nil {
		return
	}
	switch reason {
	case ReasonNone:
	case ReasonPublishTimeout:
		add(&registry.fwPublishTimeout, 1)
	case ReasonPublishUnknown:
		add(&registry.fwPublishUnknown, 1)
	case ReasonPubACKMissing:
		add(&registry.fwPubACKMissing, 1)
	case ReasonPubACKRejected:
		add(&registry.fwPubACKRejected, 1)
	case ReasonIntegrityRejected, ReasonInvalidInput, ReasonConflict:
		add(&registry.fwIntegrityRejected, 1)
	default:
		add(&registry.fwDependencyUnavailable, 1)
	}
}

func (registry *Registry) RecordFirewallACK(value FirewallACK) {
	if registry == nil {
		return
	}
	switch value.Disposition {
	case ACKSettled:
		add(&registry.fwACKSettled, 1)
	case ACKReplayed:
		add(&registry.fwACKReplayed, 1)
	case ACKRescued:
		add(&registry.fwACKRescued, 1)
	default:
		add(&registry.fwACKRejected, 1)
	}
	switch value.Terminal {
	case TerminalApplied:
		add(&registry.fwApplied, 1)
	case TerminalFailed:
		add(&registry.fwFailed, 1)
	case TerminalRolledBack:
		add(&registry.fwRolledBack, 1)
	}
	if value.Recovery {
		add(&registry.fwRecoveries, 1)
	}
	switch value.GlobalOutcome {
	case GlobalActive:
		add(&registry.fwGlobalActive, 1)
	case GlobalPartial:
		add(&registry.fwGlobalPartial, 1)
	case GlobalFailed:
		add(&registry.fwGlobalFailed, 1)
	case GlobalRolledBack:
		add(&registry.fwGlobalRolledBack, 1)
	}
}

func (registry *Registry) Snapshot() Snapshot {
	if registry == nil {
		return Snapshot{}
	}
	return Snapshot{
		CC: CCSnapshot{
			ObserveRuns: registry.ccObserveRuns.Load(), Accepted: registry.ccAccepted.Load(),
			Duplicates: registry.ccDuplicates.Load(), Rejected: registry.ccRejected.Load(), Queued: registry.ccQueued.Load(),
			CapacityRejected: registry.ccCapacityRejected.Load(), ScopeRejected: registry.ccScopeRejected.Load(),
			DependencyUnavailable: registry.ccDependencyUnavailable.Load(), Invalid: registry.ccInvalid.Load(), Conflict: registry.ccConflict.Load(),
			CoordinationRuns: registry.ccCoordinationRuns.Load(), CoordinationClaimed: registry.ccCoordinationClaimed.Load(),
			CoordinationPublished: registry.ccCoordinationPublished.Load(), CoordinationRetryable: registry.ccCoordinationRetryable.Load(),
			ActivationActive: registry.ccActivationActive.Load(), ActivationFailed: registry.ccActivationFailed.Load(),
			FalsePositiveReleases: registry.ccFalsePositiveReleases.Load(), ReleaseReplays: registry.ccReleaseReplays.Load(),
			ReleaseRejected: registry.ccReleaseRejected.Load(),
		},
		Firewall: FirewallSnapshot{
			DispatchRuns: registry.fwDispatchRuns.Load(), Claimed: registry.fwClaimed.Load(), Published: registry.fwPublished.Load(),
			PubACKDuplicates: registry.fwPubACKDuplicates.Load(), Retryable: registry.fwRetryable.Load(), Exhausted: registry.fwExhausted.Load(),
			PublishTimeout: registry.fwPublishTimeout.Load(), PublishUnknown: registry.fwPublishUnknown.Load(),
			PubACKMissing: registry.fwPubACKMissing.Load(), PubACKRejected: registry.fwPubACKRejected.Load(),
			IntegrityRejected: registry.fwIntegrityRejected.Load(), DependencyUnavailable: registry.fwDependencyUnavailable.Load(),
			ACKSettled: registry.fwACKSettled.Load(), ACKReplayed: registry.fwACKReplayed.Load(), ACKRescued: registry.fwACKRescued.Load(), ACKRejected: registry.fwACKRejected.Load(),
			Applied: registry.fwApplied.Load(), Failed: registry.fwFailed.Load(), RolledBack: registry.fwRolledBack.Load(), Recoveries: registry.fwRecoveries.Load(),
			GlobalActive: registry.fwGlobalActive.Load(), GlobalPartial: registry.fwGlobalPartial.Load(), GlobalFailed: registry.fwGlobalFailed.Load(), GlobalRolledBack: registry.fwGlobalRolledBack.Load(),
		},
	}
}

func (registry *Registry) recordCCReason(reason Reason, count uint64) {
	switch reason {
	case ReasonNone, ReasonFalsePositiveConfirmed:
	case ReasonCapacityRejected:
		add(&registry.ccCapacityRejected, count)
	case ReasonScopeRejected:
		add(&registry.ccScopeRejected, count)
	case ReasonInvalidInput:
		add(&registry.ccInvalid, count)
	case ReasonConflict:
		add(&registry.ccConflict, count)
	default:
		add(&registry.ccDependencyUnavailable, count)
	}
}

func positive(value int) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func maxOne(value int) uint64 {
	if value < 1 {
		return 1
	}
	return uint64(value)
}

func add(counter *atomic.Uint64, delta uint64) {
	for delta > 0 {
		current := counter.Load()
		if current == math.MaxUint64 {
			return
		}
		next := current + delta
		if next < current {
			next = math.MaxUint64
		}
		if counter.CompareAndSwap(current, next) {
			return
		}
	}
}
