// Package dbpoolmon is the database pool saturation rule shared by
// market-service (internal/poolmon) and control-api
// (internal/poolmon): what one 10-second cycle of a pgx pool
// measures, when a cycle is bad, and when consecutive cycles open and close
// an alert. Persisting, notifying and the operator views stay with each
// service.
//
// After a stall where a transaction taking a second connection
// drained the pool and the service hung with nothing showing it.
package dbpoolmon

import (
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SampleInterval is the sampling period. 10 seconds resolves a stall within
// half a minute (3 cycles) while costing one in-memory pool.Stat() call.
const SampleInterval = 10 * time.Second

// HistoryLen keeps one hour of samples (360 × 10 s, about 70 KB as JSON).
const HistoryLen = int(time.Hour / SampleInterval)

// EnterCycles consecutive bad cycles (30 seconds) raise the alert. A single
// cycle is too noisy: a scheduler burst or a cold pool dialling its first
// connections (AcquireDuration includes dial time) can look bad for 10
// seconds and clear on its own; a real stall lasts minutes.
const EnterCycles = 3

// RecoverCycles consecutive clean cycles end the alert, symmetric with
// EnterCycles so a pool flapping at the edge does not open and resolve every
// few seconds (DedupWindow absorbs the rest).
const RecoverCycles = 3

// SaturationMargin: a cycle is saturated when in use ≥ MaxConns − margin.
// With one connection left the next concurrent request already waits, and
// the connections a service holds for its whole life (leader loops, LISTEN
// sessions) are part of "in use", so the request share is smaller than
// MaxConns suggests.
const SaturationMargin int32 = 1

// SlowAcquire: a cycle is slow when its average acquire wait exceeds 100 ms.
// An acquire served from an idle connection takes microseconds and a new
// connection to a local PostgreSQL a few milliseconds; averaging over 100 ms
// across a cycle means acquires are waiting for others to release.
const SlowAcquire = 100 * time.Millisecond

// DedupWindow: the same alert fired again within 15 minutes of its last
// firing is folded into the previous one, so a flapping pool shows as one
// alert to operators.
const DedupWindow = 15 * time.Minute

// Reasons a cycle counts as bad (Cycle.Reasons).
const (
	ReasonSaturated = "saturated"        // in use ≥ MaxConns − SaturationMargin
	ReasonSlow      = "slow_acquire"     // average acquire wait > SlowAcquire
	ReasonCanceled  = "canceled_acquire" // an acquire gave up while the pool was full or queued
)

// Thresholds is the operator view of the constants above.
type Thresholds struct {
	EnterCycles      int   `json:"enter_cycles"`
	RecoverCycles    int   `json:"recover_cycles"`
	SaturationMargin int32 `json:"saturation_margin"`
	SlowAcquireMS    int64 `json:"slow_acquire_ms"`
	DedupMinutes     int64 `json:"dedup_minutes"`
}

// CurrentThresholds returns the constants above.
func CurrentThresholds() Thresholds {
	return Thresholds{EnterCycles: EnterCycles, RecoverCycles: RecoverCycles, SaturationMargin: SaturationMargin,
		SlowAcquireMS: SlowAcquire.Milliseconds(), DedupMinutes: int64(DedupWindow / time.Minute)}
}

// Stat is the part of pgxpool.Stat the rule reads; the counters are
// cumulative since the pool opened.
type Stat struct {
	MaxConns, TotalConns, AcquiredConns, IdleConns, ConstructingConns int32
	AcquireCount, EmptyAcquireCount, CanceledAcquireCount             int64
	AcquireDuration                                                   time.Duration
}

// FromPool reads pool.Stat() (in memory, no connection taken).
func FromPool(pool *pgxpool.Pool) func() Stat {
	return func() Stat {
		s := pool.Stat()
		return Stat{MaxConns: s.MaxConns(), TotalConns: s.TotalConns(), AcquiredConns: s.AcquiredConns(), IdleConns: s.IdleConns(),
			ConstructingConns: s.ConstructingConns(), AcquireCount: s.AcquireCount(), EmptyAcquireCount: s.EmptyAcquireCount(),
			CanceledAcquireCount: s.CanceledAcquireCount(), AcquireDuration: s.AcquireDuration()}
	}
}

// Cycle is one sampling period: the pool gauges of cur and the counter
// increments since prev.
type Cycle struct {
	MaxConns, TotalConns, InUse, Idle, Constructing int32
	// Acquires succeeded this cycle; Queued of them found no idle connection
	// and waited for a release or a new connection (EmptyAcquireCount);
	// Canceled gave up because their context ended (CanceledAcquireCount).
	Acquires, Queued, Canceled int64
	// AvgWaitMS is ΔAcquireDuration / ΔAcquireCount (0 without acquires).
	AvgWaitMS float64
	// Reasons the cycle is bad (Reason*); empty, never nil, when clean.
	Reasons []string
}

// Measure builds the cycle of cur against the previous sample prev.
func Measure(prev, cur Stat) Cycle {
	delta := func(now, before int64) int64 { return max(now-before, 0) }
	c := Cycle{MaxConns: cur.MaxConns, TotalConns: cur.TotalConns, InUse: cur.AcquiredConns, Idle: cur.IdleConns,
		Constructing: cur.ConstructingConns, Acquires: delta(cur.AcquireCount, prev.AcquireCount),
		Queued: delta(cur.EmptyAcquireCount, prev.EmptyAcquireCount), Canceled: delta(cur.CanceledAcquireCount, prev.CanceledAcquireCount),
		Reasons: []string{}}
	if c.Acquires > 0 {
		wait := max(cur.AcquireDuration-prev.AcquireDuration, 0)
		c.AvgWaitMS = float64(wait.Microseconds()) / 1000 / float64(c.Acquires)
	}
	full := c.InUse >= c.MaxConns-SaturationMargin
	if full {
		c.Reasons = append(c.Reasons, ReasonSaturated)
	}
	if c.AvgWaitMS > float64(SlowAcquire.Milliseconds()) {
		c.Reasons = append(c.Reasons, ReasonSlow)
	}
	// CanceledAcquireCount also counts an Acquire whose context had already
	// ended (the client went away before the query), which says nothing
	// about the pool. A cancel in a cycle where the pool was full or acquires
	// had to wait is a request that gave up waiting for a connection.
	if c.Canceled > 0 && (full || c.Queued > 0) {
		c.Reasons = append(c.Reasons, ReasonCanceled)
	}
	return c
}

// Transition is what one observed cycle changed.
type Transition int

const (
	Steady  Transition = iota // no change
	Enter                     // the alert opens with this cycle
	Recover                   // the alert closes with this cycle
)

// Detector is the alert state of one pool: EnterCycles consecutive bad cycles
// (or one cancelled acquire under pressure) open it, RecoverCycles
// consecutive clean cycles close it. Not safe for concurrent use; the owner
// serialises Observe with its readers.
type Detector struct {
	bad, clean int
	firing     bool
	since      time.Time
	reasons    []string
}

// Observe feeds the reasons of the cycle sampled at at.
func (d *Detector) Observe(at time.Time, reasons []string) Transition {
	if len(reasons) > 0 {
		d.bad, d.clean = d.bad+1, 0
	} else {
		d.bad, d.clean = 0, d.clean+1
	}
	switch {
	case !d.firing && (d.bad >= EnterCycles || slices.Contains(reasons, ReasonCanceled)):
		d.firing, d.since, d.reasons = true, at, slices.Clone(reasons)
		return Enter
	case d.firing && d.clean >= RecoverCycles:
		d.firing, d.reasons = false, nil
		return Recover
	case d.firing:
		for _, r := range reasons {
			if !slices.Contains(d.reasons, r) {
				d.reasons = append(d.reasons, r)
			}
		}
	}
	return Steady
}

// Firing reports whether the alert is open, since when, and every reason
// seen since it opened (a copy, empty when not firing).
func (d *Detector) Firing() (bool, time.Time, []string) {
	if !d.firing {
		return false, time.Time{}, []string{}
	}
	return true, d.since, slices.Clone(d.reasons)
}

// Append adds s to history and drops the oldest past HistoryLen.
func Append[T any](history []T, s T) []T {
	history = append(history, s)
	if over := len(history) - HistoryLen; over > 0 {
		history = slices.Delete(history, 0, over)
	}
	return history
}
