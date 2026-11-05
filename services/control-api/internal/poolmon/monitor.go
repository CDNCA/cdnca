// Package poolmon samples control-api's database pool every 10 seconds,
// keeps the last hour in memory for GET /v1/admin/system-db-pool and
// notifies the platform (notification center, admin inbox) when requests
// queue for connections (a market-service stall once had a transaction
// taking a second connection drain the pool with nothing showing it).
//
// The saturation rule is libs/dbpoolmon, shared with market-service. Each
// control-api process samples its own pool; there is no leader.
package poolmon

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/dbpoolmon"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
)

// writeTimeout bounds one notification write; a failed write stays queued
// and is retried on the next cycle.
const writeTimeout = 5 * time.Second

// maxPending bounds the queued notification writes while the database is
// down (transitions are at most one per 30 seconds, so this is hours).
const maxPending = 64

// Recovery causes (control.db_pool.recovered "cause").
const (
	CauseRecovered         = "recovered"          // RecoverCycles clean cycles
	CauseInstanceRestarted = "instance_restarted" // a new process closed an alert its predecessor left open
)

// Sample is one cycle: the pool gauges at At and the counter increments
// since the previous cycle.
type Sample struct {
	At           time.Time `json:"at"`
	MaxConns     int32     `json:"max_conns"`
	TotalConns   int32     `json:"total_conns"`
	InUse        int32     `json:"in_use"`
	Idle         int32     `json:"idle"`
	Constructing int32     `json:"constructing"`
	// ResidentConns are pool connections control-api keeps for a long time
	// (LISTEN loops, session advisory locks: database.Residents with
	// InPool); RequestCapacity = MaxConns − ResidentConns is the share every
	// request and short job competes for.
	ResidentConns   int32 `json:"resident_conns"`
	RequestCapacity int32 `json:"request_capacity"`
	// Acquires succeeded this cycle; Queued of them found no idle connection
	// and waited (EmptyAcquireCount); Canceled gave up because their context
	// ended (CanceledAcquireCount).
	Acquires  int64    `json:"acquires"`
	Queued    int64    `json:"queued"`
	Canceled  int64    `json:"canceled"`
	AvgWaitMS float64  `json:"avg_wait_ms"`
	Reasons   []string `json:"reasons"`
}

// Notifier sends the platform notifications. Every call is idempotent per
// (instance, since): a retried or repeated call sends nothing new.
type Notifier interface {
	Saturated(ctx context.Context, instance string, since time.Time, s Sample) error
	Recovered(ctx context.Context, instance string, since time.Time, cause string, at time.Time) error
	// CloseStale sends the recovery (CauseInstanceRestarted) of every alert
	// of instance a previous process notified and never recovered.
	CloseStale(ctx context.Context, instance string, at time.Time) error
}

type opKind int

const (
	opCloseStale opKind = iota
	opSaturated
	opRecovered
)

type op struct {
	kind   opKind
	since  time.Time
	at     time.Time
	cause  string
	sample Sample
}

// Monitor samples one pool and keeps the alert state of one instance.
type Monitor struct {
	instance  string
	stat      func() dbpoolmon.Stat
	residents func() []database.Resident
	notifier  Notifier
	logger    *slog.Logger

	mu       sync.Mutex
	history  []Sample
	held     []database.Resident
	detector dbpoolmon.Detector
	since    time.Time // start of the current or last alert
	// notified: the current alert has been sent. An alert entered within
	// DedupWindow of the last sent one is folded into it (not sent); if it
	// is still firing once the window has passed, it is sent then, so an
	// alert stays hidden for at most DedupWindow. Only a sent alert is
	// followed by a recovery notification.
	notified     bool
	lastNotified time.Time // last saturation notification (DedupWindow runs from here)
	pendingCount int

	// Owned by the goroutine calling Tick (Run): no lock.
	prev    dbpoolmon.Stat
	primed  bool
	pending []op
}

// New monitors stat for instance; residents lists the resident connections
// (database.Residents).
func New(instance string, stat func() dbpoolmon.Stat, residents func() []database.Resident, notifier Notifier, logger *slog.Logger) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}
	if residents == nil {
		residents = func() []database.Resident { return nil }
	}
	return &Monitor{instance: instance, stat: stat, residents: residents, notifier: notifier, logger: logger}
}

// Run closes this instance's alerts left open by a previous process, then
// samples every SampleInterval until ctx ends.
func (m *Monitor) Run(ctx context.Context) error {
	m.Prime()
	m.push(op{kind: opCloseStale, at: time.Now().UTC()})
	m.flush(ctx)
	ticker := time.NewTicker(dbpoolmon.SampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			m.Tick(ctx, now)
		}
	}
}

// Prime takes the counter baseline, so the first Tick measures one cycle.
func (m *Monitor) Prime() {
	m.prev, m.primed = m.stat(), true
}

// Tick samples the pool once, updates the alert state and sends due
// notifications. Calls must not overlap (Run calls it from one goroutine).
func (m *Monitor) Tick(ctx context.Context, now time.Time) {
	if !m.primed {
		m.Prime()
	}
	cur := m.stat()
	held := m.residents()
	var inPool int32
	for _, r := range held {
		if r.InPool {
			inPool++
		}
	}
	c := dbpoolmon.Measure(m.prev, cur)
	m.prev = cur
	m.evaluate(Sample{At: now.UTC(), MaxConns: c.MaxConns, TotalConns: c.TotalConns, InUse: c.InUse, Idle: c.Idle,
		Constructing: c.Constructing, ResidentConns: inPool, RequestCapacity: max(c.MaxConns-inPool, 0),
		Acquires: c.Acquires, Queued: c.Queued, Canceled: c.Canceled, AvgWaitMS: c.AvgWaitMS, Reasons: c.Reasons}, held)
	m.flush(ctx)
}

func (m *Monitor) evaluate(s Sample, held []database.Resident) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.history = dbpoolmon.Append(m.history, s)
	m.held = held
	switch m.detector.Observe(s.At, s.Reasons) {
	case dbpoolmon.Enter:
		m.since = s.At
		m.notified = m.lastNotified.IsZero() || s.At.Sub(m.lastNotified) >= dbpoolmon.DedupWindow
		m.logger.Warn("control database pool saturated: requests are queueing for connections",
			append(attrs(m.instance, s), "dedup", !m.notified)...)
		if m.notified {
			m.notifySaturated(s)
		}
	case dbpoolmon.Recover:
		m.logger.Info("control database pool recovered", append(attrs(m.instance, s), "since", m.since, "notified", m.notified)...)
		if m.notified {
			m.push(op{kind: opRecovered, since: m.since, at: s.At, cause: CauseRecovered})
		}
		m.notified = false
	default:
		if firing, _, _ := m.detector.Firing(); firing && !m.notified && s.At.Sub(m.lastNotified) >= dbpoolmon.DedupWindow {
			m.notified = true
			m.logger.Warn("control database pool still saturated after the dedup window", append(attrs(m.instance, s), "since", m.since)...)
			m.notifySaturated(s)
		}
	}
}

// notifySaturated queues the saturation notification of the current alert;
// the caller holds mu.
func (m *Monitor) notifySaturated(s Sample) {
	m.lastNotified = s.At
	m.push(op{kind: opSaturated, since: m.since, sample: s})
}

// push queues a write; past maxPending the oldest go.
func (m *Monitor) push(o op) {
	m.pending = append(m.pending, o)
	if over := len(m.pending) - maxPending; over > 0 {
		m.pending = slices.Delete(m.pending, 0, over)
	}
}

// flush sends the queued notifications in order and stops at the first
// failure, which is retried next cycle.
func (m *Monitor) flush(ctx context.Context) {
	for len(m.pending) > 0 {
		write, cancel := context.WithTimeout(ctx, writeTimeout)
		err := m.apply(write, m.pending[0])
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				m.logger.Warn("control database pool notification not written; retrying next cycle", "instance", m.instance, "error", err)
			}
			break
		}
		m.pending = m.pending[1:]
	}
	m.mu.Lock()
	m.pendingCount = len(m.pending)
	m.mu.Unlock()
}

func (m *Monitor) apply(ctx context.Context, o op) error {
	switch o.kind {
	case opCloseStale:
		return m.notifier.CloseStale(ctx, m.instance, o.at)
	case opSaturated:
		return m.notifier.Saturated(ctx, m.instance, o.since, o.sample)
	default:
		return m.notifier.Recovered(ctx, m.instance, o.since, o.cause, o.at)
	}
}

// Snapshot is what the admin API shows of this instance.
type Snapshot struct {
	Instance        string               `json:"instance"`
	IntervalSeconds int64                `json:"interval_seconds"`
	Thresholds      dbpoolmon.Thresholds `json:"thresholds"`
	Current         *Sample              `json:"current"`
	Series          []Sample             `json:"series"`
	// Residents are the resident connections at the last sample.
	Residents     []database.Resident `json:"residents"`
	Firing        bool                `json:"firing"`
	FiringSince   *time.Time          `json:"firing_since"`
	FiringReasons []string            `json:"firing_reasons"`
	// Notified: the current alert has been sent (false while it is folded
	// into the one sent at LastNotifiedAt, within the dedup window).
	Notified       bool       `json:"notified"`
	LastNotifiedAt *time.Time `json:"last_notified_at"`
	// PendingNotifications are notification writes waiting to be retried
	// (the database refused them).
	PendingNotifications int `json:"pending_notifications"`
}

// Snapshot copies the current state (safe from any goroutine).
func (m *Monitor) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	firing, since, reasons := m.detector.Firing()
	out := Snapshot{Instance: m.instance, IntervalSeconds: int64(dbpoolmon.SampleInterval / time.Second),
		Thresholds: dbpoolmon.CurrentThresholds(), Series: slices.Clone(m.history), Residents: slices.Clone(m.held),
		Firing: firing, FiringReasons: reasons, Notified: firing && m.notified, PendingNotifications: m.pendingCount}
	if out.Series == nil {
		out.Series = []Sample{}
	}
	if out.Residents == nil {
		out.Residents = []database.Resident{}
	}
	if n := len(m.history); n > 0 {
		last := m.history[n-1]
		out.Current = &last
	}
	if firing {
		out.FiringSince = &since
	}
	if !m.lastNotified.IsZero() {
		last := m.lastNotified
		out.LastNotifiedAt = &last
	}
	return out
}

// attrs are the log fields of a sample (every value, for the WARN line).
func attrs(instance string, s Sample) []any {
	return []any{"instance", instance, "max_conns", s.MaxConns, "total_conns", s.TotalConns, "in_use", s.InUse, "idle", s.Idle,
		"constructing", s.Constructing, "resident_conns", s.ResidentConns, "request_capacity", s.RequestCapacity,
		"acquires", s.Acquires, "queued", s.Queued, "canceled", s.Canceled, "avg_wait_ms", s.AvgWaitMS, "reasons", s.Reasons}
}

// formatWait is the notification text of an average wait.
func formatWait(ms float64) string { return strconv.FormatFloat(ms, 'f', 1, 64) }
