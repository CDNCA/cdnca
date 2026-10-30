package telemetryclient

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

type Spool interface {
	Flush(context.Context, eventspool.Publisher, int) (eventspool.PublishResult, error)
	Stats() (eventspool.Stats, error)
}

type ConnectionsSpool interface {
	FlushConnections(context.Context, eventspool.Publisher, int) (eventspool.ConnectionsPublishResult, error)
}

const maxConnectionsBatchRecords = 256

type spoolCursor struct {
	spool Spool
}

func NewDurableCursor(spool Spool) DurableCursor {
	return spoolCursor{spool: spool}
}

func (c spoolCursor) AcknowledgedSequence(ctx context.Context) (uint64, error) {
	if c.spool == nil {
		return 0, ErrInvalidConfiguration
	}
	type result struct {
		stats eventspool.Stats
		err   error
	}
	completed := make(chan result, 1)
	go func() {
		stats, err := c.spool.Stats()
		completed <- result{stats: stats, err: err}
	}()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case value := <-completed:
		return value.stats.AckedSequence, value.err
	}
}

type WorkerConfig struct {
	MaximumEvents  int
	EmptyInterval  time.Duration
	InitialBackoff time.Duration
	MaximumBackoff time.Duration
}

type WorkerSnapshot struct {
	Running          bool
	Degraded         bool
	LastErrorCode    string
	AcceptedSequence uint64
}

type Worker struct {
	config    WorkerConfig
	spool     Spool
	publisher eventspool.Publisher
	mu        sync.RWMutex
	snapshot  WorkerSnapshot
	jitter    func(time.Duration) time.Duration
	// loggedCode: the failure last logged, so a transient one is logged
	// once and its recovery once (guarded by mu).
	loggedCode string
}

func NewWorker(config WorkerConfig, spool Spool, publisher eventspool.Publisher) (*Worker, error) {
	if spool == nil || publisher == nil || config.MaximumEvents < 1 || config.MaximumEvents > 10000 || config.EmptyInterval <= 0 ||
		config.InitialBackoff <= 0 || config.MaximumBackoff < config.InitialBackoff || config.MaximumBackoff > time.Hour {
		return nil, ErrInvalidConfiguration
	}
	return &Worker{
		config: config, spool: spool, publisher: publisher,
		jitter: func(delay time.Duration) time.Duration {
			return time.Duration(float64(delay) * (0.8 + rand.Float64()*0.4))
		},
	}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	w.setSnapshot(func(value *WorkerSnapshot) { value.Running = true })
	defer w.setSnapshot(func(value *WorkerSnapshot) { value.Running = false })
	backoff := w.config.InitialBackoff
	for {
		result, err := w.spool.Flush(ctx, w.publisher, w.config.MaximumEvents)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if result.LastSequence > 0 {
			w.setSnapshot(func(value *WorkerSnapshot) { value.AcceptedSequence = result.LastSequence })
		}
		if err != nil {
			code := safeWorkerError(err)
			permanent := permanentWorkerError(err)
			w.setSnapshot(func(value *WorkerSnapshot) {
				value.Degraded = true
				value.LastErrorCode = code
			})
			// A permanent rejection (the gateway refusing a batch, e.g. for a
			// config version its node authorization does not carry yet) used
			// to end the worker and with it the whole telemetry pipeline: the
			// tail stopped after its first batch, silently (N11). Retry at
			// the maximum backoff instead; the gateway re-reads the node's
			// authorization on every session.
			w.logFailure("telemetry upload", code, permanent, err)
			delay := w.jitter(backoff)
			if permanent || delay < 0 || delay > w.config.MaximumBackoff {
				delay = w.config.MaximumBackoff
			}
			if retryAfter := RetryAfter(err); retryAfter > delay {
				delay = retryAfter
			}
			if sleepErr := sleep(ctx, delay); sleepErr != nil {
				return sleepErr
			}
			backoff = nextBackoff(backoff, w.config.MaximumBackoff)
			continue
		}
		w.logRecovered("telemetry upload", result.LastSequence)
		w.setSnapshot(func(value *WorkerSnapshot) {
			value.Degraded = false
			value.LastErrorCode = ""
		})
		backoff = w.config.InitialBackoff
		if result.Published == 0 {
			if err := sleep(ctx, w.config.EmptyInterval); err != nil {
				return err
			}
		}
	}
}

// RunConnections drains the durable connections queue through the same
// publisher while keeping its watermark and partial acknowledgement boundary
// independent from legacy access/security events.
func (w *Worker) RunConnections(ctx context.Context) error {
	if w == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	spool, ok := any(w.spool).(ConnectionsSpool)
	if !ok {
		return ErrInvalidConfiguration
	}
	w.setSnapshot(func(value *WorkerSnapshot) { value.Running = true })
	defer w.setSnapshot(func(value *WorkerSnapshot) { value.Running = false })
	backoff := w.config.InitialBackoff
	maximum := w.config.MaximumEvents
	if maximum > maxConnectionsBatchRecords {
		maximum = maxConnectionsBatchRecords
	}
	for {
		result, err := spool.FlushConnections(ctx, w.publisher, maximum)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if result.LastSourceWatermark > 0 {
			w.setSnapshot(func(value *WorkerSnapshot) { value.AcceptedSequence = result.LastSourceWatermark })
		}
		if err != nil {
			code := safeWorkerError(err)
			permanent := permanentWorkerError(err)
			w.setSnapshot(func(value *WorkerSnapshot) {
				value.Degraded = true
				value.LastErrorCode = code
			})
			// A permanent rejection (the gateway refusing a batch, e.g. for a
			// config version its node authorization does not carry yet) used
			// to end the worker and with it the whole telemetry pipeline: the
			// tail stopped after its first batch, silently (N11). Retry at
			// the maximum backoff instead; the gateway re-reads the node's
			// authorization on every session.
			w.logFailure("connections telemetry upload", code, permanent, err)
			delay := w.jitter(backoff)
			if permanent || delay < 0 || delay > w.config.MaximumBackoff {
				delay = w.config.MaximumBackoff
			}
			if retryAfter := RetryAfter(err); retryAfter > delay {
				delay = retryAfter
			}
			if sleepErr := sleep(ctx, delay); sleepErr != nil {
				return sleepErr
			}
			backoff = nextBackoff(backoff, w.config.MaximumBackoff)
			continue
		}
		w.logRecovered("connections telemetry upload", result.LastSourceWatermark)
		w.logRecovered("connections telemetry upload", result.LastSourceWatermark)
		w.setSnapshot(func(value *WorkerSnapshot) {
			value.Degraded = false
			value.LastErrorCode = ""
		})
		backoff = w.config.InitialBackoff
		if result.Published == 0 {
			if err := sleep(ctx, w.config.EmptyInterval); err != nil {
				return err
			}
		}
	}
}

// logFailure: a permanent rejection is logged on every attempt (at most once
// per maximum backoff), a transient one when its code changes.
func (w *Worker) logFailure(what, code string, permanent bool, err error) {
	w.mu.Lock()
	repeat := w.loggedCode == code
	w.loggedCode = code
	w.mu.Unlock()
	switch {
	case permanent:
		slog.Error(what+" rejected; retrying at maximum backoff", "code", code, "error", err)
	case !repeat:
		slog.Warn(what+" failed; retrying", "code", code, "error", err)
	}
}

func (w *Worker) logRecovered(what string, sequence uint64) {
	w.mu.Lock()
	code := w.loggedCode
	w.loggedCode = ""
	w.mu.Unlock()
	if code != "" {
		slog.Info(what+" recovered", "previous_code", code, "sequence", sequence)
	}
}

func (w *Worker) RunFailureIsolated(ctx context.Context, report func(string)) {
	err := w.Run(ctx)
	snapshot := w.Snapshot()
	if report == nil {
		return
	}
	if snapshot.LastErrorCode != "" {
		report(snapshot.LastErrorCode)
		return
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		report(safeWorkerError(err))
	}
}

func (w *Worker) Snapshot() WorkerSnapshot {
	if w == nil {
		return WorkerSnapshot{}
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.snapshot
}

func (w *Worker) setSnapshot(change func(*WorkerSnapshot)) {
	w.mu.Lock()
	change(&w.snapshot)
	w.mu.Unlock()
}

func safeWorkerError(err error) string {
	switch {
	case errors.Is(err, ErrPermanentProtocol):
		return "TELEMETRY_PROTOCOL_REJECTED"
	case errors.Is(err, ErrInvalidPublication):
		return "TELEMETRY_PUBLICATION_INVALID"
	case errors.Is(err, ErrInvalidResponse):
		return "TELEMETRY_RESPONSE_INVALID"
	case errors.Is(err, ErrBackpressure):
		return "TELEMETRY_BACKPRESSURE"
	case errors.Is(err, ErrPartialAcknowledged):
		return "TELEMETRY_PARTIAL_ACK"
	case errors.Is(err, eventspool.ErrConnectionsUnavailable):
		return "TELEMETRY_CONNECTIONS_UNAVAILABLE"
	case errors.Is(err, eventspool.ErrConnectionsConflict):
		return "TELEMETRY_CONNECTIONS_CONFLICT"
	case errors.Is(err, eventspool.ErrConnectionsWatermark):
		return "TELEMETRY_CONNECTIONS_WATERMARK"
	case errors.Is(err, eventspool.ErrInvalidConnections):
		return "TELEMETRY_CONNECTIONS_INVALID"
	case errors.Is(err, eventspool.ErrCorruptState):
		return "TELEMETRY_SPOOL_CORRUPT"
	default:
		return "TELEMETRY_UNAVAILABLE"
	}
}

func permanentWorkerError(err error) bool {
	return errors.Is(err, ErrPermanentProtocol) || errors.Is(err, ErrInvalidPublication) ||
		errors.Is(err, ErrInvalidResponse) || errors.Is(err, eventspool.ErrInvalidAck) ||
		errors.Is(err, eventspool.ErrCorruptState) || errors.Is(err, eventspool.ErrInvalidConfig) ||
		errors.Is(err, eventspool.ErrConnectionsConflict) || errors.Is(err, eventspool.ErrConnectionsWatermark) ||
		errors.Is(err, eventspool.ErrInvalidConnections)
}

func sleep(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var _ Spool = (*eventspool.Spool)(nil)
var _ DurableCursor = spoolCursor{}
