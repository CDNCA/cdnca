package analyticsreplicametrics

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

const (
	MetricSourceUp         = "cdnca_clickhouse_replica_source_up"
	MetricReplicaMissing   = "cdnca_clickhouse_replica_missing"
	MetricReplicaReadOnly  = "cdnca_clickhouse_replica_readonly"
	MetricSessionExpired   = "cdnca_clickhouse_replica_session_expired"
	MetricQueueBacklog     = "cdnca_clickhouse_replication_queue_backlog"
	MetricDelayExceeded    = "cdnca_clickhouse_replication_delay_exceeded"
	MetricLogLagExceeded   = "cdnca_clickhouse_replication_log_lag_exceeded"
	MetricAlertStatus      = "cdnca_clickhouse_replica_alert_status"
	maximumMonitoredTables = 1024
)

var (
	ErrInvalidConfiguration = errors.New("invalid analytics replica metrics configuration")
	ErrAlreadyRunning       = errors.New("analytics replica metrics runtime already running")
	ErrNotReady             = errors.New("analytics replica metrics runtime not ready")
	ErrSourceUnavailable    = errors.New("analytics replica metrics source unavailable")
	ErrClosed               = errors.New("analytics replica metrics runtime closed")
)

type AlertStatus uint8

const (
	AlertOK AlertStatus = iota
	AlertFiring
	AlertSourceUnavailable
	// AlertCapabilityUnsupported means the ClickHouse deployment is reachable
	// but does not expose replicated tables (for example, local MergeTree).
	AlertCapabilityUnsupported
)

type Gauge struct {
	Name  string
	Value uint64
}

type Snapshot struct {
	SourceUp        uint64
	ReplicaMissing  uint64
	ReplicaReadOnly uint64
	SessionExpired  uint64
	QueueBacklog    uint64
	DelayExceeded   uint64
	LogLagExceeded  uint64
	AlertStatus     AlertStatus
	ObservedAt      time.Time
	EvaluatedAt     time.Time
}

func (snapshot Snapshot) PrometheusGauges() [8]Gauge {
	return [8]Gauge{
		{Name: MetricSourceUp, Value: snapshot.SourceUp},
		{Name: MetricReplicaMissing, Value: snapshot.ReplicaMissing},
		{Name: MetricReplicaReadOnly, Value: snapshot.ReplicaReadOnly},
		{Name: MetricSessionExpired, Value: snapshot.SessionExpired},
		{Name: MetricQueueBacklog, Value: snapshot.QueueBacklog},
		{Name: MetricDelayExceeded, Value: snapshot.DelayExceeded},
		{Name: MetricLogLagExceeded, Value: snapshot.LogLagExceeded},
		{Name: MetricAlertStatus, Value: uint64(snapshot.AlertStatus)},
	}
}

type HealthSource interface {
	Read(context.Context) (analyticslog.ReplicaHealthSnapshot, error)
}

type Config struct {
	PollInterval time.Duration
	ReadTimeout  time.Duration
	MaxTables    int
	MaxStaleness time.Duration
	Now          func() time.Time
}

type Runtime struct {
	config Config
	source HealthSource

	mu       sync.RWMutex
	running  bool
	closing  bool
	closed   bool
	ready    bool
	failure  error
	cancel   context.CancelFunc
	done     chan struct{}
	snapshot Snapshot
	closeMu  sync.Mutex
}

func New(config Config, source HealthSource) (*Runtime, error) {
	if nilSource(source) || config.PollInterval < 10*time.Millisecond || config.PollInterval > 5*time.Minute ||
		config.ReadTimeout < time.Millisecond || config.ReadTimeout > 30*time.Second ||
		config.MaxTables < 1 || config.MaxTables > maximumMonitoredTables ||
		config.MaxStaleness < time.Second || config.MaxStaleness > 5*time.Minute || config.Now == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Runtime{
		config: config, source: source,
		snapshot: Snapshot{AlertStatus: AlertSourceUnavailable},
	}, nil
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	runContext, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	runtime.mu.Lock()
	if runtime.closing || runtime.closed {
		runtime.mu.Unlock()
		cancel()
		return ErrClosed
	}
	if runtime.running {
		runtime.mu.Unlock()
		cancel()
		return ErrAlreadyRunning
	}
	runtime.running = true
	runtime.ready = false
	runtime.cancel = cancel
	runtime.done = done
	runtime.mu.Unlock()
	defer func() {
		cancel()
		runtime.mu.Lock()
		runtime.running = false
		runtime.ready = false
		runtime.cancel = nil
		if runtime.closing {
			runtime.closed = true
		}
		close(done)
		runtime.mu.Unlock()
	}()

	for {
		if runContext.Err() != nil {
			return nil
		}
		runtime.evaluate(runContext)
		if !wait(runContext, runtime.config.PollInterval) {
			return nil
		}
	}
}

func (runtime *Runtime) Ready() error {
	if runtime == nil {
		return ErrInvalidConfiguration
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if runtime.closing || runtime.closed {
		return ErrClosed
	}
	if runtime.failure != nil {
		return runtime.failure
	}
	if !runtime.running || !runtime.ready {
		return ErrNotReady
	}
	return nil
}

func (runtime *Runtime) Snapshot() Snapshot {
	if runtime == nil {
		return Snapshot{AlertStatus: AlertSourceUnavailable}
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return runtime.snapshot
}

func (runtime *Runtime) Close() error {
	if runtime == nil {
		return ErrInvalidConfiguration
	}
	runtime.closeMu.Lock()
	defer runtime.closeMu.Unlock()
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		return nil
	}
	runtime.closing = true
	runtime.ready = false
	runtime.failure = nil
	cancel, done, running := runtime.cancel, runtime.done, runtime.running
	if !running {
		runtime.closed = true
	}
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if running {
		<-done
	}
	return nil
}

func (runtime *Runtime) evaluate(ctx context.Context) {
	readContext, cancel := context.WithTimeout(ctx, runtime.config.ReadTimeout)
	health, err := runtime.source.Read(readContext)
	cancel()
	if ctx.Err() != nil {
		return
	}
	evaluatedAt := runtime.config.Now().UTC().Truncate(time.Millisecond)
	if evaluatedAt.IsZero() {
		runtime.recordFailure(evaluatedAt)
		return
	}
	if errors.Is(err, analyticslog.ErrCapabilityUnsupported) {
		runtime.recordCapabilityUnsupported(evaluatedAt)
		return
	}
	if err != nil {
		runtime.recordFailure(evaluatedAt)
		return
	}
	snapshot, ok := evaluateHealth(health, evaluatedAt, runtime.config)
	if !ok {
		runtime.recordFailure(evaluatedAt)
		return
	}
	runtime.mu.Lock()
	if !runtime.closing && !runtime.closed {
		runtime.snapshot = snapshot
		runtime.failure = nil
		runtime.ready = true
	}
	runtime.mu.Unlock()
}

func (runtime *Runtime) recordFailure(evaluatedAt time.Time) {
	runtime.mu.Lock()
	if !runtime.closing && !runtime.closed {
		runtime.snapshot = Snapshot{AlertStatus: AlertSourceUnavailable, EvaluatedAt: evaluatedAt}
		runtime.failure = ErrSourceUnavailable
		runtime.ready = false
	}
	runtime.mu.Unlock()
}

func (runtime *Runtime) recordCapabilityUnsupported(evaluatedAt time.Time) {
	runtime.mu.Lock()
	if !runtime.closing && !runtime.closed {
		runtime.snapshot = Snapshot{
			SourceUp: 1, AlertStatus: AlertCapabilityUnsupported, EvaluatedAt: evaluatedAt,
		}
		runtime.failure = nil
		runtime.ready = true
	}
	runtime.mu.Unlock()
}

func evaluateHealth(health analyticslog.ReplicaHealthSnapshot, evaluatedAt time.Time, config Config) (Snapshot, bool) {
	if !validIdentity(health.Database) || health.ObservedAt.IsZero() || health.ObservedAt.Location() != time.UTC ||
		health.ObservedAt.After(evaluatedAt) || evaluatedAt.Sub(health.ObservedAt) > config.MaxStaleness ||
		len(health.Tables) == 0 || len(health.Tables) > config.MaxTables {
		return Snapshot{}, false
	}
	result := Snapshot{
		SourceUp: 1, AlertStatus: AlertOK,
		ObservedAt: health.ObservedAt, EvaluatedAt: evaluatedAt,
	}
	allHealthy := true
	tables := make(map[string]struct{}, len(health.Tables))
	for _, table := range health.Tables {
		if !validIdentity(table.Table) {
			return Snapshot{}, false
		}
		if _, duplicate := tables[table.Table]; duplicate {
			return Snapshot{}, false
		}
		tables[table.Table] = struct{}{}
		reasons := make(map[analyticslog.ReplicaHealthReason]struct{}, len(table.Reasons))
		for _, reason := range table.Reasons {
			if _, duplicate := reasons[reason]; duplicate {
				return Snapshot{}, false
			}
			reasons[reason] = struct{}{}
			switch reason {
			case analyticslog.ReplicaUnavailable:
				result.ReplicaMissing++
			case analyticslog.ReplicaReadOnly:
				result.ReplicaReadOnly++
			case analyticslog.ReplicaSessionExpired:
				result.SessionExpired++
			case analyticslog.ReplicaQueueBacklog:
				result.QueueBacklog++
			case analyticslog.ReplicaDelayExceeded:
				result.DelayExceeded++
			case analyticslog.ReplicaLogLagExceeded:
				result.LogLagExceeded++
			default:
				return Snapshot{}, false
			}
		}
		tableHealthy := len(reasons) == 0
		if table.Healthy != tableHealthy {
			return Snapshot{}, false
		}
		allHealthy = allHealthy && tableHealthy
	}
	if health.Healthy != allHealthy {
		return Snapshot{}, false
	}
	if !allHealthy {
		result.AlertStatus = AlertFiring
	}
	return result, true
}

func validIdentity(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}

func nilSource(source HealthSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func wait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
