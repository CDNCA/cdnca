package analyticslog

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

const replicaHealthSQL = `SELECT
database,
table,
toUInt8(is_readonly) AS is_readonly,
toUInt8(is_session_expired) AS is_session_expired,
toUInt64(queue_size) AS queue_size,
toUInt64(absolute_delay) AS absolute_delay,
toUInt64(if(log_max_index>=log_pointer,log_max_index-log_pointer,0)) AS log_lag,
toUInt64(total_replicas) AS total_replicas,
toUInt64(active_replicas) AS active_replicas,
toInt64(toUnixTimestamp64Milli(now64(3,'UTC'))) AS observed_at_ms
FROM system.replicas
WHERE database={database:String}
ORDER BY table ASC
LIMIT {row_limit:UInt16}
SETTINGS max_threads=1
FORMAT JSONEachRow`

const (
	defaultReplicaHealthCapacity = 4
	maximumReplicaHealthCapacity = 64
	defaultReplicaHealthTables   = 128
	maximumReplicaHealthTables   = 1024
	defaultReplicaQueueSize      = 1000
	defaultReplicaAbsoluteDelay  = 5 * time.Minute
	defaultReplicaLogLag         = 100000
	defaultReplicaSnapshotAge    = 30 * time.Second
)

type ReplicaHealthReason string

const (
	ReplicaSessionExpired ReplicaHealthReason = "replica_session_expired"
	ReplicaReadOnly       ReplicaHealthReason = "replica_read_only"
	ReplicaUnavailable    ReplicaHealthReason = "replica_unavailable"
	ReplicaQueueBacklog   ReplicaHealthReason = "replication_queue_backlog"
	ReplicaDelayExceeded  ReplicaHealthReason = "replication_delay_exceeded"
	ReplicaLogLagExceeded ReplicaHealthReason = "replication_log_lag_exceeded"
)

type ReplicaHealthConfig struct {
	QueryTimeout     time.Duration
	MaxConcurrent    int
	MaxTables        int
	MaxQueueSize     uint64
	MaxAbsoluteDelay time.Duration
	MaxLogLag        uint64
	MaxSnapshotAge   time.Duration
	Now              func() time.Time
}

type ReplicaTableHealth struct {
	Table          string
	Healthy        bool
	Reasons        []ReplicaHealthReason
	QueueSize      uint64
	AbsoluteDelay  time.Duration
	LogLag         uint64
	TotalReplicas  uint64
	ActiveReplicas uint64
}

type ReplicaHealthSnapshot struct {
	Database   string
	ObservedAt time.Time
	Healthy    bool
	Tables     []ReplicaTableHealth
}

type ReplicaHealthSource struct {
	client           *Client
	queryTimeout     time.Duration
	capacity         chan struct{}
	maxTables        int
	maxQueueSize     uint64
	maxAbsoluteDelay time.Duration
	maxLogLag        uint64
	maxSnapshotAge   time.Duration
	now              func() time.Time
}

type replicaHealthRow struct {
	Database         string `json:"database"`
	Table            string `json:"table"`
	ReadOnly         uint8  `json:"is_readonly"`
	SessionExpired   uint8  `json:"is_session_expired"`
	QueueSize        uint64 `json:"queue_size"`
	AbsoluteDelay    uint64 `json:"absolute_delay"`
	LogLag           uint64 `json:"log_lag"`
	TotalReplicas    uint64 `json:"total_replicas"`
	ActiveReplicas   uint64 `json:"active_replicas"`
	ObservedAtMillis int64  `json:"observed_at_ms"`
}

func NewReplicaHealthSource(client *Client, config ReplicaHealthConfig) (*ReplicaHealthSource, error) {
	if client == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = client.queryTimeout
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = defaultReplicaHealthCapacity
	}
	if config.MaxTables == 0 {
		config.MaxTables = defaultReplicaHealthTables
	}
	if config.MaxQueueSize == 0 {
		config.MaxQueueSize = defaultReplicaQueueSize
	}
	if config.MaxAbsoluteDelay == 0 {
		config.MaxAbsoluteDelay = defaultReplicaAbsoluteDelay
	}
	if config.MaxLogLag == 0 {
		config.MaxLogLag = defaultReplicaLogLag
	}
	if config.MaxSnapshotAge == 0 {
		config.MaxSnapshotAge = defaultReplicaSnapshotAge
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.QueryTimeout < time.Millisecond || config.QueryTimeout > 30*time.Second ||
		config.MaxConcurrent < 1 || config.MaxConcurrent > maximumReplicaHealthCapacity ||
		config.MaxTables < 1 || config.MaxTables > maximumReplicaHealthTables ||
		config.MaxAbsoluteDelay < time.Second || config.MaxAbsoluteDelay > 24*time.Hour ||
		config.MaxSnapshotAge < time.Second || config.MaxSnapshotAge > 5*time.Minute {
		return nil, ErrInvalidConfiguration
	}
	return &ReplicaHealthSource{
		client: client, queryTimeout: config.QueryTimeout,
		capacity: make(chan struct{}, config.MaxConcurrent), maxTables: config.MaxTables,
		maxQueueSize: config.MaxQueueSize, maxAbsoluteDelay: config.MaxAbsoluteDelay,
		maxLogLag: config.MaxLogLag, maxSnapshotAge: config.MaxSnapshotAge, now: config.Now,
	}, nil
}

func (source *ReplicaHealthSource) Read(ctx context.Context) (ReplicaHealthSnapshot, error) {
	if source == nil || source.client == nil || source.capacity == nil || source.now == nil || ctx == nil {
		return ReplicaHealthSnapshot{}, ErrStorageUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ReplicaHealthSnapshot{}, err
	}
	select {
	case source.capacity <- struct{}{}:
		defer func() { <-source.capacity }()
	case <-ctx.Done():
		return ReplicaHealthSnapshot{}, ctx.Err()
	default:
		return ReplicaHealthSnapshot{}, ErrStorageUnavailable
	}

	queryContext, cancel := context.WithTimeout(ctx, source.queryTimeout)
	defer cancel()
	parameters := url.Values{
		"param_database":       {source.client.database},
		"param_row_limit":      {strconv.Itoa(source.maxTables + 1)},
		"max_result_rows":      {strconv.Itoa(source.maxTables + 1)},
		"result_overflow_mode": {"throw"},
	}
	rows, err := queryRows[replicaHealthRow](source.client, queryContext, replicaHealthSQL, parameters, source.maxTables+1)
	if err != nil {
		return ReplicaHealthSnapshot{}, err
	}
	return source.validateRows(rows)
}

func (source *ReplicaHealthSource) validateRows(rows []replicaHealthRow) (ReplicaHealthSnapshot, error) {
	if len(rows) == 0 {
		return ReplicaHealthSnapshot{}, ErrCapabilityUnsupported
	}
	if len(rows) > source.maxTables {
		return ReplicaHealthSnapshot{}, ErrInvalidResponse
	}
	now := source.now().UTC().Truncate(time.Millisecond)
	observedAt := time.UnixMilli(rows[0].ObservedAtMillis).UTC()
	if now.IsZero() || observedAt.IsZero() || observedAt.After(now) || now.Sub(observedAt) > source.maxSnapshotAge {
		return ReplicaHealthSnapshot{}, ErrInvalidResponse
	}

	snapshot := ReplicaHealthSnapshot{
		Database: source.client.database, ObservedAt: observedAt, Healthy: true,
		Tables: make([]ReplicaTableHealth, len(rows)),
	}
	previousTable := ""
	for index, row := range rows {
		if row.Database != source.client.database || !validDatabase(row.Table) || row.Table <= previousTable ||
			row.ObservedAtMillis != rows[0].ObservedAtMillis || row.ReadOnly > 1 || row.SessionExpired > 1 ||
			row.TotalReplicas == 0 || row.ActiveReplicas > row.TotalReplicas ||
			row.AbsoluteDelay > uint64((3650*24*time.Hour)/time.Second) {
			return ReplicaHealthSnapshot{}, ErrInvalidResponse
		}
		previousTable = row.Table
		table := ReplicaTableHealth{
			Table: row.Table, Healthy: true, QueueSize: row.QueueSize,
			AbsoluteDelay: time.Duration(row.AbsoluteDelay) * time.Second,
			LogLag:        row.LogLag, TotalReplicas: row.TotalReplicas, ActiveReplicas: row.ActiveReplicas,
		}
		if row.SessionExpired == 1 {
			table.Reasons = append(table.Reasons, ReplicaSessionExpired)
		}
		if row.ReadOnly == 1 {
			table.Reasons = append(table.Reasons, ReplicaReadOnly)
		}
		if row.ActiveReplicas < row.TotalReplicas {
			table.Reasons = append(table.Reasons, ReplicaUnavailable)
		}
		if row.QueueSize > source.maxQueueSize {
			table.Reasons = append(table.Reasons, ReplicaQueueBacklog)
		}
		if table.AbsoluteDelay > source.maxAbsoluteDelay {
			table.Reasons = append(table.Reasons, ReplicaDelayExceeded)
		}
		if row.LogLag > source.maxLogLag {
			table.Reasons = append(table.Reasons, ReplicaLogLagExceeded)
		}
		table.Healthy = len(table.Reasons) == 0
		if !table.Healthy {
			snapshot.Healthy = false
		}
		snapshot.Tables[index] = table
	}
	return snapshot, nil
}
