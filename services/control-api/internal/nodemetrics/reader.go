package nodemetrics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

var ErrNotFound = errors.New("node metrics not found")

const MaxLatestBatch = 300

type LatestView struct {
	RecordKind           string
	ScopeID              uuid.UUID
	NodeID               uuid.UUID
	NodeName             string
	ConfigRevision       uint64
	PublicationSequence  uint64
	ObservedAt           time.Time
	ActiveConfigRevision uint64
	ProbePort            uint16
	Healthy              bool
	ProbeSucceeded       bool
	ConsecutiveFailures  uint8
	ConsecutiveSuccesses uint8
	ProbesTotal          uint64
	ProbeFailuresTotal   uint64
	Recovered            bool
	RecoveryNotified     bool
	RolledBack           bool
	Known                bool
	CPUPercent           *float64
	MemoryUsedBytes      *uint64
	MemoryTotalBytes     *uint64
	ActiveConnections    *uint64
	RXBandwidthBPS       *uint64
	TXBandwidthBPS       *uint64
	Telemetry            *Telemetry
	TotalRXBytes         *uint64
	TotalTXBytes         *uint64
	PubAckStream         string
	PubAckSequence       uint64
	ConsumerDurable      string
	ConsumerSequence     uint64
	IngestedAt           time.Time
	LatestRecovery       *RecoveryView
	MonthlyTraffic       *MonthlyTraffic
	// TelemetryDetail: the node's latest session declares
	// NODE_TELEMETRY_DETAIL v1 (mounts, port group override receipts).
	TelemetryDetail bool
	// StorageSupported: the node's latest session declares NODE_STORAGE v1
	// (the console may change its cache directory, cache limit and log directory).
	StorageSupported bool
}

type HistoryView struct {
	NodeID              uuid.UUID
	NodeName            string
	PublicationSequence uint64
	ObservedAt          time.Time
	Known               bool
	CPUPercent          *float64
	MemoryUsedBytes     *uint64
	MemoryTotalBytes    *uint64
	ActiveConnections   *uint64
	RXBandwidthBPS      *uint64
	TXBandwidthBPS      *uint64
	Telemetry           *Telemetry
	TotalRXBytes        *uint64
	TotalTXBytes        *uint64
}

type RecoveryView struct {
	ConfigRevision      uint64
	PublicationSequence uint64
	RecoveredAt         time.Time
	ReasonCode          string
	PubAckStream        string
	PubAckSequence      uint64
}

type PostgresReader struct{ pool *pgxpool.Pool }

func NewPostgresReader(pool *pgxpool.Pool) (*PostgresReader, error) {
	if pool == nil {
		return nil, ErrInvalidConfiguration
	}
	return &PostgresReader{pool: pool}, nil
}

func (reader *PostgresReader) Latest(ctx context.Context, scopeID, nodeID uuid.UUID) (LatestView, error) {
	items, _, err := reader.LatestBatch(ctx, scopeID, []uuid.UUID{nodeID})
	if err != nil {
		return LatestView{}, err
	}
	if len(items) == 0 {
		return LatestView{}, ErrNotFound
	}
	return items[0], nil
}

func (reader *PostgresReader) LatestBatch(ctx context.Context, scopeID uuid.UUID, nodeIDs []uuid.UUID) ([]LatestView, []uuid.UUID, error) {
	if reader == nil || reader.pool == nil || ctx == nil || scopeID == uuid.Nil || len(nodeIDs) < 1 || len(nodeIDs) > MaxLatestBatch {
		return nil, nil, ErrInvalidConfiguration
	}
	seen := make(map[uuid.UUID]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		if _, duplicate := seen[id]; id == uuid.Nil || duplicate {
			return nil, nil, ErrInvalidConfiguration
		}
		seen[id] = struct{}{}
	}
	// Membership and samples use one snapshot. A missing or foreign node suppresses
	// the entire result before any sibling's metric payload is decoded.
	rows, err := reader.pool.Query(ctx, `
		WITH scoped_nodes AS (
			SELECT node.scope_id, node.id, node.name, requested.position
			FROM unnest($2::uuid[]) WITH ORDINALITY AS requested(id, position)
			JOIN nodes node ON node.id=requested.id AND node.scope_id=$1
		)
		SELECT node.scope_id, node.id, node.name, metric.config_revision,
		       metric.publication_sequence, metric.observed_at, COALESCE(metric.active_config_revision,0),
		       COALESCE(metric.probe_port,0), COALESCE(metric.healthy,false), COALESCE(metric.probe_succeeded,false),
		       COALESCE(metric.consecutive_failures,0), COALESCE(metric.consecutive_successes,0),
		       COALESCE(metric.probes_total,0), COALESCE(metric.probe_failures_total,0), COALESCE(metric.recovered,false),
		       COALESCE(metric.recovery_notified,false), COALESCE(metric.rolled_back,false), metric.metrics_known,
		       metric.cpu_percent, metric.memory_used_bytes, metric.memory_total_bytes,
		       metric.active_connections, metric.rx_bandwidth_bps, metric.tx_bandwidth_bps,
		       metric.telemetry_json, metric.total_rx_bytes, metric.total_tx_bytes,
		       metric.puback_stream, metric.puback_sequence, metric.consumer_durable,
		       metric.consumer_sequence, metric.ingested_at,
		       recovery.config_revision, recovery.publication_sequence, recovery.observed_at,
		       recovery.recovery_reason_code, recovery.puback_stream, recovery.puback_sequence, metric.record_kind,
		       (SELECT facts.capabilities_snapshot FROM node_session_capabilities facts
		        WHERE facts.node_id=node.id ORDER BY facts.session_epoch DESC LIMIT 1)
		FROM scoped_nodes node
		LEFT JOIN node_load_latest metric ON metric.node_id = node.id
		LEFT JOIN node_recovery_latest recovery ON recovery.node_id = node.id
		WHERE (SELECT count(*) FROM scoped_nodes)=cardinality($2::uuid[])
		ORDER BY node.position`, scopeID, nodeIDs)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	items := make([]LatestView, 0, len(nodeIDs))
	notReported := make([]uuid.UUID, 0, len(nodeIDs))
	for rows.Next() {
		// config_revision is NOT NULL for every stored sample, including host-only
		// revision zero. SQL NULL therefore denotes only the absent LEFT JOIN row.
		if rows.RawValues()[3] == nil {
			var id uuid.UUID
			targets := make([]any, len(rows.FieldDescriptions()))
			targets[1] = &id
			if err := rows.Scan(targets...); err != nil {
				return nil, nil, err
			}
			notReported = append(notReported, id)
			continue
		}
		view, err := scanLatestMetrics(rows)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, view)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(items)+len(notReported) != len(nodeIDs) {
		return nil, nil, ErrNotFound
	}
	monthly, err := reader.monthlyTraffic(ctx, scopeID, nodeIDs, time.Now().UTC())
	if err != nil {
		return nil, nil, err
	}
	for index := range items {
		if summary, ok := monthly[items[index].NodeID]; ok {
			items[index].MonthlyTraffic = &summary
		}
	}
	return items, notReported, nil
}

func scanLatestMetrics(row pgx.Row) (LatestView, error) {
	var view LatestView
	var recoveryConfigRevision, recoveryPublicationSequence, recoveryPubAckSequence *uint64
	var recoveryObservedAt *time.Time
	var recoveryReasonCode, recoveryPubAckStream *string
	var telemetryJSON, capabilities []byte
	err := row.Scan(
		&view.ScopeID, &view.NodeID, &view.NodeName, &view.ConfigRevision,
		&view.PublicationSequence, &view.ObservedAt, &view.ActiveConfigRevision, &view.ProbePort,
		&view.Healthy, &view.ProbeSucceeded, &view.ConsecutiveFailures, &view.ConsecutiveSuccesses,
		&view.ProbesTotal, &view.ProbeFailuresTotal, &view.Recovered, &view.RecoveryNotified,
		&view.RolledBack, &view.Known, &view.CPUPercent,
		&view.MemoryUsedBytes, &view.MemoryTotalBytes, &view.ActiveConnections,
		&view.RXBandwidthBPS, &view.TXBandwidthBPS, &telemetryJSON, &view.TotalRXBytes,
		&view.TotalTXBytes, &view.PubAckStream,
		&view.PubAckSequence, &view.ConsumerDurable, &view.ConsumerSequence, &view.IngestedAt,
		&recoveryConfigRevision, &recoveryPublicationSequence, &recoveryObservedAt,
		&recoveryReasonCode, &recoveryPubAckStream, &recoveryPubAckSequence, &view.RecordKind, &capabilities)
	if errors.Is(err, pgx.ErrNoRows) {
		return LatestView{}, ErrNotFound
	}
	if err != nil {
		return LatestView{}, err
	}
	if err := decodeStoredTelemetry(telemetryJSON, &view.Telemetry); err != nil {
		return LatestView{}, err
	}
	view.TelemetryDetail = DeclaresTelemetryDetail(capabilities)
	view.StorageSupported = declaresCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_NODE_STORAGE, siteobject.NodeStorageAPIVersion)
	if (view.Telemetry == nil) != (view.TotalRXBytes == nil || view.TotalTXBytes == nil) {
		return LatestView{}, ErrInvalidSample
	}
	if recoveryConfigRevision != nil {
		if recoveryPublicationSequence == nil || recoveryObservedAt == nil || recoveryReasonCode == nil ||
			recoveryPubAckStream == nil || recoveryPubAckSequence == nil {
			return LatestView{}, ErrInvalidSample
		}
		view.LatestRecovery = &RecoveryView{ConfigRevision: *recoveryConfigRevision,
			PublicationSequence: *recoveryPublicationSequence, RecoveredAt: *recoveryObservedAt,
			ReasonCode: *recoveryReasonCode, PubAckStream: *recoveryPubAckStream,
			PubAckSequence: *recoveryPubAckSequence}
	}
	return view, nil
}

func (reader *PostgresReader) History(
	ctx context.Context,
	scopeID, nodeID uuid.UUID,
	from, to time.Time,
	limit int,
) ([]HistoryView, error) {
	if reader == nil || reader.pool == nil || ctx == nil || scopeID == uuid.Nil || nodeID == uuid.Nil ||
		from.IsZero() || to.IsZero() || to.Before(from) || limit < 1 || limit > 2000 {
		return nil, ErrInvalidConfiguration
	}
	rows, err := reader.pool.Query(ctx, `
		SELECT node.id, node.name, metric.publication_sequence, metric.observed_at,
		       metric.metrics_known, metric.cpu_percent, metric.memory_used_bytes,
		       metric.memory_total_bytes, metric.active_connections,
		       metric.rx_bandwidth_bps, metric.tx_bandwidth_bps, metric.telemetry_json,
		       metric.total_rx_bytes, metric.total_tx_bytes
		FROM nodes node
		JOIN (
			SELECT *
			FROM node_metric_samples
			WHERE node_id=$2 AND record_kind IN ('metric','host_metric')
			  AND observed_at >= $3 AND observed_at <= $4
			ORDER BY observed_at DESC, publication_sequence DESC
			LIMIT $5
		) metric ON metric.node_id = node.id
		WHERE node.scope_id=$1 AND node.id=$2
		ORDER BY metric.observed_at ASC, metric.publication_sequence ASC`,
		scopeID, nodeID, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	history := make([]HistoryView, 0, limit)
	for rows.Next() {
		var view HistoryView
		var telemetryJSON []byte
		if err := rows.Scan(
			&view.NodeID, &view.NodeName, &view.PublicationSequence, &view.ObservedAt,
			&view.Known, &view.CPUPercent, &view.MemoryUsedBytes, &view.MemoryTotalBytes,
			&view.ActiveConnections, &view.RXBandwidthBPS, &view.TXBandwidthBPS,
			&telemetryJSON, &view.TotalRXBytes, &view.TotalTXBytes,
		); err != nil {
			return nil, err
		}
		if err := decodeStoredTelemetry(telemetryJSON, &view.Telemetry); err != nil {
			return nil, err
		}
		if (view.Telemetry == nil) != (view.TotalRXBytes == nil || view.TotalTXBytes == nil) {
			return nil, ErrInvalidSample
		}
		history = append(history, view)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return history, nil
}

// TelemetryDetailAPIVersion is the NODE_TELEMETRY_DETAIL version whose
// telemetry carries mounts and port group override receipts.
const TelemetryDetailAPIVersion = 1

// DeclaresTelemetryDetail: an AgentCapabilities snapshot declares
// NODE_TELEMETRY_DETAIL v1 or later.
func DeclaresTelemetryDetail(snapshot []byte) bool {
	return declaresCapability(snapshot, agentv1.CapabilityName_CAPABILITY_NAME_NODE_TELEMETRY_DETAIL, TelemetryDetailAPIVersion)
}

func declaresCapability(snapshot []byte, name agentv1.CapabilityName, version uint32) bool {
	var capabilities agentv1.AgentCapabilities
	if len(snapshot) == 0 || proto.Unmarshal(snapshot, &capabilities) != nil {
		return false
	}
	for _, capability := range capabilities.GetFeatures() {
		if capability.GetName() == name && capability.GetApiVersion() >= version {
			return true
		}
	}
	return false
}

func decodeStoredTelemetry(payload []byte, target **Telemetry) error {
	if len(payload) == 0 {
		*target = nil
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var telemetry Telemetry
	if err := decoder.Decode(&telemetry); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validTelemetry(&telemetry) {
		return ErrInvalidSample
	}
	*target = &telemetry
	return nil
}
