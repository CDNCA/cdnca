package nodemetrics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, ErrInvalidConfiguration
	}
	return &PostgresStore{pool: pool}, nil
}

func (store *PostgresStore) Put(ctx context.Context, sample Sample) (bool, error) {
	if store == nil || store.pool == nil || ctx == nil || !validStoreSample(sample) {
		return false, ErrInvalidSample
	}
	replayed := false
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var cpuPercent, memoryUsed, memoryTotal, activeConnections, rxBPS, txBPS any
		var telemetryJSON, totalRXBytes, totalTXBytes any
		var activeRevision, probePort, healthy, probeSucceeded, consecutiveFailures, consecutiveSuccesses any
		var probesTotal, probeFailuresTotal, recovered, recoveryNotified, rolledBack, recoveryReason any
		if sample.Kind == RecordMetric {
			activeRevision, probePort = sample.ActiveConfigRevision, sample.ProbePort
			healthy, probeSucceeded = sample.Healthy, sample.ProbeSucceeded
			consecutiveFailures, consecutiveSuccesses = sample.ConsecutiveFailures, sample.ConsecutiveSuccesses
			probesTotal, probeFailuresTotal = sample.ProbesTotal, sample.ProbeFailuresTotal
			recovered, recoveryNotified, rolledBack = sample.Recovered, sample.RecoveryNotified, sample.RolledBack
		} else if sample.Kind == RecordRecoveryNotification {
			recoveryReason = sample.RecoveryReasonCode
		}
		if sample.Known {
			cpuPercent, memoryUsed, memoryTotal = sample.CPUPercent, sample.MemoryUsedBytes, sample.MemoryTotalBytes
			activeConnections, rxBPS, txBPS = sample.ActiveConnections, sample.RXBandwidthBPS, sample.TXBandwidthBPS
			if sample.Telemetry != nil {
				var marshalErr error
				telemetryJSON, marshalErr = json.Marshal(sample.Telemetry)
				if marshalErr != nil {
					return marshalErr
				}
				totalRXBytes, totalTXBytes = sample.Telemetry.TotalRXBytes, sample.Telemetry.TotalTXBytes
			}
		}
		result, err := tx.Exec(ctx, `
			INSERT INTO node_metric_samples (
				event_id, request_id, node_id, schema_version, config_revision, publication_sequence,
				observed_at, record_kind, active_config_revision, probe_port, healthy, probe_succeeded,
				consecutive_failures, consecutive_successes, probes_total, probe_failures_total,
				recovered, recovery_notified, rolled_back, recovery_reason_code,
				metrics_known, cpu_percent, memory_used_bytes, memory_total_bytes,
				active_connections, rx_bandwidth_bps, tx_bandwidth_bps, telemetry_json,
				total_rx_bytes, total_tx_bytes, puback_stream, puback_sequence,
				consumer_durable, consumer_sequence, num_delivered, wire_sha256
			) VALUES (
				$1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11,
				$12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24,
				$25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36
			) ON CONFLICT DO NOTHING`,
			sample.EventID, sample.RequestID, sample.NodeID, sample.SchemaVersion, sample.ConfigRevision,
			sample.PublicationSequence, sample.ObservedAt, sample.Kind, activeRevision, probePort, healthy,
			probeSucceeded, consecutiveFailures, consecutiveSuccesses, probesTotal, probeFailuresTotal,
			recovered, recoveryNotified, rolledBack, recoveryReason, sample.Known, cpuPercent, memoryUsed, memoryTotal,
			activeConnections, rxBPS, txBPS, telemetryJSON, totalRXBytes, totalTXBytes,
			sample.PubAckStream, sample.PubAckSequence, sample.ConsumerDurable,
			sample.ConsumerSequence, sample.NumDelivered, sample.WireSHA256[:])
		if err != nil {
			var postgresError *pgconn.PgError
			if errors.As(err, &postgresError) && postgresError.Code == "P1501" {
				return ErrConflict
			}
			return err
		}
		if result.RowsAffected() == 1 {
			return nil
		}
		var existing []byte
		var pubAckStream, consumerDurable string
		var pubAckSequence uint64
		err = tx.QueryRow(ctx, `
			SELECT wire_sha256, puback_stream, puback_sequence, consumer_durable
			FROM node_metric_samples
			WHERE event_id=$1::uuid OR (node_id=$2::uuid AND publication_sequence=$3)
			   OR (puback_stream=$4 AND puback_sequence=$5)
			ORDER BY event_id=$1::uuid DESC LIMIT 1`, sample.EventID, sample.NodeID,
			sample.PublicationSequence, sample.PubAckStream, sample.PubAckSequence).Scan(
			&existing, &pubAckStream, &pubAckSequence, &consumerDurable)
		if err != nil || !bytes.Equal(existing, sample.WireSHA256[:]) ||
			pubAckStream != sample.PubAckStream || pubAckSequence != sample.PubAckSequence ||
			consumerDurable != sample.ConsumerDurable {
			return ErrConflict
		}
		replayed = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("store node metric sample: %w", err)
	}
	return replayed, nil
}

func validStoreSample(sample Sample) bool {
	if !canonicalUUID(sample.EventID) || !canonicalUUID(sample.RequestID) || !canonicalUUID(sample.NodeID) ||
		sample.SchemaVersion != 1 || (sample.ConfigRevision == 0) != (sample.Kind == RecordHostMetric) || sample.ConfigRevision > math.MaxInt64 ||
		sample.PublicationSequence == 0 || sample.PublicationSequence > math.MaxInt64 || sample.ObservedAt.IsZero() ||
		sample.PubAckStream != NodeMonitoringStatusStream || sample.PubAckSequence == 0 ||
		sample.PubAckSequence > math.MaxInt64 || sample.ConsumerDurable != DefaultConsumerDurable ||
		sample.ConsumerSequence == 0 || sample.ConsumerSequence > math.MaxInt64 ||
		sample.NumDelivered == 0 || sample.NumDelivered > math.MaxInt64 {
		return false
	}
	if sample.Kind == RecordRecoveryNotification {
		return sample.RecoveryReasonCode == RecoveryReasonProbeRecovered && !sample.Known &&
			sample.ActiveConfigRevision == 0 && sample.ProbePort == 0 && !sample.Healthy &&
			!sample.ProbeSucceeded && sample.ConsecutiveFailures == 0 && sample.ConsecutiveSuccesses == 0 &&
			sample.ProbesTotal == 0 && sample.ProbeFailuresTotal == 0 && !sample.Recovered &&
			!sample.RecoveryNotified && !sample.RolledBack && sample.CPUPercent == 0 &&
			sample.MemoryUsedBytes == 0 && sample.MemoryTotalBytes == 0 && sample.ActiveConnections == 0 &&
			sample.RXBandwidthBPS == 0 && sample.TXBandwidthBPS == 0 && sample.Telemetry == nil
	}
	if sample.Kind == RecordHostMetric {
		if !sample.Known || sample.ActiveConfigRevision != 0 || sample.AppliedConfigRevision > math.MaxInt64 || sample.ProbePort != 0 || sample.Healthy || sample.ProbeSucceeded ||
			sample.ConsecutiveFailures != 0 || sample.ConsecutiveSuccesses != 0 || sample.ProbesTotal != 0 ||
			sample.ProbeFailuresTotal != 0 || sample.Recovered || sample.RecoveryNotified || sample.RolledBack || sample.RecoveryReasonCode != "" {
			return false
		}
	} else if sample.Kind != RecordMetric || sample.RecoveryReasonCode != "" || sample.ActiveConfigRevision == 0 ||
		sample.ActiveConfigRevision > math.MaxInt64 || sample.ProbePort == 0 ||
		sample.ConsecutiveFailures > 20 || sample.ConsecutiveSuccesses > 20 ||
		sample.ProbeFailuresTotal > sample.ProbesTotal ||
		sample.ConsecutiveFailures > 0 && sample.ConsecutiveSuccesses > 0 ||
		sample.Recovered && (!sample.Healthy || !sample.ProbeSucceeded) ||
		sample.RolledBack && (sample.ActiveConfigRevision >= sample.ConfigRevision || sample.ProbeSucceeded) {
		return false
	}
	if !sample.Known {
		return sample.Telemetry == nil && sample.CPUPercent == 0 && sample.MemoryUsedBytes == 0 && sample.MemoryTotalBytes == 0 &&
			sample.ActiveConnections == 0 && sample.RXBandwidthBPS == 0 && sample.TXBandwidthBPS == 0
	}
	return !math.IsNaN(sample.CPUPercent) && !math.IsInf(sample.CPUPercent, 0) &&
		sample.CPUPercent >= 0 && sample.CPUPercent <= 100 && sample.MemoryTotalBytes > 0 &&
		sample.MemoryTotalBytes <= math.MaxInt64 && sample.MemoryUsedBytes <= sample.MemoryTotalBytes &&
		sample.ActiveConnections <= math.MaxInt64 && sample.RXBandwidthBPS <= math.MaxInt64 &&
		sample.TXBandwidthBPS <= math.MaxInt64 && validTelemetry(sample.Telemetry)
}

func validTelemetry(telemetry *Telemetry) bool {
	if telemetry == nil {
		return true
	}
	if !validNetworkSelection(telemetry) || telemetry.SchemaVersion != 1 || telemetry.TotalRXBytes > math.MaxInt64 || telemetry.TotalTXBytes > math.MaxInt64 ||
		len(telemetry.NetworkInterfaces) > 128 || len(telemetry.Disks) > 128 || !validDDoSDrops(telemetry.DDoSDrops) || !validXDPStatus(telemetry.XDP) ||
		!validSiteDrop(telemetry.SiteDrop) || !validDDoSProtection(telemetry.DDoSProtection) ||
		!validMounts(telemetry.Mounts) || !validPortGroupOverrides(telemetry.PortGroupOverrides) || !validStorage(telemetry.Storage) {
		return false
	}
	previousName := ""
	for _, network := range telemetry.NetworkInterfaces {
		if network.Name == "" || len(network.Name) > 128 || previousName >= network.Name ||
			network.RXBytes > math.MaxInt64 || network.TXBytes > math.MaxInt64 ||
			network.RXBandwidthBPS > math.MaxInt64 || network.TXBandwidthBPS > math.MaxInt64 {
			return false
		}
		previousName = network.Name
	}
	if telemetry.SystemLoad != nil {
		if telemetry.SystemLoad.TotalProcesses == 0 || telemetry.SystemLoad.RunningProcesses > telemetry.SystemLoad.TotalProcesses {
			return false
		}
		for _, value := range []float64{telemetry.SystemLoad.OneMinute, telemetry.SystemLoad.FiveMinutes, telemetry.SystemLoad.FifteenMinutes} {
			if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1e9 {
				return false
			}
		}
	}
	previousPath := ""
	for _, disk := range telemetry.Disks {
		if disk.Path == "" || len(disk.Path) > 4096 || disk.Path[0] != '/' || previousPath >= disk.Path ||
			disk.TotalBytes > math.MaxInt64 || disk.UsedBytes > disk.TotalBytes || disk.TotalInodes > math.MaxInt64 ||
			disk.UsedInodes > disk.TotalInodes || math.IsNaN(disk.SpacePercent) || math.IsInf(disk.SpacePercent, 0) ||
			disk.SpacePercent < 0 || disk.SpacePercent > 100 || math.IsNaN(disk.InodePercent) ||
			math.IsInf(disk.InodePercent, 0) || disk.InodePercent < 0 || disk.InodePercent > 100 {
			return false
		}
		previousPath = disk.Path
	}
	return true
}
