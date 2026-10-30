package nodemetrics

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	// MaxMonitoringHistoryWindow bounds one node's probe range scan.
	MaxMonitoringHistoryWindow = 7 * 24 * time.Hour
	MaxMonitoringHistoryLimit  = 100
	MaxMonitoringHistoryPage   = 1000
)

// MonitoringHistoryPage is one node's local availability log: every row is
// an actual Agent-local probe report, exactly one check that fails when that
// probe failed. Carrier checkpoints are the dnspup log
// (DNSPupMonitoringHistory).
type MonitoringHistoryPage struct {
	SchemaVersion int                     `json:"schema_version"`
	NodeID        uuid.UUID               `json:"node_id"`
	From          time.Time               `json:"from"`
	To            time.Time               `json:"to"`
	Page          int                     `json:"page"`
	Limit         int                     `json:"limit"`
	Total         int64                   `json:"total"`
	Items         []MonitoringHistoryItem `json:"items"`
}

type MonitoringHistoryItem struct {
	ObservedAt           time.Time `json:"observed_at"`
	ConfigRevision       uint64    `json:"config_revision"`
	ActiveConfigRevision uint64    `json:"active_config_revision"`
	ProbePort            uint16    `json:"probe_port"`
	ProbeSucceeded       bool      `json:"probe_succeeded"`
	Healthy              bool      `json:"healthy"`
	FailedChecks         int       `json:"failed_checks"`
	TotalChecks          int       `json:"total_checks"`
}

func (reader *PostgresReader) MonitoringHistory(
	ctx context.Context, scopeID, nodeID uuid.UUID, from, to time.Time, page, limit int,
) (MonitoringHistoryPage, error) {
	if reader == nil || reader.pool == nil || ctx == nil || scopeID == uuid.Nil || nodeID == uuid.Nil ||
		from.IsZero() || to.IsZero() || !from.Before(to) || to.Sub(from) > MaxMonitoringHistoryWindow ||
		page < 1 || page > MaxMonitoringHistoryPage || limit < 1 || limit > MaxMonitoringHistoryLimit {
		return MonitoringHistoryPage{}, ErrInvalidConfiguration
	}
	result := MonitoringHistoryPage{SchemaVersion: 1, NodeID: nodeID, From: from.UTC(), To: to.UTC(),
		Page: page, Limit: limit, Items: make([]MonitoringHistoryItem, 0, limit)}
	tx, err := reader.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return MonitoringHistoryPage{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id=$1 AND scope_id=$2)`,
		nodeID, scopeID).Scan(&exists); err != nil {
		return MonitoringHistoryPage{}, err
	}
	if !exists {
		return MonitoringHistoryPage{}, ErrNotFound
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM node_metric_samples
		WHERE node_id=$1 AND record_kind='metric' AND observed_at>=$2 AND observed_at<=$3`,
		nodeID, result.From, result.To).Scan(&result.Total); err != nil {
		return MonitoringHistoryPage{}, err
	}
	rows, err := tx.Query(ctx, `SELECT observed_at,config_revision,active_config_revision,probe_port,
			probe_succeeded,healthy
		FROM node_metric_samples
		WHERE node_id=$1 AND record_kind='metric' AND observed_at>=$2 AND observed_at<=$3
		ORDER BY observed_at DESC,publication_sequence DESC
		LIMIT $4 OFFSET $5`, nodeID, result.From, result.To, limit, (page-1)*limit)
	if err != nil {
		return MonitoringHistoryPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item MonitoringHistoryItem
		if err := rows.Scan(&item.ObservedAt, &item.ConfigRevision, &item.ActiveConfigRevision, &item.ProbePort,
			&item.ProbeSucceeded, &item.Healthy); err != nil {
			return MonitoringHistoryPage{}, err
		}
		if item.ObservedAt.IsZero() || item.ConfigRevision == 0 || item.ActiveConfigRevision == 0 || item.ProbePort == 0 {
			return MonitoringHistoryPage{}, ErrInvalidSample
		}
		item.ObservedAt = item.ObservedAt.UTC()
		item.TotalChecks = 1
		if !item.ProbeSucceeded {
			item.FailedChecks = 1
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return MonitoringHistoryPage{}, err
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return MonitoringHistoryPage{}, err
	}
	return result, nil
}

// DNSPupHistoryCheckpoint is one dnspup checkpoint's answer of a round.
type DNSPupHistoryCheckpoint struct {
	ID        string `json:"id"`
	Group     string `json:"group"`
	Carrier   string `json:"carrier,omitempty"`
	Region    string `json:"region,omitempty"`
	Location  string `json:"location,omitempty"`
	OK        bool   `json:"ok"`
	LatencyMS int    `json:"latency_ms,omitempty"`
}

// DNSPupHistoryItem is one probed node address in one dnspup round
// (internal/nodednspupprobe; table node_dnspup_probe_results). With a group
// filter only that group's checkpoints are counted.
type DNSPupHistoryItem struct {
	ObservedAt   time.Time                 `json:"observed_at"`
	Address      string                    `json:"address"`
	Port         uint16                    `json:"port"`
	Failed       bool                      `json:"failed"`
	FailedChecks int                       `json:"failed_checks"`
	TotalChecks  int                       `json:"total_checks"`
	Checkpoints  []DNSPupHistoryCheckpoint `json:"checkpoints"`
}

// DNSPupHistoryPage is one node's dnspup availability log.
type DNSPupHistoryPage struct {
	SchemaVersion int                 `json:"schema_version"`
	Source        string              `json:"source"`
	NodeID        uuid.UUID           `json:"node_id"`
	Group         string              `json:"group"`
	From          time.Time           `json:"from"`
	To            time.Time           `json:"to"`
	Page          int                 `json:"page"`
	Limit         int                 `json:"limit"`
	Total         int64               `json:"total"`
	Items         []DNSPupHistoryItem `json:"items"`
}

// DNSPupHistoryGroups are the group filters ("" = all).
var DNSPupHistoryGroups = []string{"", "domestic", "telecom", "unicom", "mobile", "overseas"}

// DNSPupMonitoringHistory pages one node's dnspup rounds, newest first.
func (reader *PostgresReader) DNSPupMonitoringHistory(
	ctx context.Context, scopeID, nodeID uuid.UUID, group string, from, to time.Time, page, limit int,
) (DNSPupHistoryPage, error) {
	if reader == nil || reader.pool == nil || ctx == nil || scopeID == uuid.Nil || nodeID == uuid.Nil ||
		from.IsZero() || to.IsZero() || !from.Before(to) || to.Sub(from) > MaxMonitoringHistoryWindow ||
		page < 1 || page > MaxMonitoringHistoryPage || limit < 1 || limit > MaxMonitoringHistoryLimit ||
		!slices.Contains(DNSPupHistoryGroups, group) {
		return DNSPupHistoryPage{}, ErrInvalidConfiguration
	}
	result := DNSPupHistoryPage{SchemaVersion: 1, Source: "dnspup", NodeID: nodeID, Group: group, From: from.UTC(),
		To: to.UTC(), Page: page, Limit: limit, Items: make([]DNSPupHistoryItem, 0, limit)}
	tx, err := reader.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return DNSPupHistoryPage{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id=$1 AND scope_id=$2)`,
		nodeID, scopeID).Scan(&exists); err != nil {
		return DNSPupHistoryPage{}, err
	}
	if !exists {
		return DNSPupHistoryPage{}, ErrNotFound
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM node_dnspup_probe_results
		WHERE node_id=$1 AND observed_at>=$2 AND observed_at<=$3`, nodeID, result.From, result.To).Scan(&result.Total); err != nil {
		return DNSPupHistoryPage{}, err
	}
	rows, err := tx.Query(ctx, `SELECT observed_at,host(address),port,failed,failed_checks,total_checks,checkpoints
		FROM node_dnspup_probe_results WHERE node_id=$1 AND observed_at>=$2 AND observed_at<=$3
		ORDER BY observed_at DESC,address,port LIMIT $4 OFFSET $5`, nodeID, result.From, result.To, limit, (page-1)*limit)
	if err != nil {
		return DNSPupHistoryPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item DNSPupHistoryItem
		var port int32
		var raw []byte
		if err := rows.Scan(&item.ObservedAt, &item.Address, &port, &item.Failed, &item.FailedChecks, &item.TotalChecks,
			&raw); err != nil {
			return DNSPupHistoryPage{}, err
		}
		if err := json.Unmarshal(raw, &item.Checkpoints); err != nil || port < 1 || port > 65535 {
			return DNSPupHistoryPage{}, ErrInvalidSample
		}
		item.ObservedAt, item.Port = item.ObservedAt.UTC(), uint16(port)
		if item.Checkpoints == nil {
			item.Checkpoints = []DNSPupHistoryCheckpoint{}
		}
		if group != "" {
			kept := item.Checkpoints[:0]
			item.FailedChecks, item.TotalChecks = 0, 0
			for _, checkpoint := range item.Checkpoints {
				if checkpoint.Group == group || group == "domestic" && checkpoint.Group != "overseas" {
					kept = append(kept, checkpoint)
					item.TotalChecks++
					if !checkpoint.OK {
						item.FailedChecks++
					}
				}
			}
			item.Checkpoints = kept
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return DNSPupHistoryPage{}, err
	}
	rows.Close()
	return result, tx.Commit(ctx)
}

// PeerHistoryCheckpoint is one vote of a peer probe round: the controller
// (id "controller") or a peer node.
type PeerHistoryCheckpoint struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Address   string   `json:"address,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	OK        bool     `json:"ok"`
	LatencyMS int      `json:"latency_ms,omitempty"`
}

// PeerHistoryItem is one probed node address in one peer probe round
// (internal/nodeprobe; table node_peer_probe_results). FailedChecks and
// TotalChecks include the controller.
type PeerHistoryItem struct {
	ObservedAt   time.Time               `json:"observed_at"`
	Address      string                  `json:"address"`
	Port         uint16                  `json:"port"`
	Failed       bool                    `json:"failed"`
	ControllerOK *bool                   `json:"controller_ok"`
	FailedChecks int                     `json:"failed_checks"`
	TotalChecks  int                     `json:"total_checks"`
	Checkpoints  []PeerHistoryCheckpoint `json:"checkpoints"`
}

// PeerHistoryPage is one node's peer probe availability log (source=peer).
type PeerHistoryPage struct {
	SchemaVersion int               `json:"schema_version"`
	Source        string            `json:"source"`
	NodeID        uuid.UUID         `json:"node_id"`
	From          time.Time         `json:"from"`
	To            time.Time         `json:"to"`
	Page          int               `json:"page"`
	Limit         int               `json:"limit"`
	Total         int64             `json:"total"`
	Items         []PeerHistoryItem `json:"items"`
}

// PeerMonitoringHistory pages one node's peer probe rounds, newest first.
func (reader *PostgresReader) PeerMonitoringHistory(
	ctx context.Context, scopeID, nodeID uuid.UUID, from, to time.Time, page, limit int,
) (PeerHistoryPage, error) {
	if reader == nil || reader.pool == nil || ctx == nil || scopeID == uuid.Nil || nodeID == uuid.Nil ||
		from.IsZero() || to.IsZero() || !from.Before(to) || to.Sub(from) > MaxMonitoringHistoryWindow ||
		page < 1 || page > MaxMonitoringHistoryPage || limit < 1 || limit > MaxMonitoringHistoryLimit {
		return PeerHistoryPage{}, ErrInvalidConfiguration
	}
	result := PeerHistoryPage{SchemaVersion: 1, Source: "peer", NodeID: nodeID, From: from.UTC(), To: to.UTC(),
		Page: page, Limit: limit, Items: make([]PeerHistoryItem, 0, limit)}
	tx, err := reader.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return PeerHistoryPage{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id=$1 AND scope_id=$2)`,
		nodeID, scopeID).Scan(&exists); err != nil {
		return PeerHistoryPage{}, err
	}
	if !exists {
		return PeerHistoryPage{}, ErrNotFound
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM node_peer_probe_results
		WHERE node_id=$1 AND observed_at>=$2 AND observed_at<=$3`, nodeID, result.From, result.To).Scan(&result.Total); err != nil {
		return PeerHistoryPage{}, err
	}
	rows, err := tx.Query(ctx, `SELECT observed_at,host(address),port,failed,controller_ok,failed_checks,total_checks,checkpoints
		FROM node_peer_probe_results WHERE node_id=$1 AND observed_at>=$2 AND observed_at<=$3
		ORDER BY observed_at DESC,address,port LIMIT $4 OFFSET $5`, nodeID, result.From, result.To, limit, (page-1)*limit)
	if err != nil {
		return PeerHistoryPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item PeerHistoryItem
		var port int32
		var raw []byte
		if err := rows.Scan(&item.ObservedAt, &item.Address, &port, &item.Failed, &item.ControllerOK, &item.FailedChecks,
			&item.TotalChecks, &raw); err != nil {
			return PeerHistoryPage{}, err
		}
		if err := json.Unmarshal(raw, &item.Checkpoints); err != nil || port < 1 || port > 65535 {
			return PeerHistoryPage{}, ErrInvalidSample
		}
		item.ObservedAt, item.Port = item.ObservedAt.UTC(), uint16(port)
		if item.Checkpoints == nil {
			item.Checkpoints = []PeerHistoryCheckpoint{}
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return PeerHistoryPage{}, err
	}
	rows.Close()
	return result, tx.Commit(ctx)
}
