package analytics

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type realtimeRosterSource struct {
	ScopeID         string `json:"scope_id"`
	TenantID        string `json:"tenant_id"`
	SiteID          string `json:"site_id"`
	Host            string `json:"host"`
	ListenPort      uint16 `json:"listen_port"`
	NodeID          string `json:"node_id"`
	ConfigVersionID string `json:"config_version_id"`
	Stable          bool   `json:"stable"`
}

const realtimeRosterCandidatesSQL = `SELECT state.configuration_scope_id,scope.tenant_id,node.id,version.id,
    version.canonical_snapshot,version.canonical_snapshot_sha256,
    node.created_at,node.updated_at,state.updated_at,version.published_at
FROM node_config_state state
JOIN nodes node ON node.id=state.node_id
JOIN access_scopes scope ON scope.id=state.configuration_scope_id AND scope.kind='tenant'
JOIN config_versions version ON version.id=state.current_config_version_id AND version.configuration_scope_id=scope.id
WHERE node.admin_state IN ('active','draining') AND version.status IN ('releasable','superseded')
ORDER BY state.configuration_scope_id,node.id LIMIT 10001`

func (store *PostgresRealtimeCoverageStore) captureRealtimeRoster(ctx context.Context, start time.Time) error {
	start = start.UTC().Truncate(time.Hour)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM analytics_realtime_source_rosters_247 WHERE window_start=$1)`, start).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return tx.Commit(ctx)
	}
	rows, err := tx.Query(ctx, realtimeRosterCandidatesSQL)
	if err != nil {
		return err
	}
	sources := []realtimeRosterSource{}
	for rows.Next() {
		var scopeID, tenantID, nodeID, configID uuid.UUID
		var raw, digest []byte
		var created, updated, stateUpdated, published time.Time
		if err = rows.Scan(&scopeID, &tenantID, &nodeID, &configID, &raw, &digest, &created, &updated, &stateUpdated, &published); err != nil {
			rows.Close()
			return err
		}
		listeners, err := nodeidentity.PublishedTelemetryListeners(raw, digest, scopeID, tenantID, configID)
		if err != nil {
			rows.Close()
			return ErrRealtimeCoverageConflict
		}
		for _, listener := range listeners {
			sources = append(sources, realtimeRosterSource{ScopeID: scopeID.String(), TenantID: tenantID.String(), NodeID: nodeID.String(),
				ConfigVersionID: configID.String(), SiteID: listener.SiteID, Host: listener.Domain, ListenPort: listener.ListenPort,
				Stable: !created.After(start) && !updated.After(start) && !stateUpdated.After(start) && !published.After(start)})
			if len(sources) > 10000 {
				rows.Close()
				return ErrRealtimeCoverageConflict
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// An empty roster is recorded as [] so an hour without listeners can be
	// proven empty; candidates against it still conflict below.
	sort.Slice(sources, func(i, j int) bool {
		a, b := sources[i], sources[j]
		if a.ScopeID != b.ScopeID {
			return a.ScopeID < b.ScopeID
		}
		if a.SiteID != b.SiteID {
			return a.SiteID < b.SiteID
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.ListenPort != b.ListenPort {
			return a.ListenPort < b.ListenPort
		}
		return a.NodeID < b.NodeID
	})
	encoded, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO analytics_realtime_source_rosters_247(window_start,sources,evidence_sha256,captured_at)
        VALUES($1,$2::jsonb,sha256(convert_to(($2::jsonb)::text,'UTF8')),clock_timestamp()) ON CONFLICT(window_start) DO NOTHING`, start, encoded)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func realtimeRosterForCandidate(ctx context.Context, tx pgx.Tx, candidate RealtimeCoverageCandidateV1) ([]RealtimeCoverageSourceV1, error) {
	var raw []byte
	var validDigest bool
	if err := tx.QueryRow(ctx, `SELECT sources,evidence_sha256=sha256(convert_to(sources::text,'UTF8')) FROM analytics_realtime_source_rosters_247 WHERE window_start=$1`, candidate.WindowStart).Scan(&raw, &validDigest); err != nil {
		return nil, err
	}
	var roster []realtimeRosterSource
	if !validDigest || json.Unmarshal(raw, &roster) != nil || len(roster) == 0 || len(roster) > 10000 {
		return nil, ErrRealtimeCoverageConflict
	}
	sources := []RealtimeCoverageSourceV1{}
	for _, source := range roster {
		if source.ScopeID != candidate.ScopeID || source.TenantID != candidate.TenantID || source.SiteID != candidate.SiteID || source.Host != candidate.Host || source.ListenPort != candidate.ListenPort {
			continue
		}
		if !source.Stable {
			return nil, ErrRealtimeCoverageConflict
		}
		var stillStable bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_config_state state JOIN nodes node ON node.id=state.node_id
            WHERE state.node_id=$1::uuid AND state.configuration_scope_id=$2::uuid AND state.current_config_version_id=$3::uuid
            AND state.updated_at<=$4 AND node.updated_at<=$4 AND node.admin_state IN ('active','draining'))`, source.NodeID, source.ScopeID, source.ConfigVersionID, candidate.WindowStart).Scan(&stillStable); err != nil {
			return nil, err
		}
		if !stillStable {
			return nil, ErrRealtimeCoverageConflict
		}
		sources = append(sources, RealtimeCoverageSourceV1{NodeID: source.NodeID, ConfigVersionID: source.ConfigVersionID})
	}
	if len(sources) == 0 {
		return nil, ErrRealtimeCoverageConflict
	}
	return sources, nil
}
