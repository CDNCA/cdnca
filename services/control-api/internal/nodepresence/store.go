package nodepresence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool     *pgxpool.Pool
	auditor  *audit.Log
	leaseTTL time.Duration
	now      func() time.Time
}

type activeDeploymentProjection struct {
	DeploymentID                 string                          `json:"deployment_id"`
	Attempt                      uint32                          `json:"attempt"`
	ConfigVersion                string                          `json:"config_version_id"`
	State                        string                          `json:"state"`
	ObservedActiveConfigIdentity *activeConfigIdentityProjection `json:"observed_active_config_identity,omitempty"`
}

type activeConfigIdentityProjection struct {
	Schema         int32  `json:"schema"`
	ConfigVersion  string `json:"config_version_id"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

func NewStore(pool *pgxpool.Pool, leaseTTL time.Duration) (*Store, error) {
	if pool == nil || leaseTTL <= 0 {
		return nil, fmt.Errorf("node presence store requires a pool and positive lease TTL")
	}
	return &Store{pool: pool, auditor: audit.New(pool), leaseTTL: leaseTTL, now: time.Now}, nil
}

func (s *Store) Project(ctx context.Context, envelope Envelope) (ProjectionResult, error) {
	if envelope.NodeID == uuid.Nil || envelope.Heartbeat == nil || envelope.Heartbeat.Event == nil {
		return ProjectionResult{}, fmt.Errorf("%w: incomplete projection", ErrInvalidHeartbeat)
	}
	heartbeat := envelope.Heartbeat
	if err := validateHeartbeatActiveIdentities(heartbeat); err != nil {
		return ProjectionResult{}, err
	}
	scoped, err := normalizeScopedConfigIdentities(heartbeat)
	if err != nil {
		return ProjectionResult{}, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	epoch := int64(heartbeat.SessionEpoch)
	sequence := int64(heartbeat.HeartbeatSequence)
	eventID, _ := uuid.Parse(heartbeat.Event.EventId)
	requestID, _ := uuid.Parse(heartbeat.Event.RequestId)

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ProjectionResult{}, fmt.Errorf("begin heartbeat projection: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var claimed []uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE((SELECT array_agg(state.configuration_scope_id ORDER BY state.configuration_scope_id)
			FROM node_config_state state WHERE state.node_id = node.id), '{}')
		FROM nodes node WHERE node.id = $1`, envelope.NodeID).Scan(&claimed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ProjectionResult{}, ErrNodeNotFound
		}
		return ProjectionResult{}, fmt.Errorf("read heartbeat node: %w", err)
	}
	// Node-side artifacts (artifact sets/segments) are delivered in the
	// platform scope, which is never a node's configuration scope: an agent
	// result for it says nothing about configuration and must not reject the
	// whole heartbeat (it would keep the node offline forever).
	var platformScopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScopeID); err != nil &&
		!errors.Is(err, pgx.ErrNoRows) {
		return ProjectionResult{}, fmt.Errorf("read platform scope: %w", err)
	}
	scoped = slices.DeleteFunc(scoped, func(entry normalizedScopedConfigIdentity) bool {
		return entry.ScopeID == platformScopeID && entry.Current == nil && !slices.Contains(claimed, entry.ScopeID)
	})
	// The legacy identity fields describe the node's only scope: the one it
	// reports, or for an agent without scoped identities the one it claimed.
	var configurationScopeID *uuid.UUID
	switch {
	case len(scoped) == 1:
		configurationScopeID = &scoped[0].ScopeID
	case len(scoped) == 0 && len(claimed) == 1:
		configurationScopeID = &claimed[0]
	}
	for _, entry := range scoped {
		if !slices.Contains(claimed, entry.ScopeID) {
			return ProjectionResult{}, fmt.Errorf("%w: scoped identity for an unclaimed scope", ErrInvalidHeartbeat)
		}
		for _, identity := range []*normalizedActiveConfigIdentity{entry.Current, entry.Previous} {
			if identity == nil {
				continue
			}
			if err := requireBoundIdentityArtifact(ctx, tx, envelope.NodeID, entry.ScopeID, identity, nil, 0,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_UNSPECIFIED); err != nil {
				return ProjectionResult{}, err
			}
		}
	}
	if err := validateHeartbeatIdentityBindings(ctx, tx, envelope.NodeID, configurationScopeID, heartbeat); err != nil {
		return ProjectionResult{}, err
	}

	var currentEpoch, currentSequence int64
	var currentEventID, currentRequestID uuid.UUID
	var currentDigest []byte
	var currentStatus string
	var currentAgentVersion *string
	var currentProjectedAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT session_epoch, heartbeat_sequence, event_id, request_id, payload_digest, status, projected_at, agent_version
		FROM node_presence
		WHERE node_id = $1
		FOR UPDATE`, envelope.NodeID).Scan(
		&currentEpoch, &currentSequence, &currentEventID, &currentRequestID,
		&currentDigest, &currentStatus, &currentProjectedAt, &currentAgentVersion,
	)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ProjectionResult{}, fmt.Errorf("lock node presence: %w", err)
	}
	presenceMissing := errors.Is(err, pgx.ErrNoRows)
	if err == nil {
		comparison := compareVersion(epoch, sequence, currentEpoch, currentSequence)
		if comparison < 0 {
			if err := tx.Commit(ctx); err != nil {
				return ProjectionResult{}, fmt.Errorf("commit stale heartbeat: %w", err)
			}
			return projectionResult(envelope.NodeID, currentEpoch, currentSequence, currentEventID, currentRequestID, currentDigest,
				currentProjectedAt, currentStatus, OutcomeStale, false, s.leaseTTL, currentAgentVersion), nil
		}
		if comparison == 0 {
			if currentEventID != eventID || !bytes.Equal(currentDigest, envelope.Digest[:]) {
				return ProjectionResult{}, ErrProjectionConflict
			}
			refresh := now.Before(currentProjectedAt.Add(s.leaseTTL))
			if err := tx.Commit(ctx); err != nil {
				return ProjectionResult{}, fmt.Errorf("commit duplicate heartbeat: %w", err)
			}
			return projectionResult(envelope.NodeID, currentEpoch, currentSequence, currentEventID, currentRequestID, currentDigest,
				currentProjectedAt, currentStatus, OutcomeDuplicate, refresh, s.leaseTTL, currentAgentVersion), nil
		}
	}

	activeDeployments, err := marshalActiveDeployments(heartbeat.ActiveDeployments)
	if err != nil {
		return ProjectionResult{}, err
	}
	currentConfig, err := optionalUUID(heartbeat.CurrentConfigVersionId)
	if err != nil {
		return ProjectionResult{}, err
	}
	previousConfig, err := optionalUUID(heartbeat.PreviousConfigVersionId)
	if err != nil {
		return ProjectionResult{}, err
	}
	loadedConfig, err := optionalUUID(heartbeat.Runtime.LoadedConfigVersionId)
	if err != nil {
		return ProjectionResult{}, err
	}
	openrestyState := runtimeState(heartbeat.Runtime.OpenrestyState)
	firewallState := runtimeState(heartbeat.Runtime.FirewallState)
	marketProbeRole := MarketProbeRole(heartbeat.Runtime.MarketProbe)
	nativeRuntime := nativeRuntimeColumns(heartbeat.Runtime.NativeRuntime)
	resources := heartbeat.Resources
	agentVersion := cloneString(heartbeat.AgentVersion)
	var identityAPIVersion *int32
	if heartbeat.ActiveConfigIdentityCapability != nil {
		value := int32(heartbeat.ActiveConfigIdentityCapability.ApiVersion)
		identityAPIVersion = &value
	}
	currentIdentity, _ := normalizeActiveConfigIdentity(heartbeat.CurrentConfigIdentity, heartbeat.CurrentConfigVersionId)
	previousIdentity, _ := normalizeActiveConfigIdentity(heartbeat.PreviousConfigIdentity, heartbeat.PreviousConfigVersionId)
	loadedIdentity, _ := normalizeActiveConfigIdentity(heartbeat.Runtime.LoadedConfigIdentity, heartbeat.Runtime.LoadedConfigVersionId)

	if presenceMissing {
		_, err = tx.Exec(ctx, `
			INSERT INTO node_presence (
				node_id, status, session_epoch, heartbeat_sequence, event_id, request_id,
				payload_digest, occurred_at, projected_at, last_seen_at, agent_version,
				confirmed_session_epoch, confirmed_heartbeat_sequence,
				confirmed_event_id, confirmed_request_id, confirmed_payload_digest, confirmed_agent_version, online_since, offline_since,
				current_config_version_id, previous_config_version_id, loaded_config_version_id,
				openresty_state, firewall_state, filesystem_total_bytes,
					filesystem_available_bytes, cache_used_bytes, active_deployments,
					active_config_identity_api_version,
					current_config_identity_schema, current_config_artifact_sha256,
					previous_config_identity_schema, previous_config_artifact_sha256,
					loaded_config_identity_schema, loaded_config_artifact_sha256,
					market_probe_role, native_runtime_state, native_runtime_release,
					native_runtime_previous_release, native_runtime_error_code, revision, updated_at
				) VALUES (
					$1, 'offline', $2, $3, $4, $5, $6, $7, $8, NULL, $9,
					NULL, NULL, NULL, NULL, NULL, NULL, NULL, $8,
					$10, $11, $12, $13, $14, $15::numeric, $16::numeric, $17::numeric, $18,
					$19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, 1, $8
				)`,
			envelope.NodeID, epoch, sequence, eventID, requestID, envelope.Digest[:],
			heartbeat.Event.OccurredTime.AsTime().UTC(), now, agentVersion,
			currentConfig, previousConfig, loadedConfig, openrestyState, firewallState,
			strconv.FormatUint(resources.FilesystemTotalBytes, 10),
			strconv.FormatUint(resources.FilesystemAvailableBytes, 10),
			strconv.FormatUint(resources.CacheUsedBytes, 10), activeDeployments,
			identityAPIVersion, identitySchema(currentIdentity), identityDigest(currentIdentity),
			identitySchema(previousIdentity), identityDigest(previousIdentity),
			identitySchema(loadedIdentity), identityDigest(loadedIdentity), marketProbeRole,
			nativeRuntime.State, nativeRuntime.Release, nativeRuntime.PreviousRelease, nativeRuntime.ErrorCode,
		)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE node_presence
			SET session_epoch = $2, heartbeat_sequence = $3,
				event_id = $4, request_id = $5, payload_digest = $6, occurred_at = $7,
				projected_at = $8, agent_version = $9,
				current_config_version_id = $10, previous_config_version_id = $11,
				loaded_config_version_id = $12, openresty_state = $13, firewall_state = $14,
				filesystem_total_bytes = $15::numeric,
				filesystem_available_bytes = $16::numeric,
					cache_used_bytes = $17::numeric, active_deployments = $18,
					active_config_identity_api_version = $19,
					current_config_identity_schema = $20, current_config_artifact_sha256 = $21,
					previous_config_identity_schema = $22, previous_config_artifact_sha256 = $23,
					loaded_config_identity_schema = $24, loaded_config_artifact_sha256 = $25,
					market_probe_role = $26, native_runtime_state = $27, native_runtime_release = $28,
					native_runtime_previous_release = $29, native_runtime_error_code = $30,
					revision = revision + 1, updated_at = $8
			WHERE node_id = $1`,
			envelope.NodeID, epoch, sequence, eventID, requestID, envelope.Digest[:],
			heartbeat.Event.OccurredTime.AsTime().UTC(), now, agentVersion,
			currentConfig, previousConfig, loadedConfig, openrestyState, firewallState,
			strconv.FormatUint(resources.FilesystemTotalBytes, 10),
			strconv.FormatUint(resources.FilesystemAvailableBytes, 10),
			strconv.FormatUint(resources.CacheUsedBytes, 10), activeDeployments,
			identityAPIVersion, identitySchema(currentIdentity), identityDigest(currentIdentity),
			identitySchema(previousIdentity), identityDigest(previousIdentity),
			identitySchema(loadedIdentity), identityDigest(loadedIdentity), marketProbeRole,
			nativeRuntime.State, nativeRuntime.Release, nativeRuntime.PreviousRelease, nativeRuntime.ErrorCode,
		)
	}
	if err != nil {
		return ProjectionResult{}, fmt.Errorf("write node presence: %w", err)
	}
	if err := replaceScopedIdentities(ctx, tx, envelope.NodeID, epoch, sequence, scoped, now); err != nil {
		return ProjectionResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ProjectionResult{}, fmt.Errorf("commit heartbeat projection: %w", err)
	}
	status := currentStatus
	if presenceMissing {
		status = StatusOffline
	}
	return projectionResult(envelope.NodeID, epoch, sequence, eventID, requestID, envelope.Digest[:], now, status,
		OutcomeAdvanced, true, s.leaseTTL, agentVersion), nil
}

func (s *Store) ConfirmOnline(ctx context.Context, projection ProjectionResult) (bool, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin online confirmation: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var scopeID uuid.UUID
	var status string
	var epoch, sequence int64
	var eventID, requestID uuid.UUID
	var digest []byte
	var projectedAt time.Time
	var confirmedEpoch, confirmedSequence *int64
	var confirmedEventID, confirmedRequestID *uuid.UUID
	var confirmedDigest []byte
	var agentVersion, confirmedAgentVersion *string
	err = tx.QueryRow(ctx, `
		SELECT nodes.scope_id, node_presence.status, node_presence.session_epoch,
		       node_presence.heartbeat_sequence, node_presence.event_id, node_presence.request_id,
		       node_presence.payload_digest, node_presence.projected_at,
		       node_presence.confirmed_session_epoch, node_presence.confirmed_heartbeat_sequence,
		       node_presence.confirmed_event_id, node_presence.confirmed_request_id,
		       node_presence.confirmed_payload_digest, node_presence.agent_version,
		       node_presence.confirmed_agent_version
		FROM node_presence
		JOIN nodes ON nodes.id = node_presence.node_id
		WHERE node_presence.node_id = $1
		FOR UPDATE OF node_presence`, projection.NodeID).Scan(
		&scopeID, &status, &epoch, &sequence, &eventID, &requestID, &digest, &projectedAt,
		&confirmedEpoch, &confirmedSequence, &confirmedEventID, &confirmedRequestID, &confirmedDigest,
		&agentVersion, &confirmedAgentVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNodeNotFound
	}
	if err != nil {
		return false, fmt.Errorf("lock online confirmation: %w", err)
	}
	if epoch != projection.SessionEpoch || sequence != projection.HeartbeatSequence || eventID != projection.EventID ||
		requestID != projection.RequestID ||
		!bytes.Equal(digest, projection.Digest[:]) || !projectedAt.Equal(projection.ProjectedAt) ||
		!equalOptionalString(agentVersion, projection.AgentVersion) {
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("commit superseded online confirmation: %w", err)
		}
		return false, nil
	}
	if status == StatusOnline && confirmedEpoch != nil && confirmedSequence != nil &&
		confirmedEventID != nil && confirmedRequestID != nil &&
		*confirmedEpoch == projection.SessionEpoch && *confirmedSequence == projection.HeartbeatSequence &&
		*confirmedEventID == projection.EventID && *confirmedRequestID == projection.RequestID &&
		bytes.Equal(confirmedDigest, projection.Digest[:]) && equalOptionalString(confirmedAgentVersion, projection.AgentVersion) {
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("commit existing online confirmation: %w", err)
		}
		return false, nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_presence
		SET status = 'online', last_seen_at = $2,
		    confirmed_session_epoch = $3, confirmed_heartbeat_sequence = $4,
		    confirmed_event_id = $5, confirmed_request_id = $6, confirmed_payload_digest = $7,
		    confirmed_agent_version = $8,
		    online_since = CASE WHEN status = 'offline' THEN $9 ELSE online_since END,
		    offline_since = NULL, revision = revision + 1, updated_at = $9
		WHERE node_id = $1`, projection.NodeID, projection.ProjectedAt,
		projection.SessionEpoch, projection.HeartbeatSequence, projection.EventID, projection.RequestID,
		projection.Digest[:], agentVersion, now); err != nil {
		return false, fmt.Errorf("confirm node online: %w", err)
	}
	transitioned := status == StatusOffline
	if transitioned {
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: "node.presence.online", ResourceType: "node",
			ResourceID: projection.NodeID.String(), RequestID: requestID.String(), Result: "success",
			Payload: map[string]any{
				"from": StatusOffline, "to": StatusOnline, "event_id": eventID.String(),
				"session_epoch": epoch, "heartbeat_sequence": sequence,
			},
		}); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit online confirmation: %w", err)
	}
	return transitioned, nil
}

func (s *Store) OfflineCandidates(ctx context.Context, cutoff time.Time, limit int) ([]OfflineCandidate, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("offline candidate limit must be positive")
	}
	rows, err := s.pool.Query(ctx, `
		SELECT node_id, confirmed_session_epoch, confirmed_heartbeat_sequence,
		       confirmed_event_id, confirmed_request_id, confirmed_payload_digest, last_seen_at
		FROM node_presence
		WHERE status = 'online' AND last_seen_at <= $1
		ORDER BY last_seen_at, node_id
		LIMIT $2`, cutoff.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("list offline candidates: %w", err)
	}
	defer rows.Close()
	result := make([]OfflineCandidate, 0, limit)
	for rows.Next() {
		var candidate OfflineCandidate
		var digest []byte
		if err := rows.Scan(&candidate.NodeID, &candidate.SessionEpoch, &candidate.HeartbeatSequence,
			&candidate.EventID, &candidate.RequestID, &digest, &candidate.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan offline candidate: %w", err)
		}
		copy(candidate.Digest[:], digest)
		candidate.LeaseExpiresAt = candidate.LastSeenAt.Add(s.leaseTTL)
		result = append(result, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate offline candidates: %w", err)
	}
	return result, nil
}

func (s *Store) MarkOffline(ctx context.Context, candidate OfflineCandidate, cutoff time.Time) (bool, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin offline transition: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var scopeID uuid.UUID
	var status string
	var epoch, sequence int64
	var lastSeen time.Time
	var eventID, requestID uuid.UUID
	var digest []byte
	err = tx.QueryRow(ctx, `
		SELECT nodes.scope_id, node_presence.status, node_presence.confirmed_session_epoch,
		       node_presence.confirmed_heartbeat_sequence, node_presence.last_seen_at,
		       node_presence.confirmed_event_id, node_presence.confirmed_request_id,
		       node_presence.confirmed_payload_digest
		FROM node_presence
		JOIN nodes ON nodes.id = node_presence.node_id
		WHERE node_presence.node_id = $1
		FOR UPDATE OF node_presence`, candidate.NodeID).Scan(
		&scopeID, &status, &epoch, &sequence, &lastSeen, &eventID, &requestID, &digest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lock offline candidate: %w", err)
	}
	if status != StatusOnline || epoch != candidate.SessionEpoch || sequence != candidate.HeartbeatSequence ||
		eventID != candidate.EventID || requestID != candidate.RequestID ||
		!bytes.Equal(digest, candidate.Digest[:]) ||
		!lastSeen.Add(s.leaseTTL).Equal(candidate.LeaseExpiresAt) ||
		candidate.LeaseExpiresAt.After(now) || lastSeen.After(cutoff.UTC()) {
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("commit skipped offline transition: %w", err)
		}
		return false, nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_presence
		SET status = 'offline', offline_since = $2, revision = revision + 1, updated_at = $2
		WHERE node_id = $1`, candidate.NodeID, now); err != nil {
		return false, fmt.Errorf("mark node offline: %w", err)
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, Action: "node.presence.offline", ResourceType: "node",
		ResourceID: candidate.NodeID.String(), RequestID: requestID.String(), Result: "success",
		Payload: map[string]any{
			"from": StatusOnline, "to": StatusOffline, "event_id": eventID.String(),
			"session_epoch": epoch, "heartbeat_sequence": sequence,
		},
	}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit offline transition: %w", err)
	}
	return true, nil
}

func projectionResult(nodeID uuid.UUID, epoch, sequence int64, eventID, requestID uuid.UUID, digest []byte, projectedAt time.Time,
	status, outcome string, refresh bool, ttl time.Duration, agentVersion *string,
) ProjectionResult {
	var digestValue [32]byte
	copy(digestValue[:], digest)
	return ProjectionResult{
		NodeID: nodeID, SessionEpoch: epoch, HeartbeatSequence: sequence, EventID: eventID,
		RequestID: requestID,
		Digest:    digestValue, ProjectedAt: projectedAt, LeaseExpiresAt: projectedAt.Add(ttl), Status: status,
		Outcome: outcome, RefreshLease: refresh,
		AgentVersion: cloneString(agentVersion),
	}
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func equalOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func compareVersion(epoch, sequence, currentEpoch, currentSequence int64) int {
	if epoch < currentEpoch || (epoch == currentEpoch && sequence < currentSequence) {
		return -1
	}
	if epoch == currentEpoch && sequence == currentSequence {
		return 0
	}
	return 1
}

func optionalUUID(value *string) (*uuid.UUID, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := canonicalUUID(*value)
	if err != nil {
		return nil, fmt.Errorf("%w: config version", ErrInvalidHeartbeat)
	}
	return &parsed, nil
}

func runtimeState(state agentv1.RuntimeState) string {
	return strings.ToLower(strings.TrimPrefix(state.String(), "RUNTIME_STATE_"))
}

func marshalActiveDeployments(deployments []*agentv1.ActiveDeployment) ([]byte, error) {
	values := make([]activeDeploymentProjection, 0, len(deployments))
	for _, deployment := range deployments {
		value := activeDeploymentProjection{
			DeploymentID: deployment.DeploymentId, Attempt: deployment.Attempt,
			ConfigVersion: deployment.ConfigVersionId,
			State:         strings.ToLower(strings.TrimPrefix(deployment.State.String(), "NODE_DEPLOYMENT_STATE_")),
		}
		if deployment.ObservedActiveConfigIdentity != nil {
			value.ObservedActiveConfigIdentity = &activeConfigIdentityProjection{
				Schema:         int32(deployment.ObservedActiveConfigIdentity.Schema),
				ConfigVersion:  deployment.ObservedActiveConfigIdentity.ConfigVersionId,
				ArtifactSHA256: hex.EncodeToString(deployment.ObservedActiveConfigIdentity.ArtifactSha256),
			}
		}
		values = append(values, value)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("marshal active deployments: %w", err)
	}
	return encoded, nil
}

func identitySchema(identity *normalizedActiveConfigIdentity) *int32 {
	if identity == nil {
		return nil
	}
	value := identity.Schema
	return &value
}

func identityDigest(identity *normalizedActiveConfigIdentity) []byte {
	if identity == nil {
		return nil
	}
	return identity.Digest
}

func validateHeartbeatIdentityBindings(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, configurationScopeID *uuid.UUID,
	heartbeat *agentv1.Heartbeat,
) error {
	for _, pair := range []struct {
		identity  *agentv1.ActiveConfigIdentity
		companion *string
	}{
		{identity: heartbeat.CurrentConfigIdentity, companion: heartbeat.CurrentConfigVersionId},
		{identity: heartbeat.PreviousConfigIdentity, companion: heartbeat.PreviousConfigVersionId},
		{identity: heartbeat.Runtime.LoadedConfigIdentity, companion: heartbeat.Runtime.LoadedConfigVersionId},
	} {
		identity, _ := normalizeActiveConfigIdentity(pair.identity, pair.companion)
		if identity != nil {
			if configurationScopeID == nil {
				return fmt.Errorf("%w: active config identity without claimed configuration scope", ErrInvalidHeartbeat)
			}
			if err := requireBoundIdentityArtifact(ctx, tx, nodeID, *configurationScopeID, identity, nil, 0,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_UNSPECIFIED); err != nil {
				return err
			}
		}
	}
	for _, deployment := range heartbeat.ActiveDeployments {
		companion := deployment.ConfigVersionId
		identity, _ := normalizeActiveConfigIdentity(deployment.ObservedActiveConfigIdentity, &companion)
		if identity == nil {
			continue
		}
		deploymentID, err := canonicalUUID(deployment.DeploymentId)
		if err != nil {
			return fmt.Errorf("%w: active deployment identity", ErrInvalidHeartbeat)
		}
		// A deployment names its own scope (migration 288), so this holds on a
		// node serving several scopes too.
		var deploymentScopeID uuid.UUID
		err = tx.QueryRow(ctx, `SELECT deployment.configuration_scope_id FROM node_deployments deployment
			JOIN node_config_state state ON state.node_id = deployment.node_id
			 AND state.configuration_scope_id = deployment.configuration_scope_id
			WHERE deployment.id = $1 AND deployment.attempt = $2 AND deployment.node_id = $3`,
			deploymentID, int32(deployment.Attempt), nodeID).Scan(&deploymentScopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: active deployment identity without claimed configuration scope", ErrInvalidHeartbeat)
		}
		if err != nil {
			return fmt.Errorf("read active deployment scope: %w", err)
		}
		if err := requireBoundIdentityArtifact(ctx, tx, nodeID, deploymentScopeID, identity, &deploymentID,
			deployment.Attempt, deployment.State); err != nil {
			return err
		}
	}
	return nil
}

func requireBoundIdentityArtifact(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID,
	identity *normalizedActiveConfigIdentity, deploymentID *uuid.UUID, attempt uint32,
	state agentv1.NodeDeploymentState,
) error {
	query := `SELECT artifact.wire_bytes,artifact.sha256
		FROM node_deployments deployment
		JOIN rollouts rollout ON rollout.id=deployment.rollout_id
		 AND rollout.config_version_id=deployment.config_version_id
		 AND rollout.configuration_scope_id=$3
		JOIN node_deployment_artifacts binding ON binding.deployment_id=deployment.id
		 AND binding.deployment_attempt=deployment.attempt
		 AND binding.config_version_id=deployment.config_version_id
		JOIN configuration_artifacts artifact ON artifact.config_version_id=binding.config_version_id
		 AND artifact.id=binding.artifact_id
		JOIN config_versions version ON version.id=artifact.config_version_id
		 AND version.configuration_scope_id=$3
		WHERE deployment.node_id=$1 AND deployment.config_version_id=$2
		 AND deployment.action='apply' AND deployment.state IN ('activated','healthy')
		 AND deployment.command_sha256=sha256(deployment.command_bytes)
		 AND artifact.kind='configuration' AND artifact.sha256=$4`
	args := []any{nodeID, identity.ConfigID, scopeID, identity.Digest}
	if deploymentID != nil {
		query = `SELECT artifact.wire_bytes,artifact.sha256
				FROM node_deployments deployment
				JOIN rollouts rollout ON rollout.id=deployment.rollout_id
				 AND rollout.config_version_id=deployment.config_version_id
				JOIN configuration_artifacts artifact ON artifact.config_version_id=deployment.config_version_id
				JOIN config_versions version ON version.id=artifact.config_version_id
				LEFT JOIN node_deployment_artifacts binding ON binding.deployment_id=deployment.id
				 AND binding.deployment_attempt=deployment.attempt
				 AND binding.config_version_id=artifact.config_version_id
				 AND binding.artifact_id=artifact.id
				WHERE deployment.id=$1 AND deployment.attempt=$2 AND deployment.node_id=$3
				 AND deployment.config_version_id=$4 AND rollout.configuration_scope_id=$5
				 AND version.configuration_scope_id=$5
				 AND deployment.command_sha256=sha256(deployment.command_bytes)
				 AND artifact.kind='configuration' AND artifact.sha256=$6
				 AND ((deployment.action='apply' AND $7='healthy' AND binding.artifact_id IS NOT NULL) OR
				      (deployment.action='rollback' AND $7='reverted'))`
		args = []any{*deploymentID, attempt, nodeID, identity.ConfigID, scopeID, identity.Digest,
			strings.ToLower(strings.TrimPrefix(state.String(), "NODE_DEPLOYMENT_STATE_"))}
	}
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("validate active config identity artifact: %w", err)
	}
	defer rows.Close()
	matched := false
	for rows.Next() {
		var wire, persistedDigest []byte
		if err := rows.Scan(&wire, &persistedDigest); err != nil {
			return fmt.Errorf("scan active config identity artifact: %w", err)
		}
		digest := sha256.Sum256(wire)
		matched = matched || bytes.Equal(persistedDigest, identity.Digest) && bytes.Equal(digest[:], identity.Digest)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate active config identity artifacts: %w", err)
	}
	if !matched {
		return fmt.Errorf("%w: unbound active config identity artifact", ErrInvalidHeartbeat)
	}
	return nil
}

// replaceScopedIdentities makes the node's scoped identities exactly the
// heartbeat's list; an agent without scoped identities clears them.
func replaceScopedIdentities(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, epoch, sequence int64,
	scoped []normalizedScopedConfigIdentity, now time.Time,
) error {
	scopes := make([]uuid.UUID, len(scoped))
	for index, entry := range scoped {
		scopes[index] = entry.ScopeID
	}
	if _, err := tx.Exec(ctx, `DELETE FROM node_presence_scope_identities
		WHERE node_id = $1 AND configuration_scope_id <> ALL($2::uuid[])`, nodeID, scopes); err != nil {
		return fmt.Errorf("prune scoped config identities: %w", err)
	}
	for _, entry := range scoped {
		var applyDeployment, applyConfig *uuid.UUID
		var applyAttempt *int32
		var applyState, applyError *string
		if entry.ApplyDeploymentID != uuid.Nil {
			attempt := int32(entry.ApplyAttempt)
			applyDeployment, applyConfig, applyAttempt = &entry.ApplyDeploymentID, &entry.ApplyConfigID, &attempt
			applyState = &entry.ApplyState
			if entry.ApplyErrorCode != "" {
				applyError = &entry.ApplyErrorCode
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO node_presence_scope_identities (
				node_id, configuration_scope_id, session_epoch, heartbeat_sequence,
				current_config_version_id, current_config_identity_schema, current_config_artifact_sha256,
				previous_config_version_id, previous_config_identity_schema, previous_config_artifact_sha256,
				last_apply_deployment_id, last_apply_attempt, last_apply_config_version_id, last_apply_state,
				last_apply_finished_at, last_apply_error_code, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
			ON CONFLICT (node_id, configuration_scope_id) DO UPDATE SET
				session_epoch = EXCLUDED.session_epoch, heartbeat_sequence = EXCLUDED.heartbeat_sequence,
				current_config_version_id = EXCLUDED.current_config_version_id,
				current_config_identity_schema = EXCLUDED.current_config_identity_schema,
				current_config_artifact_sha256 = EXCLUDED.current_config_artifact_sha256,
				previous_config_version_id = EXCLUDED.previous_config_version_id,
				previous_config_identity_schema = EXCLUDED.previous_config_identity_schema,
				previous_config_artifact_sha256 = EXCLUDED.previous_config_artifact_sha256,
				last_apply_deployment_id = EXCLUDED.last_apply_deployment_id,
				last_apply_attempt = EXCLUDED.last_apply_attempt,
				last_apply_config_version_id = EXCLUDED.last_apply_config_version_id,
				last_apply_state = EXCLUDED.last_apply_state,
				last_apply_finished_at = EXCLUDED.last_apply_finished_at,
				last_apply_error_code = EXCLUDED.last_apply_error_code, updated_at = EXCLUDED.updated_at`,
			nodeID, entry.ScopeID, epoch, sequence,
			entry.CurrentID, identitySchema(entry.Current), identityDigest(entry.Current),
			entry.PreviousID, identitySchema(entry.Previous), identityDigest(entry.Previous),
			applyDeployment, applyAttempt, applyConfig, applyState, entry.ApplyFinishedAt, applyError, now); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && (pgErr.Code == "P8702" || pgErr.Code == "23503") {
				return fmt.Errorf("%w: unbound scoped config identity", ErrInvalidHeartbeat)
			}
			return fmt.Errorf("write scoped config identity: %w", err)
		}
	}
	return nil
}
