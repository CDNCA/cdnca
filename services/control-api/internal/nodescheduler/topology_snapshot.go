package nodescheduler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Service) CreateTargetSnapshotForNodes(
	ctx context.Context,
	actor Actor,
	groupID uuid.UUID,
	revision int64,
	targetNodeIDs []uuid.UUID,
	idempotencyKey string,
	requestID string,
) (TargetSnapshot, error) {
	if ctx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ResourceScopeID() == uuid.Nil ||
		groupID == uuid.Nil || revision < 1 || len(targetNodeIDs) < 1 || len(targetNodeIDs) > 10000 ||
		!writeMetadataPattern.MatchString(idempotencyKey) || !writeMetadataPattern.MatchString(requestID) {
		return TargetSnapshot{}, ErrInvalidInput
	}
	targetNodeIDs = slices.Clone(targetNodeIDs)
	for _, nodeID := range targetNodeIDs {
		if nodeID == uuid.Nil {
			return TargetSnapshot{}, ErrInvalidInput
		}
	}
	sort.Slice(targetNodeIDs, func(i, j int) bool { return bytes.Compare(targetNodeIDs[i][:], targetNodeIDs[j][:]) < 0 })
	if len(slices.Compact(slices.Clone(targetNodeIDs))) != len(targetNodeIDs) {
		return TargetSnapshot{}, ErrInvalidInput
	}
	nodeDigest := CanonicalNodeSetDigest(targetNodeIDs)
	requestDigest := targetSnapshotRequestDigest(groupID, revision, nodeDigest)
	now := s.now().UTC().Truncate(time.Microsecond)
	scopeID := actor.ResourceScopeID()
	var result TargetSnapshot
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionManage, true); err != nil {
			return err
		}
		stored, found, err := claimWrite(ctx, tx, actor, operationTargetSnapshotCreate,
			idempotencyKey, requestDigest, groupID, now)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(stored, &result); err != nil {
				return fmt.Errorf("decode topology snapshot replay: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			"node-scheduling-topology:"+scopeID.String()); err != nil {
			return fmt.Errorf("lock node scheduling topology: %w", err)
		}
		var sourceDigest []byte
		var sealedAt *time.Time
		if err := tx.QueryRow(ctx, `SELECT revision.configuration_digest,revision.sealed_at
			FROM node_line_groups line_group
			JOIN node_line_group_revisions revision
			  ON revision.tenant_scope_id=line_group.tenant_scope_id
			 AND revision.line_group_id=line_group.id
			WHERE line_group.tenant_scope_id=$1 AND line_group.id=$2
			  AND revision.revision=$3 AND line_group.deleted_at IS NULL FOR SHARE OF line_group,revision`,
			scopeID, groupID, revision).Scan(&sourceDigest, &sealedAt); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("load topology source revision: %w", err)
		}
		if sealedAt == nil || len(sourceDigest) != 32 {
			return ErrTargetSnapshotUnavailable
		}
		endpointNodeIDs, err := loadSourceEndpointNodes(ctx, tx, scopeID, groupID, revision)
		if err != nil {
			return err
		}
		if err := validateDeployableNodes(ctx, tx, scopeID, targetNodeIDs); err != nil {
			return err
		}
		if err := validateDeployableNodes(ctx, tx, scopeID, endpointNodeIDs); err != nil {
			return err
		}
		if err := validateTopology(ctx, tx, scopeID, targetNodeIDs, endpointNodeIDs); err != nil {
			return err
		}
		if replay, ok, err := loadTargetSnapshotReplay(ctx, tx, scopeID, groupID, revision, sourceDigest,
			nodeDigest, targetNodeIDs, endpointNodeIDs, now); err != nil {
			return err
		} else if ok {
			result = replay
			return completeWrite(ctx, tx, actor, operationTargetSnapshotCreate,
				idempotencyKey, result, now)
		}

		snapshotID := uuid.NewSHA1(groupID, []byte(targetNodeSetSchema))
		var snapshotRevision int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0)+1 FROM edge_target_snapshots
			WHERE tenant_scope_id=$1 AND id=$2`, scopeID, snapshotID).Scan(&snapshotRevision); err != nil {
			return fmt.Errorf("allocate topology snapshot revision: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO edge_target_snapshots(
			id,tenant_scope_id,revision,source_line_group_id,source_revision,
			source_configuration_digest,node_set_digest,node_count,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, snapshotID, scopeID, snapshotRevision,
			groupID, revision, sourceDigest, nodeDigest[:], len(targetNodeIDs), now); err != nil {
			return fmt.Errorf("persist topology snapshot: %w", err)
		}
		identities, err := loadSnapshotIdentities(ctx, tx, scopeID, groupID, snapshotID, revision, snapshotRevision, now, targetNodeIDs, endpointNodeIDs)
		if err != nil {
			return err
		}
		for _, nodeID := range targetNodeIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO edge_target_snapshot_nodes(
				tenant_scope_id,snapshot_id,snapshot_revision,node_id) VALUES($1,$2,$3,$4)`,
				scopeID, snapshotID, snapshotRevision, nodeID); err != nil {
				return fmt.Errorf("persist topology snapshot target: %w", err)
			}
		}
		for _, identity := range identities {
			identityID := identity.NodeID
			if identity.EndpointID != nil {
				identityID = *identity.EndpointID
			}
			if _, err := tx.Exec(ctx, `INSERT INTO edge_target_snapshot_identities(
				tenant_scope_id,snapshot_id,snapshot_revision,identity_id,topology_revision,node_id,tier,
				source_line_group_id,source_revision,endpoint_id,mtls_identity_sha256,created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, scopeID, snapshotID, snapshotRevision,
				identityID, identity.TopologyRevision, identity.NodeID, identity.Tier,
				identity.SourceLineGroupID, identity.SourceRevision, identity.EndpointID,
				identity.MTLSIdentitySHA256, now); err != nil {
				return fmt.Errorf("persist topology snapshot identity: %w", err)
			}
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: "node_scheduling.target_snapshot.create",
			ResourceType: "edge_target_snapshot", ResourceID: snapshotID.String(),
			RequestID: requestID, Result: "success", Payload: map[string]any{
				"source_line_group_id": groupID.String(), "source_revision": revision,
				"snapshot_revision": snapshotRevision, "l1_target_count": len(targetNodeIDs),
				"l2_candidate_count": len(endpointNodeIDs), "node_set_digest": fmt.Sprintf("%x", nodeDigest[:]),
			},
		}); err != nil {
			return fmt.Errorf("append topology snapshot audit: %w", err)
		}
		result = TargetSnapshot{
			Reference:     TargetSnapshotReference{ID: snapshotID, Revision: snapshotRevision, SHA256: nodeDigest},
			TenantScopeID: scopeID, SourceLineGroupID: groupID, SourceRevision: revision,
			SourceConfigurationDigest: slices.Clone(sourceDigest), NodeIDs: slices.Clone(targetNodeIDs), IdentityFacts: identities,
		}
		return completeWrite(ctx, tx, actor, operationTargetSnapshotCreate,
			idempotencyKey, result, now)
	})
	return result, err
}

func (s *Service) GetTargetSnapshot(
	ctx context.Context,
	actor Actor,
	groupID uuid.UUID,
	revision int64,
) (TargetSnapshot, error) {
	if ctx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ResourceScopeID() == uuid.Nil ||
		groupID == uuid.Nil || revision < 1 {
		return TargetSnapshot{}, ErrInvalidInput
	}
	var result TargetSnapshot
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		var err error
		result, err = loadTargetSnapshot(ctx, tx, actor.ResourceScopeID(), groupID, revision)
		return err
	})
	return result, err
}

func targetSnapshotRequestDigest(groupID uuid.UUID, revision int64, nodeDigest [32]byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.node-scheduling.target-snapshot-request/v1\x00"))
	_, _ = hash.Write(groupID[:])
	var encodedRevision [8]byte
	binary.BigEndian.PutUint64(encodedRevision[:], uint64(revision))
	_, _ = hash.Write(encodedRevision[:])
	_, _ = hash.Write(nodeDigest[:])
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func loadTargetSnapshot(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, groupID uuid.UUID,
	revision int64,
) (TargetSnapshot, error) {
	var result TargetSnapshot
	var nodeDigest []byte
	var nodeCount int
	err := tx.QueryRow(ctx, `SELECT snapshot.id,snapshot.revision,snapshot.source_configuration_digest,
		       snapshot.node_set_digest,snapshot.node_count
		FROM edge_target_snapshots snapshot
		JOIN node_line_groups line_group
		  ON line_group.tenant_scope_id=snapshot.tenant_scope_id
		 AND line_group.id=snapshot.source_line_group_id
		WHERE snapshot.tenant_scope_id=$1 AND snapshot.source_line_group_id=$2
		  AND snapshot.source_revision=$3 AND line_group.deleted_at IS NULL
		ORDER BY snapshot.revision DESC LIMIT 1 FOR SHARE OF snapshot,line_group`, scopeID, groupID, revision).Scan(
		&result.Reference.ID, &result.Reference.Revision, &result.SourceConfigurationDigest,
		&nodeDigest, &nodeCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return TargetSnapshot{}, ErrNotFound
	}
	if err != nil {
		return TargetSnapshot{}, fmt.Errorf("load topology snapshot: %w", err)
	}
	if len(result.SourceConfigurationDigest) != 32 || len(nodeDigest) != 32 {
		return TargetSnapshot{}, ErrTargetSnapshotUnavailable
	}
	copy(result.Reference.SHA256[:], nodeDigest)
	result.TenantScopeID = scopeID
	result.SourceLineGroupID = groupID
	result.SourceRevision = revision
	rows, err := tx.Query(ctx, `SELECT node_id FROM edge_target_snapshot_nodes
		WHERE tenant_scope_id=$1 AND snapshot_id=$2 AND snapshot_revision=$3 ORDER BY node_id`,
		scopeID, result.Reference.ID, result.Reference.Revision)
	if err != nil {
		return TargetSnapshot{}, fmt.Errorf("load topology snapshot targets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			return TargetSnapshot{}, err
		}
		result.NodeIDs = append(result.NodeIDs, nodeID)
	}
	if err := rows.Err(); err != nil {
		return TargetSnapshot{}, err
	}
	rows.Close()
	if len(result.NodeIDs) != nodeCount {
		return TargetSnapshot{}, ErrTargetSnapshotUnavailable
	}
	identities, err := loadPersistedSnapshotIdentities(ctx, tx, scopeID, result.Reference.ID, result.Reference.Revision)
	if err != nil {
		return TargetSnapshot{}, err
	}
	if !validSnapshotIdentitySet(identities, nodeCount, groupID, revision, result.Reference.Revision) {
		return TargetSnapshot{}, ErrTargetSnapshotUnavailable
	}
	result.IdentityFacts = identities
	return result, nil
}

func loadSnapshotIdentities(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, groupID, snapshotID uuid.UUID,
	sourceRevision, topologyRevision int64,
	at time.Time,
	targetNodeIDs, endpointNodeIDs []uuid.UUID,
) ([]SnapshotIdentity, error) {
	if scopeID == uuid.Nil || groupID == uuid.Nil || snapshotID == uuid.Nil || topologyRevision < 1 ||
		sourceRevision < 1 || len(targetNodeIDs) == 0 || len(endpointNodeIDs) == 0 {
		return nil, ErrTargetSnapshotUnavailable
	}
	result := make([]SnapshotIdentity, 0, len(targetNodeIDs)+len(endpointNodeIDs))
	digests := make(map[uuid.UUID][]byte, len(targetNodeIDs)+len(endpointNodeIDs))
	appendNode := func(nodeID uuid.UUID, tier string, endpointID *uuid.UUID) error {
		digest := digests[nodeID]
		if digest == nil {
			err := tx.QueryRow(ctx, `SELECT COALESCE(current.leaf_der_sha256,current.leaf_certificate_sha256)
				FROM nodes node
				JOIN LATERAL (
					SELECT certificate.leaf_der_sha256,certificate.leaf_certificate_sha256
					FROM node_certificates certificate
					WHERE certificate.node_id=node.id AND certificate.status='active'
					  AND certificate.not_before <= $3 AND certificate.not_after > $3
					  AND (certificate.rotation_status IN ('current','overlap') OR certificate.rotation_status='legacy_unbound')
					ORDER BY certificate.issued_at DESC,certificate.id DESC LIMIT 1
				) current ON true
				WHERE node.scope_id=$1 AND node.id=$2 AND node.admin_state='active'`, scopeID, nodeID, at).Scan(&digest)
			if errors.Is(err, pgx.ErrNoRows) || len(digest) != 32 {
				return ErrTargetSnapshotUnavailable
			}
			if err != nil {
				return fmt.Errorf("load topology node identity: %w", err)
			}
			digests[nodeID] = slices.Clone(digest)
		}
		result = append(result, SnapshotIdentity{
			NodeID: nodeID, Tier: tier, TopologyRevision: topologyRevision,
			SourceLineGroupID: groupID, SourceRevision: sourceRevision, EndpointID: endpointID,
			MTLSIdentitySHA256: slices.Clone(digest),
		})
		return nil
	}
	for _, nodeID := range targetNodeIDs {
		if err := appendNode(nodeID, "l1", nil); err != nil {
			return nil, err
		}
	}
	rows, err := tx.Query(ctx, `SELECT id,node_id FROM node_line_endpoints
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3
		ORDER BY node_id,id FOR SHARE`, scopeID, groupID, sourceRevision)
	if err != nil {
		return nil, fmt.Errorf("load topology endpoint identities: %w", err)
	}
	type endpointIdentity struct {
		id     uuid.UUID
		nodeID uuid.UUID
	}
	var endpoints []endpointIdentity
	for rows.Next() {
		var endpointID uuid.UUID
		var nodeID *uuid.UUID
		if err := rows.Scan(&endpointID, &nodeID); err != nil {
			rows.Close()
			return nil, err
		}
		if endpointID == uuid.Nil || nodeID == nil || *nodeID == uuid.Nil {
			rows.Close()
			return nil, ErrTargetSnapshotUnavailable
		}
		endpoints = append(endpoints, endpointIdentity{id: endpointID, nodeID: *nodeID})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(endpoints) == 0 {
		return nil, ErrTargetSnapshotUnavailable
	}
	for _, value := range endpoints {
		endpoint := value.id
		if err := appendNode(value.nodeID, "l2", &endpoint); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func loadPersistedSnapshotIdentities(ctx context.Context, tx pgx.Tx, scopeID, snapshotID uuid.UUID, revision int64) ([]SnapshotIdentity, error) {
	rows, err := tx.Query(ctx, `SELECT node_id,tier,topology_revision,source_line_group_id,source_revision,endpoint_id,mtls_identity_sha256
		FROM edge_target_snapshot_identities
		WHERE tenant_scope_id=$1 AND snapshot_id=$2 AND snapshot_revision=$3
		ORDER BY tier,node_id,endpoint_id FOR SHARE`, scopeID, snapshotID, revision)
	if err != nil {
		return nil, fmt.Errorf("load topology identity facts: %w", err)
	}
	defer rows.Close()
	var result []SnapshotIdentity
	for rows.Next() {
		var value SnapshotIdentity
		if err := rows.Scan(&value.NodeID, &value.Tier, &value.TopologyRevision, &value.SourceLineGroupID,
			&value.SourceRevision, &value.EndpointID, &value.MTLSIdentitySHA256); err != nil {
			return nil, err
		}
		if value.NodeID == uuid.Nil || value.TopologyRevision != revision || len(value.MTLSIdentitySHA256) != 32 ||
			(value.Tier == "l1" && value.EndpointID != nil) || (value.Tier == "l2" && value.EndpointID == nil) {
			return nil, ErrTargetSnapshotUnavailable
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func loadTargetSnapshotReplay(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, groupID uuid.UUID,
	revision int64,
	sourceDigest []byte,
	nodeDigest [32]byte,
	targetNodeIDs, endpointNodeIDs []uuid.UUID,
	at time.Time,
) (TargetSnapshot, bool, error) {
	stored, err := loadTargetSnapshot(ctx, tx, scopeID, groupID, revision)
	if errors.Is(err, ErrNotFound) {
		return TargetSnapshot{}, false, nil
	}
	if err != nil {
		return TargetSnapshot{}, false, err
	}
	if !bytes.Equal(stored.SourceConfigurationDigest, sourceDigest) || stored.Reference.SHA256 != nodeDigest ||
		!slices.Equal(stored.NodeIDs, targetNodeIDs) {
		return TargetSnapshot{}, false, ErrTargetSnapshotConflict
	}
	current, err := loadSnapshotIdentities(ctx, tx, scopeID, groupID, stored.Reference.ID, revision,
		stored.Reference.Revision, at, targetNodeIDs, endpointNodeIDs)
	if err != nil {
		return TargetSnapshot{}, false, err
	}
	if !validSnapshotIdentitySet(current, len(targetNodeIDs), groupID, revision, stored.Reference.Revision) {
		return TargetSnapshot{}, false, ErrTargetSnapshotUnavailable
	}
	if !sameSnapshotIdentities(stored.IdentityFacts, current) {
		return TargetSnapshot{}, false, nil
	}
	stored.Replayed = true
	return stored, true, nil
}

func sameSnapshotIdentities(left, right []SnapshotIdentity) bool {
	if len(left) != len(right) {
		return false
	}
	key := func(value SnapshotIdentity) string {
		endpoint := ""
		if value.EndpointID != nil {
			endpoint = value.EndpointID.String()
		}
		return value.Tier + "\x00" + value.NodeID.String() + "\x00" + endpoint
	}
	leftByKey := make(map[string]SnapshotIdentity, len(left))
	for _, value := range left {
		leftByKey[key(value)] = value
	}
	for _, value := range right {
		stored, ok := leftByKey[key(value)]
		if !ok || !bytes.Equal(stored.MTLSIdentitySHA256, value.MTLSIdentitySHA256) {
			return false
		}
	}
	return true
}

func validSnapshotIdentitySet(values []SnapshotIdentity, targetCount int, groupID uuid.UUID, sourceRevision, topologyRevision int64) bool {
	if targetCount < 1 || groupID == uuid.Nil || sourceRevision < 1 || topologyRevision < 1 {
		return false
	}
	l1Count, l2Count := 0, 0
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value.NodeID == uuid.Nil || value.TopologyRevision != topologyRevision ||
			value.SourceLineGroupID != groupID || value.SourceRevision != sourceRevision || len(value.MTLSIdentitySHA256) != 32 {
			return false
		}
		endpoint := ""
		if value.EndpointID != nil {
			if *value.EndpointID == uuid.Nil || value.Tier != "l2" {
				return false
			}
			endpoint = value.EndpointID.String()
		} else if value.Tier != "l1" {
			return false
		}
		key := value.Tier + "\x00" + value.NodeID.String() + "\x00" + endpoint
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		if value.Tier == "l1" {
			l1Count++
		} else {
			l2Count++
		}
	}
	return l1Count == targetCount && l2Count > 0
}

func loadSourceEndpointNodes(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID, revision int64) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT node_id FROM node_line_endpoints
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3 ORDER BY node_id,id FOR SHARE`,
		scopeID, groupID, revision)
	if err != nil {
		return nil, fmt.Errorf("load topology L2 candidates: %w", err)
	}
	defer rows.Close()
	var result []uuid.UUID
	for rows.Next() {
		var nodeID *uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			return nil, err
		}
		if nodeID == nil || *nodeID == uuid.Nil {
			return nil, ErrTargetSnapshotUnavailable
		}
		result = append(result, *nodeID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, ErrTargetSnapshotUnavailable
	}
	return slices.Compact(result), nil
}

func validateDeployableNodes(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, nodeIDs []uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT node.id,node.admin_state,COALESCE(config.reconciliation_required,false),
		EXISTS(SELECT 1 FROM node_deployments deployment WHERE deployment.node_id=node.id
		AND (deployment.configuration_scope_id=$1 OR NOT deployment.queued_per_scope)
		AND deployment.state NOT IN ('healthy','failed','reverted','rollback_failed','cancelled'))
		FROM nodes node LEFT JOIN node_config_state config ON config.node_id=node.id AND config.configuration_scope_id=$1
		WHERE node.scope_id=$1 AND node.id=ANY($2::uuid[]) ORDER BY node.id FOR SHARE OF node`, scopeID, nodeIDs)
	if err != nil {
		return fmt.Errorf("validate topology target nodes: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id uuid.UUID
		var state string
		var reconciliation, deployment bool
		if err := rows.Scan(&id, &state, &reconciliation, &deployment); err != nil {
			return err
		}
		count++
		if state != "active" || reconciliation || deployment {
			return ErrTargetSnapshotUnavailable
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != len(nodeIDs) {
		return ErrTargetSnapshotUnavailable
	}
	return nil
}

func validateTopology(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, targets, endpoints []uuid.UUID) error {
	graph := make(map[uuid.UUID]map[uuid.UUID]struct{})
	indegree := make(map[uuid.UUID]int)
	addEdge := func(from, to uuid.UUID) error {
		if from == to {
			return ErrTopologyCycle
		}
		if graph[from] == nil {
			graph[from] = make(map[uuid.UUID]struct{})
		}
		if _, exists := graph[from][to]; !exists {
			graph[from][to] = struct{}{}
			indegree[to]++
		}
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT target.node_id,endpoint.node_id
		FROM edge_target_snapshots snapshot
		JOIN edge_target_snapshot_nodes target ON target.tenant_scope_id=snapshot.tenant_scope_id
		 AND target.snapshot_id=snapshot.id AND target.snapshot_revision=snapshot.revision
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=snapshot.tenant_scope_id
		 AND endpoint.line_group_id=snapshot.source_line_group_id AND endpoint.config_revision=snapshot.source_revision
		WHERE snapshot.tenant_scope_id=$1 ORDER BY target.node_id,endpoint.node_id`, scopeID)
	if err != nil {
		return fmt.Errorf("load existing node scheduling topology: %w", err)
	}
	for rows.Next() {
		var from uuid.UUID
		var to *uuid.UUID
		if err := rows.Scan(&from, &to); err != nil {
			rows.Close()
			return err
		}
		if to == nil || *to == uuid.Nil {
			rows.Close()
			return ErrTargetSnapshotUnavailable
		}
		if err := addEdge(from, *to); err != nil {
			rows.Close()
			return err
		}
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return rowErr
	}
	for _, target := range targets {
		for _, endpoint := range endpoints {
			if err := addEdge(target, endpoint); err != nil {
				return err
			}
		}
	}
	return validateTopologyGraph(graph, indegree)
}

func validateTopologyGraph(graph map[uuid.UUID]map[uuid.UUID]struct{}, indegree map[uuid.UUID]int) error {
	for nodeID, edges := range graph {
		if indegree[nodeID] > 0 && len(edges) > 0 {
			return ErrTopologyCycle
		}
	}
	state := make(map[uuid.UUID]uint8)
	var visit func(uuid.UUID) bool
	visit = func(nodeID uuid.UUID) bool {
		if state[nodeID] == 1 {
			return false
		}
		if state[nodeID] == 2 {
			return true
		}
		state[nodeID] = 1
		for next := range graph[nodeID] {
			if !visit(next) {
				return false
			}
		}
		state[nodeID] = 2
		return true
	}
	for nodeID := range graph {
		if !visit(nodeID) {
			return ErrTopologyCycle
		}
	}
	return nil
}
