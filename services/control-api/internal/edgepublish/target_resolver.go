package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SnapshotTargetResolver is the production database adapter for TargetResolver.
// It reads only the immutable tenant-scoped snapshot identity and digest supplied
// by the caller; it never derives node IDs from endpoint addresses or endpoint IDs.
type SnapshotTargetResolver struct{}

func NewSnapshotTargetResolver() *SnapshotTargetResolver {
	return &SnapshotTargetResolver{}
}

func (*SnapshotTargetResolver) ResolveTarget(
	ctx context.Context,
	tx pgx.Tx,
	tenantScopeID uuid.UUID,
	reference TargetSnapshotReference,
) (TargetSnapshot, error) {
	if ctx == nil || tx == nil || tenantScopeID == uuid.Nil || reference.ID == uuid.Nil || reference.Revision < 1 || reference.SHA256 == ([32]byte{}) {
		return TargetSnapshot{}, ErrTargetSnapshotConflict
	}
	var storedDigest []byte
	var nodeCount int
	var groupID uuid.UUID
	var sourceRevision int64
	var probeIntervalMS, failureThreshold, recoveryThreshold int
	var l2ConfigID *uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT snapshot.node_set_digest,snapshot.node_count,snapshot.source_line_group_id,snapshot.source_revision,
		       source.probe_interval_ms,source.failure_threshold,source.recovery_threshold,source.l2_config_id
		FROM edge_target_snapshots snapshot
		JOIN node_line_group_revisions source ON source.tenant_scope_id=snapshot.tenant_scope_id
		 AND source.line_group_id=snapshot.source_line_group_id AND source.revision=snapshot.source_revision
		WHERE snapshot.tenant_scope_id=$1 AND snapshot.id=$2 AND snapshot.revision=$3
		FOR SHARE OF snapshot,source`, tenantScopeID, reference.ID, reference.Revision).Scan(
		&storedDigest, &nodeCount, &groupID, &sourceRevision,
		&probeIntervalMS, &failureThreshold, &recoveryThreshold, &l2ConfigID,
	); errors.Is(err, pgx.ErrNoRows) {
		return TargetSnapshot{}, ErrTargetSnapshotConflict
	} else if err != nil {
		return TargetSnapshot{}, fmt.Errorf("%w: load target snapshot", ErrPersistence)
	}
	if len(storedDigest) != 32 || !bytes.Equal(storedDigest, reference.SHA256[:]) || nodeCount < 1 || nodeCount > maxPublicationTargets {
		return TargetSnapshot{}, ErrTargetSnapshotConflict
	}
	rows, err := tx.Query(ctx, `
		SELECT node_id
		FROM edge_target_snapshot_nodes
		WHERE tenant_scope_id=$1 AND snapshot_id=$2 AND snapshot_revision=$3
		ORDER BY node_id
		FOR SHARE`, tenantScopeID, reference.ID, reference.Revision)
	if err != nil {
		return TargetSnapshot{}, fmt.Errorf("%w: load target snapshot nodes", ErrPersistence)
	}
	defer rows.Close()
	nodeIDs := make([]uuid.UUID, 0, nodeCount)
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			return TargetSnapshot{}, fmt.Errorf("%w: scan target snapshot node", ErrPersistence)
		}
		if nodeID == uuid.Nil || len(nodeIDs) > 0 && nodeIDs[len(nodeIDs)-1] == nodeID {
			return TargetSnapshot{}, ErrTargetSnapshotConflict
		}
		nodeIDs = append(nodeIDs, nodeID)
	}
	if err := rows.Err(); err != nil {
		return TargetSnapshot{}, fmt.Errorf("%w: iterate target snapshot nodes", ErrPersistence)
	}
	if len(nodeIDs) != nodeCount || nodescheduler.CanonicalNodeSetDigest(nodeIDs) != reference.SHA256 {
		return TargetSnapshot{}, ErrTargetSnapshotConflict
	}
	topology, err := loadL2TopologySnapshot(ctx, tx, tenantScopeID, reference, groupID, sourceRevision,
		nodeIDs, probeIntervalMS, failureThreshold, recoveryThreshold)
	if err != nil {
		return TargetSnapshot{}, err
	}
	if l2ConfigID != nil {
		configs, err := loadL2TopologyConfigs(ctx, tx, tenantScopeID, []uuid.UUID{*l2ConfigID})
		if err != nil {
			return TargetSnapshot{}, err
		}
		topology.Config = configs[*l2ConfigID]
		if topology.Config == nil {
			// an older line group revision naming a configuration deleted
			// since: the snapshot no longer describes what was configured
			return TargetSnapshot{}, ErrTargetSnapshotConflict
		}
	}
	return TargetSnapshot{Reference: reference, NodeIDs: slices.Clone(nodeIDs), Topology: topology}, nil
}

// loadL2TopologyConfigs reads the live L2 configurations ids of the scope
// with their enabled members in sort order (sort_order, then display id, as
// 节点管理 > L2配置 > 配置节点 lists them). A deleted configuration is absent.
func loadL2TopologyConfigs(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]*L2TopologyConfig, error) {
	result := make(map[uuid.UUID]*L2TopologyConfig, len(ids))
	if len(ids) == 0 {
		return result, nil
	}
	rows, err := tx.Query(ctx, `SELECT config.id,config.mode,config.load_method,member.node_id,member.weight,member.condition_id
		FROM l2_topology_configs config
		LEFT JOIN l2_topology_nodes member ON member.tenant_scope_id=config.tenant_scope_id
		 AND member.config_id=config.id AND member.enabled AND member.deleted_at IS NULL
		WHERE config.tenant_scope_id=$1 AND config.id=ANY($2::uuid[]) AND config.deleted_at IS NULL
		ORDER BY config.id,member.sort_order,member.display_id FOR SHARE OF config`, scopeID, ids)
	if err != nil {
		return nil, fmt.Errorf("%w: load L2 configurations", ErrPersistence)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var mode, loadMethod string
		var nodeID, conditionID *uuid.UUID
		var weight *int
		if err := rows.Scan(&id, &mode, &loadMethod, &nodeID, &weight, &conditionID); err != nil {
			return nil, fmt.Errorf("%w: scan L2 configuration", ErrPersistence)
		}
		config := result[id]
		if config == nil {
			config = &L2TopologyConfig{ID: id, Mode: mode, LoadMethod: loadMethod}
			result[id] = config
		}
		if nodeID != nil && weight != nil {
			config.Members = append(config.Members, L2TopologyMember{NodeID: *nodeID, Weight: *weight, ConditionID: conditionID})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate L2 configurations", ErrPersistence)
	}
	rows.Close()
	// the members' L2 conditions (A19-b): a live member names a live
	// condition (nodescheduler refuses deleting a referenced one)
	var conditionIDs []uuid.UUID
	for _, config := range result {
		for _, member := range config.Members {
			if member.ConditionID != nil && !slices.Contains(conditionIDs, *member.ConditionID) {
				conditionIDs = append(conditionIDs, *member.ConditionID)
			}
		}
	}
	if len(conditionIDs) == 0 {
		return result, nil
	}
	conditionRows, err := tx.Query(ctx, `SELECT id,rules FROM l2_topology_conditions
		WHERE tenant_scope_id=$1 AND id=ANY($2::uuid[]) AND deleted_at IS NULL FOR SHARE`, scopeID, conditionIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: load L2 conditions", ErrPersistence)
	}
	defer conditionRows.Close()
	conditions := make(map[uuid.UUID][]edgesite.L2Rule, len(conditionIDs))
	for conditionRows.Next() {
		var id uuid.UUID
		var raw []byte
		var rules []edgesite.L2Rule
		if err := conditionRows.Scan(&id, &raw); err != nil {
			return nil, fmt.Errorf("%w: scan L2 condition", ErrPersistence)
		}
		if err := json.Unmarshal(raw, &rules); err != nil || len(rules) == 0 {
			return nil, ErrTargetSnapshotConflict
		}
		conditions[id] = rules
	}
	if err := conditionRows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate L2 conditions", ErrPersistence)
	}
	for _, config := range result {
		for _, member := range config.Members {
			if member.ConditionID == nil {
				continue
			}
			rules, ok := conditions[*member.ConditionID]
			if !ok {
				return nil, ErrTargetSnapshotConflict
			}
			if config.Conditions == nil {
				config.Conditions = map[uuid.UUID][]edgesite.L2Rule{}
			}
			config.Conditions[*member.ConditionID] = rules
		}
	}
	return result, nil
}

func loadL2TopologySnapshot(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	reference TargetSnapshotReference,
	groupID uuid.UUID,
	sourceRevision int64,
	targetNodeIDs []uuid.UUID,
	probeIntervalMS, failureThreshold, recoveryThreshold int,
) (*L2TopologySnapshot, error) {
	if groupID == uuid.Nil || sourceRevision < 1 || probeIntervalMS < 1000 || failureThreshold < 1 || recoveryThreshold < 1 {
		return nil, ErrTargetSnapshotConflict
	}
	result := &L2TopologySnapshot{
		Revision: reference.Revision, SourceLineGroupID: groupID, SourceRevision: sourceRevision,
		ProbeIntervalMS: probeIntervalMS, FailureThreshold: failureThreshold, RecoveryThreshold: recoveryThreshold,
	}
	// an L1 target's display id and IP location: what L2 condition node
	// rules match (A19-b)
	rows, err := tx.Query(ctx, `SELECT identity.node_id,identity.tier,identity.endpoint_id,
		identity.mtls_identity_sha256,host(endpoint.address),endpoint.port,endpoint.weight,
		COALESCE(node.display_id::text,''),COALESCE(node.management_settings#>>'{ip_location,country_code}',''),
		COALESCE(node.management_settings#>>'{ip_location,isp}',''),
		COALESCE(node.management_settings#>>'{ip_location,province}',''),
		COALESCE(node.management_settings#>>'{ip_location,city}','')
		FROM edge_target_snapshot_identities identity
		LEFT JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=identity.tenant_scope_id
		 AND endpoint.line_group_id=identity.source_line_group_id AND endpoint.config_revision=identity.source_revision
		 AND endpoint.id=identity.endpoint_id AND endpoint.node_id=identity.node_id
		LEFT JOIN nodes node ON node.id=identity.node_id AND identity.tier='l1'
		WHERE identity.tenant_scope_id=$1 AND identity.snapshot_id=$2 AND identity.snapshot_revision=$3
		  AND identity.topology_revision=$3
		ORDER BY identity.tier,identity.node_id,identity.endpoint_id FOR SHARE OF identity`,
		scopeID, reference.ID, reference.Revision)
	if err != nil {
		return nil, fmt.Errorf("%w: load L2 topology identities", ErrPersistence)
	}
	defer rows.Close()
	seenTargets := make(map[uuid.UUID]struct{}, len(targetNodeIDs))
	seenEndpoints := make(map[uuid.UUID]struct{})
	for rows.Next() {
		var nodeID uuid.UUID
		var tier string
		var endpointID *uuid.UUID
		var digest []byte
		var address *string
		var port, weight *int
		var location L2NodeLocation
		if err := rows.Scan(&nodeID, &tier, &endpointID, &digest, &address, &port, &weight, &location.DisplayID,
			&location.CountryCode, &location.ISP, &location.Province, &location.City); err != nil {
			return nil, fmt.Errorf("%w: scan L2 topology identity", ErrPersistence)
		}
		if nodeID == uuid.Nil || len(digest) != sha256.Size {
			return nil, ErrTargetSnapshotConflict
		}
		var identity [sha256.Size]byte
		copy(identity[:], digest)
		switch tier {
		case "l1":
			if endpointID != nil || address != nil || port != nil || weight != nil {
				return nil, ErrTargetSnapshotConflict
			}
			seenTargets[nodeID] = struct{}{}
			result.TargetIdentities = append(result.TargetIdentities, L2TopologyIdentity{NodeID: nodeID, MTLSIdentitySHA256: identity, Location: location})
		case "l2":
			if endpointID == nil || *endpointID == uuid.Nil || address == nil || port == nil || weight == nil || *port < 1 || *port > 65535 || *weight < 1 || *weight > 100 {
				return nil, ErrTargetSnapshotConflict
			}
			if _, duplicate := seenEndpoints[*endpointID]; duplicate {
				return nil, ErrTargetSnapshotConflict
			}
			seenEndpoints[*endpointID] = struct{}{}
			result.Endpoints = append(result.Endpoints, L2TopologyEndpoint{
				EndpointID: *endpointID, NodeID: nodeID, Address: *address, Port: *port, Weight: *weight,
				MTLSIdentitySHA256: identity,
			})
		default:
			return nil, ErrTargetSnapshotConflict
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate L2 topology identities", ErrPersistence)
	}
	if len(seenTargets) != len(targetNodeIDs) || len(result.Endpoints) == 0 {
		return nil, ErrTargetSnapshotConflict
	}
	for _, nodeID := range targetNodeIDs {
		if _, exists := seenTargets[nodeID]; !exists {
			return nil, ErrTargetSnapshotConflict
		}
	}
	return result, nil
}
