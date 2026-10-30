package nodescheduler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	permissionRead                = "node_scheduling.read"
	permissionManage              = "node_scheduling.manage"
	operationGroupCreate          = "node_scheduling.group.create"
	operationGroupUpdate          = "node_scheduling.group.update"
	operationGroupRollback        = "node_scheduling.group.rollback"
	operationGroupDelete          = "node_scheduling.group.delete"
	operationTargetSnapshotCreate = "node_scheduling.target_snapshot.create"
)

type auditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Service struct {
	pool         *pgxpool.Pool
	auditor      auditAppender
	now          func() time.Time
	iam          *iamlock.Authorizer
	loads        LoadProvider
	publications PublicationTrigger
}

// PublicationTrigger enqueues the automatic republication of a scope whose
// line group changed its node set, in the caller's transaction (FX02).
// It reports whether a new request was queued.
type PublicationTrigger interface {
	EnqueueLineGroupChangeTx(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID, requestID string) (bool, error)
}

// ScopeRevisionPublisher is the optional half of a PublicationTrigger that
// publishes an L2 topology write (504 triggers advance the scope's revision
// outside any request) when no request covers the scope's current revision
// (edgeautopublish.EnqueueUnrequestedScopeRevisionTx).
type ScopeRevisionPublisher interface {
	EnqueueUnrequestedScopeRevisionTx(ctx context.Context, tx pgx.Tx, scopeID, resourceID uuid.UUID, requestID string) (bool, error)
}

// SetPublicationTrigger wires automatic republication; without it a node-set
// change still advances each using scope's source revision, so its operator
// can publish the new nodes.
func (s *Service) SetPublicationTrigger(trigger PublicationTrigger) { s.publications = trigger }

// publishL2WriteTx publishes the scope's L2 topology write when the trigger
// supports it (an automatic scope; a manual one keeps it pending).
func (s *Service) publishL2WriteTx(ctx context.Context, tx pgx.Tx, actor Actor, resourceID uuid.UUID, requestID string) error {
	publisher, ok := s.publications.(ScopeRevisionPublisher)
	if !ok {
		return nil
	}
	if _, err := publisher.EnqueueUnrequestedScopeRevisionTx(ctx, tx, actor.ResourceScopeID(), resourceID,
		"l2-topology/"+requestID); err != nil {
		return fmt.Errorf("enqueue L2 topology publication: %w", err)
	}
	// fix-autol2b: the scopes whose sites use a line group naming the
	// configuration (a platform line group's tenants above all) republish
	// too: their automatic publications carry its L2.
	groups, err := l2ResourceLineGroups(ctx, tx, actor.ResourceScopeID(), resourceID)
	if err != nil {
		return err
	}
	for _, groupID := range groups {
		scopes, err := lockLineGroupUsingScopes(ctx, tx, groupID)
		if err != nil {
			return err
		}
		scopes = slices.DeleteFunc(scopes, func(scopeID uuid.UUID) bool { return scopeID == actor.ResourceScopeID() })
		if _, err := s.republishUsingScopes(ctx, tx, scopes, groupID, "l2-topology/"+requestID); err != nil {
			return err
		}
	}
	return nil
}

// l2ResourceLineGroups: the live line groups of scopeID naming the L2
// configuration an L2 write touched (resourceID: the configuration, one of
// its members, or a condition its members use), in id order.
func l2ResourceLineGroups(ctx context.Context, tx pgx.Tx, scopeID, resourceID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT line_group.id FROM node_line_groups line_group
		WHERE line_group.tenant_scope_id=$1 AND line_group.deleted_at IS NULL AND line_group.l2_config_id IN (
		    SELECT config.id FROM l2_topology_configs config WHERE config.tenant_scope_id=$1 AND config.id=$2
		    UNION
		    SELECT member.config_id FROM l2_topology_nodes member
		    WHERE member.tenant_scope_id=$1 AND (member.id=$2 OR member.condition_id=$2))
		ORDER BY line_group.id`, scopeID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("read L2 configuration line groups: %w", err)
	}
	groups, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("read L2 configuration line groups: %w", err)
	}
	return groups, nil
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func NewService(pool *pgxpool.Pool, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{pool: pool, auditor: audit.New(pool), now: now}
}

func NewIAMService(pool *pgxpool.Pool, now func() time.Time, iam *iamlock.Authorizer, loads LoadProvider) (*Service, error) {
	if pool == nil || iam == nil || !iam.Configured() {
		return nil, ErrInvalidInput
	}
	service := NewService(pool, now)
	service.iam = iam
	service.loads = loads
	return service, nil
}

func (s *Service) PutGroup(ctx context.Context, actor Actor, request PutGroupRequest) (WriteResult, error) {
	operation := operationGroupUpdate
	if request.ExpectedRevision == 0 {
		operation = operationGroupCreate
	}
	return s.putGroup(ctx, actor, request, operation, 0)
}

func (s *Service) DeleteGroup(
	ctx context.Context,
	actor Actor,
	groupID uuid.UUID,
	expectedRevision int64,
	idempotencyKey string,
	requestID string,
) (DeleteResult, error) {
	return s.deleteGroup(ctx, actor, groupID, expectedRevision, idempotencyKey, requestID, PurposeGeneral)
}

func (s *Service) deleteGroup(
	ctx context.Context,
	actor Actor,
	groupID uuid.UUID,
	expectedRevision int64,
	idempotencyKey string,
	requestID string,
	purpose string,
) (DeleteResult, error) {
	if ctx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ResourceScopeID() == uuid.Nil ||
		groupID == uuid.Nil || expectedRevision < 1 || !writeMetadataPattern.MatchString(idempotencyKey) ||
		!writeMetadataPattern.MatchString(requestID) {
		return DeleteResult{}, ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	digest := deleteGroupRequestDigest(groupID, expectedRevision)
	if purpose != PurposeGeneral {
		digest = bindPurpose(digest, purpose)
	}
	var result DeleteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizePurpose(ctx, tx, actor, purpose); err != nil {
			return err
		}
		stored, found, err := claimWrite(ctx, tx, actor, operationGroupDelete,
			idempotencyKey, digest, groupID, now)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(stored, &result); err != nil {
				return fmt.Errorf("decode node line group delete replay: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if err := lockLineGroupReferences(ctx, tx, actor.ResourceScopeID()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, groupID.String()); err != nil {
			return fmt.Errorf("lock node line group: %w", err)
		}
		var currentRevision int64
		err = tx.QueryRow(ctx, `SELECT current_revision FROM node_line_groups
			WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL AND purpose=$3 FOR UPDATE`,
			actor.ResourceScopeID(), groupID, purpose).Scan(&currentRevision)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock node line group for delete: %w", err)
		}
		if currentRevision != expectedRevision {
			return ErrRevisionConflict
		}
		if purpose == PurposeMarketSupply {
			if err := ensureMarketSupplyGroupUnused(ctx, tx, groupID); err != nil {
				return err
			}
		}
		command, err := tx.Exec(ctx, `UPDATE node_line_groups
			SET deleted_at=$4,deleted_by_user_id=$5,updated_by_user_id=$5,updated_at=$4
			WHERE tenant_scope_id=$1 AND id=$2 AND current_revision=$3 AND deleted_at IS NULL`,
			actor.ResourceScopeID(), groupID, expectedRevision, now, actor.UserID)
		if err != nil {
			return classifyWriteError(err)
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result = DeleteResult{
			GroupID: groupID, ScopeID: actor.ResourceScopeID(), Revision: expectedRevision, DeletedAt: now,
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ResourceScopeID(), ActorUserID: &actor.UserID, Action: operationGroupDelete,
			ResourceType: "node_line_group", ResourceID: groupID.String(), RequestID: requestID,
			Result: "success", Payload: map[string]any{
				"revision": expectedRevision, "deleted_at": now,
			},
		}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, operationGroupDelete, idempotencyKey, result, now)
	})
	if err != nil {
		return DeleteResult{}, fmt.Errorf("delete node line group: %w", err)
	}
	return result, nil
}

func lockLineGroupReferences(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
		"node-scheduling-line-group-reference:"+scopeID.String()); err != nil {
		return fmt.Errorf("lock node line group references: %w", err)
	}
	return nil
}

// validateEndpointNodeAddresses requires every node-bound endpoint to use an
// address the node owns: its primary IPv4/IPv6 or one of its secondary IPs
// (节点管理 > 副IP). Secondary IPs thereby become real line-group candidates
// instead of a stored-only field, and an endpoint
// can no longer pin an arbitrary address to a node's health and holds.
func validateEndpointNodeAddresses(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, endpoints []Endpoint) error {
	nodeIDs := make([]uuid.UUID, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.NodeID != uuid.Nil && !slices.Contains(nodeIDs, endpoint.NodeID) {
			nodeIDs = append(nodeIDs, endpoint.NodeID)
		}
	}
	if len(nodeIDs) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT node.id, address
		FROM nodes node
		CROSS JOIN LATERAL (
			SELECT host(node.ipv4) WHERE node.ipv4 IS NOT NULL
			UNION ALL SELECT host(node.ipv6) WHERE node.ipv6 IS NOT NULL
			UNION ALL SELECT jsonb_array_elements_text(COALESCE(node.management_settings->'secondary_ips','[]'::jsonb))
		) owned(address)
		WHERE node.scope_id=$1 AND node.id=ANY($2::uuid[])
		FOR SHARE OF node`, scopeID, nodeIDs)
	if err != nil {
		return fmt.Errorf("load node addresses: %w", err)
	}
	owned := make(map[string]struct{})
	err = func() error {
		defer rows.Close()
		for rows.Next() {
			var nodeID uuid.UUID
			var address string
			if err := rows.Scan(&nodeID, &address); err != nil {
				return err
			}
			if parsed, parseErr := netip.ParseAddr(address); parseErr == nil {
				owned[nodeID.String()+"|"+parsed.String()] = struct{}{}
			}
		}
		return rows.Err()
	}()
	if err != nil {
		return fmt.Errorf("load node addresses: %w", err)
	}
	for _, endpoint := range endpoints {
		if endpoint.NodeID == uuid.Nil {
			continue
		}
		if _, ok := owned[endpoint.NodeID.String()+"|"+endpoint.Address]; !ok {
			return ErrEndpointAddressNotOnNode
		}
	}
	return nil
}

// validateLineGroupReference: a line group's L2 configuration (L2配置) is an
// L2 topology configuration of the scope (migration 504), never another line
// group; its region is empty (any) or the group's.
func validateLineGroupReference(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	region string,
	l2ConfigID *uuid.UUID,
) error {
	if l2ConfigID == nil {
		return nil
	}
	if *l2ConfigID == uuid.Nil {
		return ErrInvalidInput
	}
	var configRegion string
	err := tx.QueryRow(ctx, `SELECT region FROM l2_topology_configs
		WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE`, scopeID, *l2ConfigID).Scan(&configRegion)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidInput
	}
	if err != nil {
		return fmt.Errorf("load line group L2 configuration: %w", err)
	}
	if configRegion != "" && configRegion != region {
		return ErrInvalidInput
	}
	return nil
}

func deleteGroupRequestDigest(groupID uuid.UUID, expectedRevision int64) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.node-scheduling.group-delete-request/v1\x00"))
	_, _ = hash.Write(groupID[:])
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(expectedRevision))
	_, _ = hash.Write(encoded[:])
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func (s *Service) putGroup(
	ctx context.Context,
	actor Actor,
	request PutGroupRequest,
	operation string,
	rollbackRevision int64,
) (WriteResult, error) {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ResourceScopeID() == uuid.Nil {
		return WriteResult{}, ErrInvalidInput
	}
	normalized, err := normalizePutRequest(request)
	if err != nil {
		return WriteResult{}, err
	}
	if rollbackRevision > 0 {
		normalized.requestDigest = bindRollbackSource(normalized.requestDigest, rollbackRevision)
		normalized.v233RequestDigest = bindRollbackSource(normalized.v233RequestDigest, rollbackRevision)
		normalized.v226RequestDigest = bindRollbackSource(normalized.v226RequestDigest, rollbackRevision)
		normalized.v233ReplayEligible = normalized.l2ConfigID == nil && normalized.failoverMode == defaultFailoverMode &&
			(normalized.ipv4ResolvedValue == "" || normalized.ipv4ResolvedValue == defaultIPv4ResolvedValue(normalized.groupID))
		normalized.v226ReplayEligible = normalized.v233ReplayEligible && len(normalized.endpoints) > 0
	}
	if normalized.purpose != PurposeGeneral {
		// A replay must not cross purposes (general requests keep their
		// historical digests).
		normalized.requestDigest = bindPurpose(normalized.requestDigest, normalized.purpose)
		normalized.v233ReplayEligible, normalized.v226ReplayEligible = false, false
	}
	if normalized.groupID == uuid.Nil {
		normalized.groupID, err = uuid.NewV7()
		if err != nil {
			return WriteResult{}, err
		}
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var result WriteResult
	var supplyGuard marketsupplyguard.Snapshot
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if normalized.purpose == PurposeMarketSupply {
			// Before any node or line group lock, as node writes take it.
			if err := marketsupplyguard.Lock(ctx, tx); err != nil {
				return err
			}
		}
		if err := s.authorizePurpose(ctx, tx, actor, normalized.purpose); err != nil {
			return err
		}
		stored, found, err := s.replayOrClaim(ctx, tx, actor, operation, normalized, now)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(stored, &result); err != nil {
				return fmt.Errorf("decode node scheduling replay: %w", err)
			}
			result.Replayed = true
			return nil
		}
		normalized, err = applyGroupDefaults(normalized)
		if err != nil {
			return err
		}
		if err := lockLineGroupReferences(ctx, tx, actor.ScopeID); err != nil {
			return err
		}
		// Site writes lock their scope's configuration row through the
		// revision trigger; take those rows before the group like they do.
		usingScopes, err := lockLineGroupUsingScopes(ctx, tx, normalized.groupID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, normalized.groupID.String()); err != nil {
			return fmt.Errorf("lock node line group: %w", err)
		}
		var currentRevision int64
		var currentPurpose string
		var currentL2ConfigID *uuid.UUID
		err = tx.QueryRow(ctx, `
			SELECT current_revision,purpose,l2_config_id
			FROM node_line_groups
			WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL
			FOR UPDATE`, actor.ScopeID, normalized.groupID).Scan(&currentRevision, &currentPurpose, &currentL2ConfigID)
		creating := errors.Is(err, pgx.ErrNoRows)
		if err != nil && !creating {
			return fmt.Errorf("lock node line group: %w", err)
		}
		if !creating && currentPurpose != normalized.purpose {
			// The line group API does not see market supply groups and the
			// supply path does not write ordinary ones.
			return ErrNotFound
		}
		if (creating && normalized.expectedRevision != 0) ||
			(!creating && currentRevision != normalized.expectedRevision) {
			return ErrRevisionConflict
		}
		if err := validateLineGroupReference(ctx, tx, actor.ScopeID, normalized.region, normalized.l2ConfigID); err != nil {
			return err
		}
		if !creating {
			if normalized.purpose == PurposeMarketSupply {
				// ADR 0012 §18.4 / U3: with a normal subscriber the supply
				// keeps an online available node (checked after the write).
				if supplyGuard, err = marketsupplyguard.GroupSnapshot(ctx, tx, normalized.groupID); err != nil {
					return err
				}
			}
		}
		newRevision := normalized.expectedRevision + 1
		if creating {
			_, err = tx.Exec(ctx, `
				INSERT INTO node_line_groups (
					id,tenant_scope_id,name,region,resolved_value,ipv4_resolved_value,l2_config_id,failover_mode,
					note,sort_order,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at,purpose
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12,$13,$13,$14)`,
				normalized.groupID, actor.ScopeID, normalized.name, normalized.region, normalized.resolvedValue,
				normalized.ipv4ResolvedValue, normalized.l2ConfigID, normalized.failoverMode, normalized.note,
				normalized.sortOrder, newRevision, actor.UserID, now, normalized.purpose)
			if err != nil {
				return classifyWriteError(err)
			}
		}
		var previousNodes []uuid.UUID
		if !creating {
			if previousNodes, err = enabledLineGroupNodes(ctx, tx, actor.ScopeID, normalized.groupID, currentRevision); err != nil {
				return err
			}
		}
		if err := validateEndpointNodeAddresses(ctx, tx, actor.ScopeID, normalized.endpoints); err != nil {
			return err
		}
		if err := insertRevision(ctx, tx, actor, normalized, newRevision, now); err != nil {
			return classifyWriteError(err)
		}
		if !creating {
			command, err := tx.Exec(ctx, `
				UPDATE node_line_groups
				SET name=$4,region=$5,resolved_value=$6,ipv4_resolved_value=$7,l2_config_id=$8,failover_mode=$9,
				    note=$10,sort_order=$11,current_revision=$12,updated_by_user_id=$13,updated_at=$14
				WHERE tenant_scope_id=$1 AND id=$2 AND current_revision=$3`,
				actor.ScopeID, normalized.groupID, normalized.expectedRevision, normalized.name, normalized.region,
				normalized.resolvedValue, normalized.ipv4ResolvedValue, normalized.l2ConfigID, normalized.failoverMode,
				normalized.note, normalized.sortOrder, newRevision, actor.UserID, now)
			if err != nil {
				return classifyWriteError(err)
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
			if err := supplyGuard.Verify(ctx, tx); err != nil {
				return fmt.Errorf("%w: %w", ErrMarketSupplyInUse, err)
			}
		}
		var displayID string
		if err := tx.QueryRow(ctx, `SELECT display_id::text FROM node_line_groups
			WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL`, actor.ScopeID, normalized.groupID).Scan(&displayID); err != nil {
			return fmt.Errorf("load node line-group display ID: %w", err)
		}
		result.Group = buildRevision(actor, normalized, newRevision, displayID, now)
		endpointIDs := make([]uuid.UUID, len(result.Group.Endpoints))
		for index, endpoint := range result.Group.Endpoints {
			endpointIDs[index] = endpoint.ID
		}
		rows, err := tx.Query(ctx, `SELECT display_id::text FROM node_line_endpoint_display_ids
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND endpoint_id=ANY($3::uuid[])
			ORDER BY array_position($3::uuid[],endpoint_id)`, actor.ScopeID, normalized.groupID, endpointIDs)
		if err != nil {
			return fmt.Errorf("load node line endpoint display IDs: %w", err)
		}
		displayIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil || len(displayIDs) != len(endpointIDs) {
			return fmt.Errorf("incomplete node line endpoint display IDs: %v", err)
		}
		for index, value := range displayIDs {
			result.Group.Endpoints[index].DisplayID = value
		}
		payload := map[string]any{
			"configuration_digest": hex.EncodeToString(normalized.configDigest[:]),
			"endpoint_count":       len(normalized.endpoints),
			"region":               normalized.region,
			"resolved_value":       normalized.resolvedValue,
			"ipv4_resolved_value":  normalized.ipv4ResolvedValue,
			"l2_config_id":         normalized.l2ConfigID,
			"failover_mode":        normalized.failoverMode,
			"note":                 normalized.note,
			"sort_order":           normalized.sortOrder,
			"previous_revision":    normalized.expectedRevision,
			"revision":             newRevision,
		}
		if rollbackRevision > 0 {
			payload["rollback_source_revision"] = rollbackRevision
		}
		if !creating && len(usingScopes) > 0 {
			currentNodes, err := enabledLineGroupNodes(ctx, tx, actor.ScopeID, normalized.groupID, newRevision)
			if err != nil {
				return err
			}
			// fix-autol2b: another L2 configuration changes the L2 of the
			// using scopes' automatic publications too
			if !slices.Equal(previousNodes, currentNodes) || !equalOptionalUUID(currentL2ConfigID, normalized.l2ConfigID) {
				queued, err := s.republishUsingScopes(ctx, tx, usingScopes, normalized.groupID, normalized.requestID)
				if err != nil {
					return err
				}
				payload["publication_scopes"] = len(usingScopes)
				payload["automatic_publications"] = queued
			}
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operation,
			ResourceType: "node_line_group", ResourceID: normalized.groupID.String(),
			RequestID: normalized.requestID, Result: "success",
			Payload: payload,
		}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, operation, normalized.idempotencyKey, result, now)
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("put node line group: %w", err)
	}
	return result, nil
}

func (s *Service) Rollback(
	ctx context.Context,
	actor Actor,
	groupID uuid.UUID,
	sourceRevision, expectedRevision int64,
	idempotencyKey, requestID string,
) (WriteResult, error) {
	if sourceRevision < 1 || expectedRevision < 1 || sourceRevision > expectedRevision {
		return WriteResult{}, ErrInvalidInput
	}
	historical, err := s.GetRevision(ctx, actor, groupID, sourceRevision)
	if err != nil {
		return WriteResult{}, err
	}
	return s.putGroup(ctx, actor, PutGroupRequest{
		GroupID: groupID, ExpectedRevision: expectedRevision, Name: historical.Name,
		Region: historical.Region, ResolvedValue: historical.ResolvedValue,
		IPv4ResolvedValue: historical.IPv4ResolvedValue, L2ConfigID: historical.L2ConfigID,
		FailoverMode: historical.FailoverMode, Note: historical.Note, SortOrder: historical.SortOrder,
		Policy: historical.Policy, Endpoints: historical.Endpoints,
		IdempotencyKey: idempotencyKey, RequestID: requestID,
	}, operationGroupRollback, sourceRevision)
}

func bindRollbackSource(requestDigest [32]byte, sourceRevision int64) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.node-scheduling.rollback-request/v1\x00"))
	_, _ = hash.Write(requestDigest[:])
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(sourceRevision))
	_, _ = hash.Write(encoded[:])
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func insertRevision(ctx context.Context, tx pgx.Tx, actor Actor, input normalizedPut, revision int64, now time.Time) error {
	policy := canonicalizePolicy(input.policy)
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_line_group_revisions (
			line_group_id,tenant_scope_id,revision,name,region,resolved_value,ipv4_resolved_value,l2_config_id,
			failover_mode,note,sort_order,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,
			failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		input.groupID, actor.ScopeID, revision, input.name, input.region, input.resolvedValue, input.ipv4ResolvedValue,
		input.l2ConfigID, input.failoverMode, input.note, input.sortOrder, policy.ProbeIntervalMS, policy.ProbeTimeoutMS,
		policy.FailureThreshold, policy.RecoveryThreshold, policy.FailureDebounceMS, policy.RecoveryDebounceMS,
		len(input.endpoints), input.configDigest[:], actor.UserID, now); err != nil {
		return err
	}
	for _, endpoint := range input.endpoints {
		address, _ := netip.ParseAddr(endpoint.Address)
		addressFamily := 6
		if address.Is4() {
			addressFamily = 4
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO node_line_endpoints (
				id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
				port,region,carrier,priority,sort_order,weight,enabled
			) VALUES ($1,NULLIF($2,'')::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			endpoint.ID, uuidString(endpoint.NodeID), actor.ScopeID, input.groupID, revision, endpoint.Address,
			addressFamily, endpoint.Port, endpoint.Region, endpoint.Carrier,
			endpoint.Priority, endpoint.SortOrder, endpoint.Weight, endpoint.Enabled); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO node_line_endpoint_health (
				tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
				consecutive_successes,consecutive_failures,last_sequence,last_changed_at,
				row_revision,created_at,updated_at
			) VALUES ($1,$2,$3,$4,'unknown',0,0,0,$5,1,$5,$5)`,
			actor.ScopeID, input.groupID, revision, endpoint.ID, now); err != nil {
			return err
		}
	}
	command, err := tx.Exec(ctx, `
		UPDATE node_line_group_revisions
		SET sealed_at=$4
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3 AND sealed_at IS NULL`,
		actor.ScopeID, input.groupID, revision, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func buildRevision(actor Actor, input normalizedPut, revision int64, displayID string, now time.Time) LineGroupRevision {
	endpoints := make([]Endpoint, len(input.endpoints))
	for index, endpoint := range input.endpoints {
		endpoints[index] = endpoint
		endpoints[index].Health = HealthState{
			Status: HealthUnknown, LastChangedAt: now, RowRevision: 1, CreatedAt: now, UpdatedAt: now,
		}
	}
	return LineGroupRevision{
		GroupID: input.groupID, DisplayID: displayID, TenantScopeID: actor.ScopeID, Revision: revision,
		Name: input.name, Region: input.region, ResolvedValue: input.resolvedValue,
		IPv4ResolvedValue: input.ipv4ResolvedValue, L2ConfigID: cloneUUIDPointer(input.l2ConfigID),
		FailoverMode: input.failoverMode, Note: input.note, SortOrder: input.sortOrder,
		Policy: input.policy, Endpoints: endpoints,
		ConfigurationDigest: bytes.Clone(input.configDigest[:]), CreatedByUserID: actor.UserID,
		CreatedAt: now, SealedAt: now,
	}
}

func (s *Service) GetCurrent(ctx context.Context, actor Actor, groupID uuid.UUID) (LineGroupRevision, error) {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ResourceScopeID() == uuid.Nil || groupID == uuid.Nil {
		return LineGroupRevision{}, ErrInvalidInput
	}
	var result LineGroupRevision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		var err error
		result, err = loadRevision(ctx, tx, actor.ResourceScopeID(), groupID, 0)
		if err != nil {
			return err
		}
		return attachReadState(ctx, tx, &result)
	})
	return result, err
}

func (s *Service) GetRevision(ctx context.Context, actor Actor, groupID uuid.UUID, revision int64) (LineGroupRevision, error) {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ResourceScopeID() == uuid.Nil || groupID == uuid.Nil || revision < 1 {
		return LineGroupRevision{}, ErrInvalidInput
	}
	var result LineGroupRevision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		var err error
		result, err = loadRevision(ctx, tx, actor.ResourceScopeID(), groupID, revision)
		return err
	})
	return result, err
}

func (s *Service) PlanCurrent(ctx context.Context, actor Actor, groupID uuid.UUID, selector Selector) (Plan, error) {
	group, err := s.GetCurrent(ctx, actor, groupID)
	if err != nil {
		return Plan{}, err
	}
	return BuildPlan(group, selector, s.now().UTC())
}

type revisionQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadRevision(ctx context.Context, pool revisionQuerier, tenantScopeID, groupID uuid.UUID, revision int64) (LineGroupRevision, error) {
	return loadRevisionOfPurpose(ctx, pool, tenantScopeID, groupID, revision, PurposeGeneral)
}

// loadRevisionOfPurpose is loadRevision for a group of purpose (migration 422).
func loadRevisionOfPurpose(ctx context.Context, pool revisionQuerier, tenantScopeID, groupID uuid.UUID, revision int64,
	purpose string,
) (LineGroupRevision, error) {
	var result LineGroupRevision
	var intervalMS, timeoutMS, failureDebounceMS, recoveryDebounceMS int64
	var endpointCount int
	var l2ConfigID *uuid.UUID
	query := `
		SELECT line_group.display_id::text,revision.name,revision.region,revision.resolved_value,
		       revision.ipv4_resolved_value,revision.l2_config_id,revision.failover_mode,
		       revision.note,revision.sort_order,revision.revision,revision.probe_interval_ms,revision.probe_timeout_ms,
		       revision.failure_threshold,revision.recovery_threshold,
		       revision.failure_debounce_ms,revision.recovery_debounce_ms,
		       revision.endpoint_count,revision.configuration_digest,revision.created_by_user_id,
		       revision.created_at,revision.sealed_at,line_group.is_platform_default
		FROM node_line_groups line_group
		JOIN node_line_group_revisions revision
		  ON revision.tenant_scope_id=line_group.tenant_scope_id
		 AND revision.line_group_id=line_group.id
		 AND revision.revision=CASE WHEN $3::bigint=0 THEN line_group.current_revision ELSE $3 END
		WHERE line_group.tenant_scope_id=$1 AND line_group.id=$2 AND line_group.deleted_at IS NULL
		  AND line_group.purpose=$4`
	err := pool.QueryRow(ctx, query, tenantScopeID, groupID, revision, purpose).Scan(
		&result.DisplayID, &result.Name, &result.Region, &result.ResolvedValue,
		&result.IPv4ResolvedValue, &l2ConfigID, &result.FailoverMode, &result.Note, &result.SortOrder,
		&result.Revision, &intervalMS, &timeoutMS,
		&result.Policy.FailureThreshold, &result.Policy.RecoveryThreshold,
		&failureDebounceMS, &recoveryDebounceMS, &endpointCount, &result.ConfigurationDigest,
		&result.CreatedByUserID, &result.CreatedAt, &result.SealedAt, &result.IsPlatformDefault,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return LineGroupRevision{}, ErrNotFound
	}
	if err != nil {
		return LineGroupRevision{}, fmt.Errorf("load node line group revision: %w", err)
	}
	result.GroupID = groupID
	result.TenantScopeID = tenantScopeID
	result.L2ConfigID = cloneUUIDPointer(l2ConfigID)
	result.Policy.ProbeInterval = time.Duration(intervalMS) * time.Millisecond
	result.Policy.ProbeTimeout = time.Duration(timeoutMS) * time.Millisecond
	result.Policy.FailureDebounce = time.Duration(failureDebounceMS) * time.Millisecond
	result.Policy.RecoveryDebounce = time.Duration(recoveryDebounceMS) * time.Millisecond
	rows, err := pool.Query(ctx, `
		SELECT endpoint.id,display.display_id::text,endpoint.node_id,host(endpoint.address),endpoint.port,endpoint.region,endpoint.carrier,
		       endpoint.priority,endpoint.sort_order,endpoint.weight,endpoint.enabled,
		       health.status,health.consecutive_successes,health.consecutive_failures,
		       health.streak_started_at,health.last_sequence,health.last_observed_at,
		       health.last_received_at,health.last_probe_digest,health.last_probe_healthy,
		       health.last_changed_at,
		       health.row_revision,health.created_at,health.updated_at
		FROM node_line_endpoints endpoint
		JOIN node_line_endpoint_display_ids display
		  ON display.tenant_scope_id=endpoint.tenant_scope_id
		 AND display.line_group_id=endpoint.line_group_id AND display.endpoint_id=endpoint.id
		JOIN node_line_endpoint_health health
		  ON health.tenant_scope_id=endpoint.tenant_scope_id
		 AND health.line_group_id=endpoint.line_group_id
		 AND health.config_revision=endpoint.config_revision
		 AND health.endpoint_id=endpoint.id
		WHERE endpoint.tenant_scope_id=$1 AND endpoint.line_group_id=$2 AND endpoint.config_revision=$3
		ORDER BY endpoint.priority,endpoint.sort_order,family(endpoint.address),endpoint.address,endpoint.port,endpoint.id`,
		tenantScopeID, groupID, result.Revision)
	if err != nil {
		return LineGroupRevision{}, fmt.Errorf("load node line endpoints: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var endpoint Endpoint
		var nodeID *uuid.UUID
		if err := rows.Scan(
			&endpoint.ID, &endpoint.DisplayID, &nodeID, &endpoint.Address, &endpoint.Port, &endpoint.Region, &endpoint.Carrier,
			&endpoint.Priority, &endpoint.SortOrder, &endpoint.Weight, &endpoint.Enabled,
			&endpoint.Health.Status, &endpoint.Health.ConsecutiveSuccesses,
			&endpoint.Health.ConsecutiveFailures, &endpoint.Health.StreakStartedAt,
			&endpoint.Health.LastSequence, &endpoint.Health.LastObservedAt,
			&endpoint.Health.LastReceivedAt, &endpoint.Health.LastProbeDigest,
			&endpoint.Health.LastProbeHealthy, &endpoint.Health.LastChangedAt, &endpoint.Health.RowRevision,
			&endpoint.Health.CreatedAt, &endpoint.Health.UpdatedAt,
		); err != nil {
			return LineGroupRevision{}, fmt.Errorf("scan node line endpoint: %w", err)
		}
		if nodeID != nil {
			endpoint.NodeID = *nodeID
		}
		result.Endpoints = append(result.Endpoints, endpoint)
	}
	if err := rows.Err(); err != nil {
		return LineGroupRevision{}, fmt.Errorf("iterate node line endpoints: %w", err)
	}
	if len(result.Endpoints) != endpointCount {
		return LineGroupRevision{}, errors.New("node line group endpoint snapshot is incomplete")
	}
	return result, nil
}

func (s *Service) authorizeTx(ctx context.Context, tx pgx.Tx, actor Actor, permission string, write bool) error {
	if s.iam == nil {
		if write {
			return authorizeWrite(ctx, tx, actor, permission)
		}
		return authorize(ctx, tx, actor, permission)
	}
	var authorization iamlock.Authorization
	var err error
	switch actor.Credential.Kind {
	case CredentialSession:
		authorization, err = s.iam.AuthorizeSession(ctx, tx, actor.Credential.Raw, actor.ResourceScopeID(), permission)
	case CredentialAPIKey:
		if actor.ScopeKind == "platform" {
			return ErrCredentialInvalid
		}
		authorization, err = s.iam.AuthorizeAPIKey(ctx, tx, actor.Credential.Raw, actor.ResourceScopeID(), permission)
	default:
		return ErrCredentialInvalid
	}
	if errors.Is(err, iamlock.ErrInvalidCredential) {
		return ErrCredentialInvalid
	}
	if errors.Is(err, iamlock.ErrPermissionDenied) {
		return ErrPermissionDenied
	}
	if err != nil {
		return fmt.Errorf("authorize node scheduling credential: %w", err)
	}
	if !authorization.Valid() || authorization.UserID() != actor.UserID ||
		authorization.AuthenticationScopeID() != actor.ScopeID || authorization.TargetScopeID() != actor.ResourceScopeID() {
		return ErrCredentialInvalid
	}
	if write && actor.ScopeKind == "platform" && actor.ResourceScopeID() != actor.ScopeID {
		return ErrPlatformWriteDenied
	}
	return nil
}

func authorize(ctx context.Context, querier rowQuerier, actor Actor, permission string) error {
	var permitted bool
	err := querier.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM custom_rbac_effective_permissions($1,$2)
		WHERE permission_name=$3
	)`, actor.ScopeID, actor.UserID, permission).Scan(&permitted)
	if err != nil {
		return fmt.Errorf("authorize node scheduling actor: %w", err)
	}
	if !permitted {
		return ErrPermissionDenied
	}
	return nil
}

func authorizeWrite(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if actor.ResourceScopeID() != actor.ScopeID {
		return ErrPlatformWriteDenied
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`,
		"custom-rbac-tenant:"+actor.ScopeID.String()); err != nil {
		return fmt.Errorf("lock node scheduling authorization: %w", err)
	}
	var scopeKind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes
		WHERE id=$1 FOR SHARE`, actor.ScopeID).Scan(&scopeKind, &tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		return fmt.Errorf("lock node scheduling scope: %w", err)
	}
	if actor.ScopeKind != "" && scopeKind != actor.ScopeKind ||
		scopeKind != "tenant" && scopeKind != "platform" ||
		scopeKind == "tenant" && tenantID == nil || scopeKind == "platform" && tenantID != nil {
		return ErrPermissionDenied
	}
	var tenantStatus = "active"
	if tenantID != nil {
		if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR SHARE`, *tenantID).
			Scan(&tenantStatus); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrPermissionDenied
			}
			return fmt.Errorf("lock node scheduling tenant: %w", err)
		}
	}
	var userStatus, membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR SHARE`, actor.UserID).
		Scan(&userStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		return fmt.Errorf("lock node scheduling account: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE scope_id=$1 AND user_id=$2 FOR SHARE`, actor.ScopeID, actor.UserID).
		Scan(&membershipStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		return fmt.Errorf("lock node scheduling membership: %w", err)
	}
	if tenantStatus != "active" || userStatus != "active" || membershipStatus != "active" {
		return ErrPermissionDenied
	}
	if scopeKind == "platform" {
		return authorize(ctx, tx, actor, "platform.admin")
	}
	return authorize(ctx, tx, actor, permission)
}

func cloneUUIDPointer(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func (s *Service) replayOrClaim(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation string,
	input normalizedPut,
	now time.Time,
) ([]byte, bool, error) {
	compatible := make([][32]byte, 0, 2)
	if input.v233ReplayEligible {
		compatible = append(compatible, input.v233RequestDigest)
	}
	if input.v226ReplayEligible {
		compatible = append(compatible, input.v226RequestDigest)
	}
	return claimWrite(ctx, tx, actor, operation, input.idempotencyKey, input.requestDigest,
		input.groupID, now, compatible...)
}

func claimWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key string,
	requestDigest [32]byte,
	targetGroupID uuid.UUID,
	now time.Time,
	compatibleRequestDigests ...[32]byte,
) ([]byte, bool, error) {
	writeID, err := uuid.NewV7()
	if err != nil {
		return nil, false, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO node_scheduling_write_requests (
			id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			target_group_id,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (tenant_scope_id,actor_user_id,operation,idempotency_key) DO NOTHING`,
		writeID, actor.ScopeID, actor.UserID, operation, key,
		requestDigest[:], targetGroupID, now)
	if err != nil {
		return nil, false, err
	}
	if command.RowsAffected() == 1 {
		return nil, false, nil
	}
	var existingDigest, response []byte
	var completedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT request_digest,response_body,completed_at
		FROM node_scheduling_write_requests
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4`,
		actor.ScopeID, actor.UserID, operation, key).Scan(
		&existingDigest, &response, &completedAt)
	if err != nil {
		return nil, false, err
	}
	if !writeReplayMatches(existingDigest, requestDigest, completedAt, response, compatibleRequestDigests...) {
		return nil, false, ErrIdempotencyConflict
	}
	return response, true, nil
}

func writeReplayMatches(
	existingDigest []byte,
	requestDigest [32]byte,
	completedAt *time.Time,
	response []byte,
	compatibleRequestDigests ...[32]byte,
) bool {
	if completedAt == nil || len(response) == 0 {
		return false
	}
	if bytes.Equal(existingDigest, requestDigest[:]) {
		return true
	}
	for _, compatibleDigest := range compatibleRequestDigests {
		if bytes.Equal(existingDigest, compatibleDigest[:]) {
			return true
		}
	}
	return false
}

func completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key string,
	result any,
	now time.Time,
) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE node_scheduling_write_requests
		SET response_body=$5,completed_at=$6
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND operation=$3
		  AND idempotency_key=$4 AND completed_at IS NULL`,
		actor.ScopeID, actor.UserID, operation, key, encoded, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func classifyWriteError(err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		if databaseError.ConstraintName == "node_line_groups_tenant_name_idx" {
			return ErrNameConflict
		}
		if databaseError.ConstraintName == "node_line_groups_scope_resolved_value_unique" ||
			databaseError.ConstraintName == "node_line_groups_scope_ipv4_resolved_value_unique_234" {
			return fmt.Errorf("%w: database constraint %s", ErrInvalidInput, databaseError.ConstraintName)
		}
		if databaseError.Code == "P5043" {
			return ErrInvalidInput
		}
		if databaseError.Code == "23503" {
			return fmt.Errorf("%w: database constraint %s", ErrInvalidInput, databaseError.ConstraintName)
		}
		if databaseError.Code == "23505" {
			return ErrRevisionConflict
		}
		if databaseError.Code == "23514" || databaseError.Code == "23P01" {
			return fmt.Errorf("%w: database constraint %s", ErrInvalidInput, databaseError.ConstraintName)
		}
	}
	return err
}

func equalOptionalUUID(left, right *uuid.UUID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
