package node

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	guard   *entitlementguard.Guard
	now     func() time.Time
}

type createStoreInput struct {
	ID             uuid.UUID
	Actor          Actor
	Name           string
	Description    string
	Region         string
	IPv4           string
	IPv6           string
	RequestID      string
	IdempotencyKey string
	IssueToken     bool
	TokenPurpose   string
	TokenTTL       time.Duration
}

type issueStoreInput struct {
	Metadata  TokenMetadata
	TokenHash []byte
}

type consumeStoreInput struct {
	TokenHash     []byte
	Purpose       string
	RequestID     string
	RequestDigest []byte
}

type storedNodeWrite struct {
	Response []byte
	Found    bool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return NewStoreWithClock(pool, time.Now, nil)
}

func NewStoreWithClock(pool *pgxpool.Pool, now func() time.Time, trust *entitlementguard.TrustStore) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		pool: pool, auditor: audit.New(pool), guard: entitlementguard.NewGuard(pool, now, trust), now: now,
	}
}

func (s *Store) Create(ctx context.Context, input createStoreInput, digest [32]byte) (CreateResult, error) {
	var result CreateResult
	var rawToken string
	var denial error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := requirePlatformScope(ctx, tx, input.Actor.ScopeID); err != nil {
			return err
		}
		stored, err := s.replayOrClaimWrite(ctx, tx, input.Actor, "node.create", input.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if stored.Found {
			if err := json.Unmarshal(stored.Response, &result); err != nil {
				return fmt.Errorf("decode stored node create response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if err := s.guard.CheckNodeCreate(ctx, tx, entitlementguard.NodeCheck{
			AuditScopeID: input.Actor.ScopeID,
			ActorUserID:  input.Actor.UserID,
			ResourceID:   input.ID,
			RequestID:    input.RequestID,
			Operation:    "node.create",
		}); err != nil {
			if !entitlementguard.IsDenial(err) {
				return err
			}
			command, deleteErr := tx.Exec(ctx, `
				DELETE FROM node_write_requests
				WHERE actor_user_id = $1 AND operation = 'node.create' AND idempotency_key = $2
				  AND completed_at IS NULL`, input.Actor.UserID, input.IdempotencyKey)
			if deleteErr != nil {
				return deleteErr
			}
			if command.RowsAffected() != 1 {
				return ErrIdempotencyConflict
			}
			denial = err
			return nil
		}
		displayID, err := allocateNodeDisplayID(ctx, tx, input.Actor.ScopeID, s.now().UTC())
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO nodes (
				id, display_id, scope_id, name, description, region, ipv4, ipv6, created_by_user_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING id, display_id::text, name, description, region, host(ipv4), host(ipv6),
			          admin_state, management_settings, revision, created_at, updated_at`,
			input.ID,
			displayID,
			input.Actor.ScopeID,
			input.Name,
			input.Description,
			input.Region,
			nullable(input.IPv4),
			nullable(input.IPv6),
			input.Actor.UserID,
		).Scan(nodeScanTargets(&result.Node)...)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrDuplicateName
			}
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      input.Actor.ScopeID,
			ActorUserID:  &input.Actor.UserID,
			Action:       "node.create",
			ResourceType: "node",
			ResourceID:   input.ID.String(),
			RequestID:    input.RequestID,
			Result:       "success",
			Payload: map[string]any{
				"admin_state": StatePending,
				"name":        input.Name,
			},
		}); err != nil {
			return err
		}
		if input.IssueToken {
			metadata, raw, tokenHash, err := newToken(input.ID, input.TokenPurpose, input.TokenTTL, s.now)
			if err != nil {
				return err
			}
			issued, err := s.insertToken(ctx, tx, input.Actor, issueStoreInput{
				Metadata: metadata, TokenHash: tokenHash,
			}, input.RequestID)
			if err != nil {
				return err
			}
			result.EnrollmentToken = &issued
			rawToken = raw
		}
		storedResult := CreateResult{Node: result.Node}
		return s.completeWrite(ctx, tx, input.Actor, "node.create", input.IdempotencyKey, &input.ID, storedResult)
	})
	if err != nil {
		return CreateResult{}, fmt.Errorf("create node: %w", err)
	}
	if denial != nil {
		return CreateResult{}, fmt.Errorf("create node: %w", denial)
	}
	if result.EnrollmentToken != nil {
		result.EnrollmentToken.Token = rawToken
	}
	return result, nil
}

func (s *Store) IssueToken(
	ctx context.Context,
	actor Actor,
	input issueStoreInput,
	requestID string,
) (IssuedToken, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return IssuedToken{}, fmt.Errorf("begin token issuance: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := requirePlatformScope(ctx, tx, actor.ScopeID); err != nil {
		return IssuedToken{}, err
	}
	var state string
	err = tx.QueryRow(ctx, `
		SELECT admin_state FROM nodes
		WHERE id = $1 AND scope_id = $2
		FOR UPDATE`, input.Metadata.NodeID, actor.ScopeID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return IssuedToken{}, ErrNotFound
	}
	if err != nil {
		return IssuedToken{}, fmt.Errorf("lock node for token issuance: %w", err)
	}
	if state == StateDisabled || state == StateRetired {
		if err := s.appendEnrollmentDenied(ctx, tx, actor.ScopeID, &actor.UserID, input.Metadata.NodeID.String(), requestID, "node_"+state); err != nil {
			return IssuedToken{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return IssuedToken{}, fmt.Errorf("commit token issuance denial: %w", err)
		}
		return IssuedToken{}, ErrEnrollmentDenied
	}
	issued, err := s.insertToken(ctx, tx, actor, input, requestID)
	if err != nil {
		return IssuedToken{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return IssuedToken{}, fmt.Errorf("commit token issuance: %w", err)
	}
	return issued, nil
}

func (s *Store) insertToken(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	input issueStoreInput,
	requestID string,
) (IssuedToken, error) {
	_, err := tx.Exec(ctx, `
		INSERT INTO node_enrollment_tokens (
			id, node_id, purpose, token_hash, created_by_user_id, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		input.Metadata.ID,
		input.Metadata.NodeID,
		input.Metadata.Purpose,
		input.TokenHash,
		actor.UserID,
		input.Metadata.CreatedAt,
		input.Metadata.ExpiresAt,
	)
	if err != nil {
		return IssuedToken{}, fmt.Errorf("insert enrollment token: %w", err)
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID:      actor.ScopeID,
		ActorUserID:  &actor.UserID,
		Action:       "node.enrollment_token.issue",
		ResourceType: "node_enrollment_token",
		ResourceID:   input.Metadata.ID.String(),
		RequestID:    requestID,
		Result:       "success",
		Payload: map[string]any{
			"expires_at": input.Metadata.ExpiresAt.UTC().Format(time.RFC3339Nano),
			"node_id":    input.Metadata.NodeID.String(),
			"purpose":    input.Metadata.Purpose,
		},
	}); err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{TokenMetadata: input.Metadata}, nil
}

func (s *Store) List(ctx context.Context, request ListRequest) (ListResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, display_id::text, name, description, region, host(ipv4), host(ipv6),
		       admin_state, management_settings, revision, created_at, updated_at
		FROM nodes
		WHERE scope_id = $1
		  AND ($2 = '' OR admin_state = $2)
		  AND ($3::uuid IS NULL OR id > $3)
		ORDER BY id
		LIMIT $4`, request.ScopeID, request.State, request.After, request.Limit+1)
	if err != nil {
		return ListResult{}, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()
	items := make([]Node, 0, request.Limit)
	for rows.Next() {
		var item Node
		if err := rows.Scan(nodeScanTargets(&item)...); err != nil {
			return ListResult{}, fmt.Errorf("scan node list: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, fmt.Errorf("list nodes: %w", err)
	}
	result := ListResult{Items: items}
	if len(items) > request.Limit {
		cursor := items[request.Limit-1].ID
		result.NextCursor = &cursor
		result.Items = items[:request.Limit]
	}
	return result, nil
}

func (s *Store) Get(ctx context.Context, scopeID uuid.UUID, nodeID uuid.UUID) (Node, error) {
	var item Node
	err := s.pool.QueryRow(ctx, `
		SELECT id, display_id::text, name, description, region, host(ipv4), host(ipv6),
		       admin_state, management_settings, revision, created_at, updated_at
		FROM nodes
		WHERE id = $1 AND scope_id = $2`, nodeID, scopeID).Scan(nodeScanTargets(&item)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	if err != nil {
		return Node{}, fmt.Errorf("get node: %w", err)
	}
	return item, nil
}

func (s *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (WriteResult, error) {
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// First, before any node or line group lock (marketsupplyguard.Lock).
		if err := marketsupplyguard.Lock(ctx, tx); err != nil {
			return err
		}
		if err := requirePlatformScope(ctx, tx, actor.ScopeID); err != nil {
			return err
		}
		if err := lockNodeScope(ctx, tx, actor.ScopeID); err != nil {
			return err
		}
		stored, err := s.replayOrClaimWrite(ctx, tx, actor, "node.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if stored.Found {
			if err := json.Unmarshal(stored.Response, &result.Node); err != nil {
				return fmt.Errorf("decode stored node update response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if request.Fields.AdminState != nil && *request.Fields.AdminState == StateRetired {
			if err := lockHTTP01Overlay(ctx, tx); err != nil {
				return err
			}
		}
		current, err := lockNode(ctx, tx, actor.ScopeID, request.ID)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		hasAuthorization, err := s.initializationEvidence(ctx, tx, current)
		if err != nil {
			return err
		}
		targetState := ""
		if request.Fields.AdminState != nil {
			targetState = *request.Fields.AdminState
		}
		if err := validateStateChange(current.AdminState, targetState, hasAuthorization); err != nil {
			return err
		}
		if targetState == StateRetired {
			// Deleting is a purge: the node row and its own data are removed.
			if request.Fields != (UpdateFields{AdminState: request.Fields.AdminState}) {
				return ErrInvalidInput
			}
			deleted, err := s.purgeNode(ctx, tx, actor, current, request.RequestID)
			if err != nil {
				return err
			}
			result.Node = deleted
			return s.completeWrite(ctx, tx, actor, "node.update", request.IdempotencyKey, &deleted.ID, deleted)
		}
		supply, err := marketsupplyguard.NodeSnapshot(ctx, tx, current.ID)
		if err != nil {
			return err
		}
		beforeState := current.AdminState
		beforeIPv4, beforeIPv6 := current.IPv4, current.IPv6
		beforeRegion := current.Region
		beforeSettings := current.ManagementSettings
		changedFields := applyUpdateFields(&current, request.Fields)
		if request.Fields.ManagementSettings != nil {
			// manual fields as written, the others the automatic values
			resolution, err := loadIPLocationResolution(ctx, tx, current.ID)
			if err != nil {
				return err
			}
			automatic := NodeIPLocation{}
			if resolution != nil {
				automatic = resolution.Automatic
			}
			applyIPLocationWrite(beforeSettings, &current.ManagementSettings, automatic)
		}
		if err := checkStorageChange(ctx, tx, current.ID, beforeSettings, current.ManagementSettings); err != nil {
			return err
		}
		if managementSettingsUsePrimaryIP(current) {
			return ErrInvalidInput
		}
		// Initializing a node that still has no region puts it into the
		// only catalogued region (D8); with several the request names one.
		if beforeState == StatePending && current.AdminState == StateActive && current.Region == "" {
			region, err := onlyCatalogRegion(ctx, tx, actor.ScopeID)
			if err != nil {
				return err
			}
			if region != "" {
				assigned := current
				assigned.Region = region
				// Never block initialization: a node a line group of the empty
				// region already uses keeps the empty region.
				if err := ensureLineGroupRegionKept(ctx, tx, assigned); err == nil {
					current.Region = region
					if !slices.Contains(changedFields, "region") {
						changedFields = append(changedFields, "region")
					}
				} else if !errors.Is(err, ErrRegionInUse) {
					return err
				}
			}
		}
		if current.Region != beforeRegion {
			if err := ensureLineGroupRegionKept(ctx, tx, current); err != nil {
				return err
			}
		}
		if err := ensureLineGroupAddressesKept(ctx, tx, current); err != nil {
			return err
		}
		if current.AdminState == StateActive &&
			(beforeState != StateActive || !sameNodeAddress(beforeIPv4, current.IPv4) || !sameNodeAddress(beforeIPv6, current.IPv6)) {
			if err := ensureActiveNodeAddressesAvailable(ctx, tx, actor.ScopeID, current); err != nil {
				return err
			}
		}
		updated, err := updateNodeRow(ctx, tx, current, request.ExpectedRevision, s.now().UTC())
		if err != nil {
			return err
		}
		if err := supply.Verify(ctx, tx); err != nil {
			return marketSupplyError(err)
		}
		result.Node = updated
		payload := map[string]any{
			"changed_fields": changedFields,
			"from_state":     beforeState,
			"to_state":       updated.AdminState,
			"revision":       updated.Revision,
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      actor.ScopeID,
			ActorUserID:  &actor.UserID,
			Action:       "node.update",
			ResourceType: "node",
			ResourceID:   updated.ID.String(),
			RequestID:    request.RequestID,
			Result:       "success",
			Payload:      payload,
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, "node.update", request.IdempotencyKey, &updated.ID, updated)
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("update node: %w", err)
	}
	return result, nil
}

func (s *Store) BatchAdminState(
	ctx context.Context,
	actor Actor,
	request BatchAdminStateRequest,
	digest [32]byte,
) (BatchAdminStateResult, error) {
	result := BatchAdminStateResult{Items: make([]BatchAdminStateItemResult, len(request.Items))}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := marketsupplyguard.Lock(ctx, tx); err != nil {
			return err
		}
		if err := requirePlatformScope(ctx, tx, actor.ScopeID); err != nil {
			return err
		}
		if err := lockNodeScope(ctx, tx, actor.ScopeID); err != nil {
			return err
		}
		stored, err := s.replayOrClaimWrite(ctx, tx, actor, "node.batch_admin_state", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if stored.Found {
			if err := json.Unmarshal(stored.Response, &result); err != nil {
				return fmt.Errorf("decode stored node batch response: %w", err)
			}
			result.Replayed = true
			return nil
		}

		type indexedItem struct {
			index int
			item  BatchAdminStateItem
		}
		ordered := make([]indexedItem, len(request.Items))
		for index, item := range request.Items {
			ordered[index] = indexedItem{index: index, item: item}
			result.Items[index] = BatchAdminStateItemResult{ID: item.ID}
		}
		sort.Slice(ordered, func(i, j int) bool {
			return ordered[i].item.ID.String() < ordered[j].item.ID.String()
		})
		if request.AdminState == StateRetired {
			if err := lockHTTP01Overlay(ctx, tx); err != nil {
				return err
			}
		}
		for _, entry := range ordered {
			itemResult := &result.Items[entry.index]
			current, err := lockNode(ctx, tx, actor.ScopeID, entry.item.ID)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					setBatchFailure(itemResult, "node_not_found")
					continue
				}
				return err
			}
			if current.Revision != entry.item.ExpectedRevision {
				setBatchFailure(itemResult, "version_conflict")
				continue
			}
			hasAuthorization, err := s.initializationEvidence(ctx, tx, current)
			if err != nil {
				return err
			}
			if err := validateStateChange(current.AdminState, request.AdminState, hasAuthorization); err != nil {
				setBatchFailure(itemResult, batchErrorCode(err))
				continue
			}
			if request.AdminState == StateRetired {
				// Each deletion runs in its own savepoint so a node that is
				// still in use fails alone and the others are still deleted.
				var deleted Node
				err := pgx.BeginFunc(ctx, tx, func(item pgx.Tx) error {
					var err error
					deleted, err = s.purgeNode(ctx, item, actor, current, request.RequestID)
					return err
				})
				if errors.Is(err, ErrInUse) || errors.Is(err, ErrNotFound) {
					setBatchFailure(itemResult, batchErrorCode(err))
					continue
				}
				if err != nil {
					return err
				}
				itemResult.Status = "updated"
				itemResult.Node = &deleted
				continue
			}
			beforeState := current.AdminState
			current.AdminState = request.AdminState
			if beforeState == StatePending && current.AdminState == StateActive && current.Region == "" {
				// Same rule as a single initialization (D8).
				region, err := onlyCatalogRegion(ctx, tx, actor.ScopeID)
				if err != nil {
					return err
				}
				if region != "" {
					assigned := current
					assigned.Region = region
					if err := ensureLineGroupRegionKept(ctx, tx, assigned); err == nil {
						current.Region = region
					} else if !errors.Is(err, ErrRegionInUse) {
						return err
					}
				}
			}
			if current.AdminState == StateActive && beforeState != StateActive {
				if err := ensureActiveNodeAddressesAvailable(ctx, tx, actor.ScopeID, current); err != nil {
					setBatchFailure(itemResult, batchErrorCode(err))
					continue
				}
			}
			// Each item in its own savepoint: one that would leave a market
			// supply without an online node fails alone (ML-18), and the
			// next item is checked against the items applied before it.
			var updated Node
			err = pgx.BeginFunc(ctx, tx, func(item pgx.Tx) error {
				supply, err := marketsupplyguard.NodeSnapshot(ctx, item, current.ID)
				if err != nil {
					return err
				}
				if updated, err = updateNodeRow(ctx, item, current, entry.item.ExpectedRevision, s.now().UTC()); err != nil {
					return err
				}
				return supply.Verify(ctx, item)
			})
			var inUse *marketsupplyguard.InUseError
			if errors.As(err, &inUse) {
				setBatchFailure(itemResult, "supply_in_use")
				itemResult.Error.OnlineAvailable, itemResult.Error.NormalSubscriptions = &inUse.OnlineAvailable, &inUse.NormalSubscriptions
				continue
			}
			if err != nil {
				return err
			}
			itemResult.Status = "updated"
			itemResult.Node = &updated
			payload := map[string]any{
				"from_state": beforeState,
				"to_state":   updated.AdminState,
				"revision":   updated.Revision,
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID:      actor.ScopeID,
				ActorUserID:  &actor.UserID,
				Action:       "node.batch_admin_state",
				ResourceType: "node",
				ResourceID:   updated.ID.String(),
				RequestID:    request.RequestID,
				Result:       "success",
				Payload:      payload,
			}); err != nil {
				return err
			}
		}
		return s.completeWrite(ctx, tx, actor, "node.batch_admin_state", request.IdempotencyKey, nil, result)
	})
	if err != nil {
		return BatchAdminStateResult{}, fmt.Errorf("batch update node admin state: %w", err)
	}
	return result, nil
}

func (s *Store) replayOrClaimWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation string,
	key string,
	digest [32]byte,
) (storedNodeWrite, error) {
	id, err := newID()
	if err != nil {
		return storedNodeWrite{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO node_write_requests (
			id, actor_user_id, actor_scope_id, operation, idempotency_key, request_digest, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (actor_user_id, operation, idempotency_key) DO NOTHING`,
		id, actor.UserID, actor.ScopeID, operation, key, digest[:], s.now().UTC())
	if err != nil {
		return storedNodeWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedNodeWrite{}, nil
	}
	var existingDigest, response []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT request_digest, response_body, completed_at
		FROM node_write_requests
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3`,
		actor.UserID, operation, key).Scan(&existingDigest, &response, &completedAt); err != nil {
		return storedNodeWrite{}, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || completedAt == nil || len(response) == 0 {
		return storedNodeWrite{}, ErrIdempotencyConflict
	}
	return storedNodeWrite{Response: response, Found: true}, nil
}

func (s *Store) completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation string,
	key string,
	resourceID *uuid.UUID,
	response any,
) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE node_write_requests
		SET resource_id = $4, response_body = $5, completed_at = $6
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3
		  AND completed_at IS NULL`,
		actor.UserID, operation, key, resourceID, string(encoded), s.now().UTC())
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func lockNode(ctx context.Context, tx pgx.Tx, scopeID, nodeID uuid.UUID) (Node, error) {
	var item Node
	err := tx.QueryRow(ctx, `
		SELECT id, display_id::text, name, description, region, host(ipv4), host(ipv6),
		       admin_state, management_settings, revision, created_at, updated_at
		FROM nodes
		WHERE id = $1 AND scope_id = $2
		FOR UPDATE`, nodeID, scopeID).Scan(nodeScanTargets(&item)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	return item, err
}

func lockNodeScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, scopeID.String())
	return err
}

func ensureActiveNodeAddressesAvailable(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, item Node) error {
	var conflict bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM nodes
			WHERE scope_id = $1
			  AND id <> $2
			  AND admin_state IN ('active', 'draining')
			  AND (($3::inet IS NOT NULL AND ipv4 = $3::inet) OR
			       ($4::inet IS NOT NULL AND ipv6 = $4::inet))
		)`, scopeID, item.ID, nullableIPValue(item.IPv4), nullableIPValue(item.IPv6)).Scan(&conflict); err != nil {
		return err
	}
	if conflict {
		return ErrIPConflict
	}
	return nil
}

func sameNodeAddress(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func nodeHasEnrollmentAuthorization(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM node_enrollment_authorizations WHERE node_id = $1
		)`, nodeID).Scan(&exists)
	return exists, err
}

// initializationEvidence returns the fact validateStateChange needs: for a
// pending node a live enrolled certificate (initialize), otherwise the
// historical enrollment authorization (re-enable).
func (s *Store) initializationEvidence(ctx context.Context, tx pgx.Tx, item Node) (bool, error) {
	if item.AdminState == StatePending {
		return nodeHasLiveCertificate(ctx, tx, item.ID, s.now().UTC())
	}
	return nodeHasEnrollmentAuthorization(ctx, tx, item.ID)
}

func applyUpdateFields(item *Node, fields UpdateFields) []string {
	changed := make([]string, 0, 7)
	if fields.Name != nil {
		item.Name = *fields.Name
		changed = append(changed, "name")
	}
	if fields.Description != nil {
		item.Description = *fields.Description
		changed = append(changed, "description")
	}
	if fields.Region != nil {
		item.Region = *fields.Region
		changed = append(changed, "region")
	}
	if fields.IPv4 != nil {
		item.IPv4 = nullableIP(*fields.IPv4)
		changed = append(changed, "ipv4")
	}
	if fields.IPv6 != nil {
		item.IPv6 = nullableIP(*fields.IPv6)
		changed = append(changed, "ipv6")
	}
	if fields.AdminState != nil {
		item.AdminState = *fields.AdminState
		changed = append(changed, "admin_state")
	}
	if fields.ManagementSettings != nil {
		item.ManagementSettings = *fields.ManagementSettings
		changed = append(changed, "management_settings")
	}
	return changed
}

func updateNodeRow(ctx context.Context, tx pgx.Tx, item Node, expectedRevision int64, now time.Time) (Node, error) {
	var updated Node
	err := tx.QueryRow(ctx, `
		UPDATE nodes SET
			name = $2, description = $3, region = $4, ipv4 = $5, ipv6 = $6,
			admin_state = $7, management_settings = $8, revision = revision + 1, updated_at = $9
		WHERE id = $1 AND revision = $10
		RETURNING id, display_id::text, name, description, region, host(ipv4), host(ipv6),
		          admin_state, management_settings, revision, created_at, updated_at`,
		item.ID, item.Name, item.Description, item.Region, item.IPv4, item.IPv6,
		item.AdminState, item.ManagementSettings, now, expectedRevision).Scan(nodeScanTargets(&updated)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return Node{}, ErrRevisionConflict
	}
	if err != nil {
		if isConstraintViolation(err, "nodes_schedule302_hostname_387_idx") {
			return Node{}, ErrSchedule302HostnameConflict
		}
		if isUniqueViolation(err) {
			return Node{}, ErrDuplicateName
		}
		return Node{}, err
	}
	return updated, nil
}

// isConstraintViolation reports a unique violation of the named index.
func isConstraintViolation(err error, name string) bool {
	var pgErr interface {
		SQLState() string
	}
	if !errors.As(err, &pgErr) || pgErr.SQLState() != "23505" {
		return false
	}
	var detailed *pgconn.PgError
	return errors.As(err, &detailed) && detailed.ConstraintName == name
}

// ensureLineGroupAddressesKept refuses an update that removes an address a
// current line-group revision still uses as this node's endpoint; the line
// group must drop the endpoint first. Historical revisions are not checked.
func ensureLineGroupAddressesKept(ctx context.Context, tx pgx.Tx, item Node) error {
	owned := make([]string, 0, 2+len(item.ManagementSettings.SecondaryIPs))
	for _, address := range []*string{item.IPv4, item.IPv6} {
		if address != nil {
			owned = append(owned, *address)
		}
	}
	owned = append(owned, item.ManagementSettings.SecondaryIPs...)
	var orphaned bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM node_line_endpoints endpoint
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=endpoint.tenant_scope_id
		 AND line_group.id=endpoint.line_group_id AND line_group.current_revision=endpoint.config_revision
		 AND line_group.deleted_at IS NULL
		WHERE endpoint.node_id=$1 AND NOT (endpoint.address = ANY($2::inet[])))`, item.ID, owned).Scan(&orphaned); err != nil {
		return err
	}
	if orphaned {
		return ErrAddressInUse
	}
	return nil
}

// ensureLineGroupRegionKept refuses a region change while the current
// revision of a live line group of another region lists this node. Line
// groups only offer nodes of their own region, and the endpoint region is
// copied from the group, so moving such a node would leave it in a line group
// its region no longer belongs to.
func ensureLineGroupRegionKept(ctx context.Context, tx pgx.Tx, item Node) error {
	var mismatched bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM node_line_endpoints endpoint
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=endpoint.tenant_scope_id
		 AND line_group.id=endpoint.line_group_id AND line_group.current_revision=endpoint.config_revision
		 AND line_group.deleted_at IS NULL
		WHERE endpoint.node_id=$1 AND line_group.region<>$2)`, item.ID, item.Region).Scan(&mismatched); err != nil {
		return err
	}
	if mismatched {
		return ErrRegionInUse
	}
	return nil
}

// onlyCatalogRegion returns the platform's region when its catalog has
// exactly one, else "". A node registered or initialized without a region is
// put there: line groups (and the packages using them) only take catalogued
// regions, so an empty region would keep the node out of every line group.
func onlyCatalogRegion(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (string, error) {
	var region string
	err := tx.QueryRow(ctx, `SELECT min(name) FROM region_catalog WHERE platform_scope_id=$1
		HAVING count(*)=1`, scopeID).Scan(&region)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read region catalog: %w", err)
	}
	return region, nil
}

func managementSettingsUsePrimaryIP(item Node) bool {
	for _, address := range item.ManagementSettings.SecondaryIPs {
		if item.IPv4 != nil && address == *item.IPv4 || item.IPv6 != nil && address == *item.IPv6 {
			return true
		}
	}
	return false
}

func nullableIP(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func nullableIPValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func setBatchFailure(result *BatchAdminStateItemResult, code string) {
	result.Status = "failed"
	result.Error = &BatchItemError{Code: code}
}

func batchErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrIdentityRequired):
		return "node_identity_required"
	case errors.Is(err, ErrRetired):
		return "node_retired"
	case errors.Is(err, ErrIPConflict):
		return "node_ip_conflict"
	case errors.Is(err, ErrInUse):
		return "node_in_use"
	case errors.Is(err, ErrNotFound):
		return "node_not_found"
	default:
		return "node_state_transition_denied"
	}
}

func (s *Store) Consume(ctx context.Context, input consumeStoreInput) (Authorization, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Authorization{}, fmt.Errorf("begin enrollment authorization: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if authorization, requestDigest, tokenHash, scopeID, found, err := s.authorizationByRequestID(ctx, tx, input.RequestID); err != nil {
		return Authorization{}, err
	} else if found {
		if subtle.ConstantTimeCompare(tokenHash, input.TokenHash) == 1 &&
			subtle.ConstantTimeCompare(requestDigest, input.RequestDigest) == 1 &&
			authorization.Purpose == input.Purpose {
			return authorization, tx.Commit(ctx)
		}
		if err := s.appendEnrollmentDenied(ctx, tx, scopeID, nil, authorization.NodeID.String(), input.RequestID, "idempotency_conflict"); err != nil {
			return Authorization{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Authorization{}, fmt.Errorf("commit idempotency denial: %w", err)
		}
		return Authorization{}, ErrIdempotencyConflict
	}

	type tokenRow struct {
		ID            uuid.UUID
		NodeID        uuid.UUID
		ScopeID       uuid.UUID
		Purpose       string
		ExpiresAt     time.Time
		ConsumedAt    *time.Time
		RequestID     *string
		RequestDigest []byte
		NodeState     string
	}
	var token tokenRow
	err = tx.QueryRow(ctx, `
		SELECT token.id, token.node_id, node.scope_id, token.purpose, token.expires_at,
		       token.consumed_at, token.consume_request_id, token.consume_request_digest,
		       node.admin_state
		FROM node_enrollment_tokens token
		JOIN nodes node ON node.id = token.node_id
		WHERE token.token_hash = $1
		FOR UPDATE OF token, node`, input.TokenHash).Scan(
		&token.ID,
		&token.NodeID,
		&token.ScopeID,
		&token.Purpose,
		&token.ExpiresAt,
		&token.ConsumedAt,
		&token.RequestID,
		&token.RequestDigest,
		&token.NodeState,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		scopeID, scopeErr := platformScopeID(ctx, tx)
		if scopeErr != nil {
			return Authorization{}, scopeErr
		}
		if err := s.appendEnrollmentDenied(ctx, tx, scopeID, nil, "unknown", input.RequestID, "invalid_token"); err != nil {
			return Authorization{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Authorization{}, fmt.Errorf("commit invalid token denial: %w", err)
		}
		return Authorization{}, ErrInvalidToken
	}
	if err != nil {
		return Authorization{}, fmt.Errorf("lock enrollment token: %w", err)
	}
	if token.ConsumedAt != nil {
		if token.RequestID != nil && *token.RequestID == input.RequestID &&
			bytes.Equal(token.RequestDigest, input.RequestDigest) && token.Purpose == input.Purpose {
			authorization, err := s.authorizationByTokenID(ctx, tx, token.ID)
			if err != nil {
				return Authorization{}, err
			}
			return authorization, tx.Commit(ctx)
		}
		return s.denyConsumption(ctx, tx, token.ScopeID, token.NodeID, input.RequestID, "token_consumed", ErrTokenConsumed)
	}
	if token.Purpose != input.Purpose {
		return s.denyConsumption(ctx, tx, token.ScopeID, token.NodeID, input.RequestID, "purpose_mismatch", ErrInvalidToken)
	}
	if !s.now().UTC().Before(token.ExpiresAt) {
		return s.denyConsumption(ctx, tx, token.ScopeID, token.NodeID, input.RequestID, "token_expired", ErrTokenExpired)
	}
	if token.NodeState == StateDisabled || token.NodeState == StateRetired {
		return s.denyConsumption(ctx, tx, token.ScopeID, token.NodeID, input.RequestID, "node_"+token.NodeState, ErrEnrollmentDenied)
	}

	authorizationID, err := newID()
	if err != nil {
		return Authorization{}, err
	}
	authorizedAt := s.now().UTC()
	authorization := Authorization{
		ID:           authorizationID,
		NodeID:       token.NodeID,
		Purpose:      token.Purpose,
		RequestID:    input.RequestID,
		AuthorizedAt: authorizedAt,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_enrollment_authorizations (
			id, token_id, node_id, purpose, request_id, request_digest, authorized_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		authorization.ID,
		token.ID,
		authorization.NodeID,
		authorization.Purpose,
		authorization.RequestID,
		input.RequestDigest,
		authorization.AuthorizedAt,
	); err != nil {
		if isUniqueViolation(err) {
			return Authorization{}, ErrIdempotencyConflict
		}
		return Authorization{}, fmt.Errorf("insert enrollment authorization: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_enrollment_tokens
		SET consumed_at = $2, consume_request_id = $3, consume_request_digest = $4
		WHERE id = $1`, token.ID, authorizedAt, input.RequestID, input.RequestDigest); err != nil {
		return Authorization{}, fmt.Errorf("consume enrollment token: %w", err)
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID:      token.ScopeID,
		Action:       "node.enrollment_token.consume",
		ResourceType: "node_enrollment_authorization",
		ResourceID:   authorization.ID.String(),
		RequestID:    input.RequestID,
		Result:       "success",
		Payload: map[string]any{
			"node_id":  token.NodeID.String(),
			"purpose":  token.Purpose,
			"token_id": token.ID.String(),
		},
	}); err != nil {
		return Authorization{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Authorization{}, fmt.Errorf("commit enrollment authorization: %w", err)
	}
	return authorization, nil
}

func (s *Store) authorizationByRequestID(
	ctx context.Context,
	tx pgx.Tx,
	requestID string,
) (Authorization, []byte, []byte, uuid.UUID, bool, error) {
	var authorization Authorization
	var requestDigest, tokenHash []byte
	var scopeID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT auth.id, auth.node_id, auth.purpose, auth.request_id, auth.request_digest,
		       auth.authorized_at, token.token_hash, node.scope_id
		FROM node_enrollment_authorizations auth
		JOIN node_enrollment_tokens token ON token.id = auth.token_id
		JOIN nodes node ON node.id = auth.node_id
		WHERE auth.request_id = $1`, requestID).Scan(
		&authorization.ID,
		&authorization.NodeID,
		&authorization.Purpose,
		&authorization.RequestID,
		&requestDigest,
		&authorization.AuthorizedAt,
		&tokenHash,
		&scopeID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Authorization{}, nil, nil, uuid.Nil, false, nil
	}
	if err != nil {
		return Authorization{}, nil, nil, uuid.Nil, false, fmt.Errorf("find enrollment request: %w", err)
	}
	if len(requestDigest) != 32 || len(tokenHash) != 32 {
		return Authorization{}, nil, nil, uuid.Nil, false, errors.New("invalid stored enrollment digest")
	}
	return authorization, requestDigest, tokenHash, scopeID, true, nil
}

func (s *Store) authorizationByTokenID(ctx context.Context, tx pgx.Tx, tokenID uuid.UUID) (Authorization, error) {
	var authorization Authorization
	err := tx.QueryRow(ctx, `
		SELECT id, node_id, purpose, request_id, authorized_at
		FROM node_enrollment_authorizations
		WHERE token_id = $1`, tokenID).Scan(
		&authorization.ID,
		&authorization.NodeID,
		&authorization.Purpose,
		&authorization.RequestID,
		&authorization.AuthorizedAt,
	)
	if err != nil {
		return Authorization{}, fmt.Errorf("load enrollment authorization: %w", err)
	}
	return authorization, nil
}

func (s *Store) denyConsumption(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	nodeID uuid.UUID,
	requestID string,
	reason string,
	resultErr error,
) (Authorization, error) {
	if err := s.appendEnrollmentDenied(ctx, tx, scopeID, nil, nodeID.String(), requestID, reason); err != nil {
		return Authorization{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Authorization{}, fmt.Errorf("commit enrollment denial: %w", err)
	}
	return Authorization{}, resultErr
}

func (s *Store) appendEnrollmentDenied(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	actorUserID *uuid.UUID,
	resourceID string,
	requestID string,
	reason string,
) error {
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID:      scopeID,
		ActorUserID:  actorUserID,
		Action:       "node.enrollment_token.reject",
		ResourceType: "node",
		ResourceID:   resourceID,
		RequestID:    requestID,
		Result:       "denied",
		Payload:      map[string]any{"reason": reason},
	})
}

func requirePlatformScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	var kind string
	if err := tx.QueryRow(ctx, "SELECT kind FROM access_scopes WHERE id = $1", scopeID).Scan(&kind); err != nil {
		return err
	}
	if kind != "platform" {
		return ErrEnrollmentDenied
	}
	return nil
}

func platformScopeID(ctx context.Context, tx pgx.Tx) (uuid.UUID, error) {
	var scopeID uuid.UUID
	if err := tx.QueryRow(ctx, "SELECT id FROM access_scopes WHERE kind = 'platform'").Scan(&scopeID); err != nil {
		return uuid.Nil, fmt.Errorf("find platform audit scope: %w", err)
	}
	return scopeID, nil
}

func nodeScanTargets(item *Node) []any {
	return []any{
		&item.ID,
		&item.DisplayID,
		&item.Name,
		&item.Description,
		&item.Region,
		&item.IPv4,
		&item.IPv6,
		&item.AdminState,
		&item.ManagementSettings,
		&item.Revision,
		&item.CreatedAt,
		&item.UpdatedAt,
	}
}

func allocateNodeDisplayID(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, updatedAt time.Time) (int64, error) {
	var displayID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at)
		VALUES($1,2,$2)
		ON CONFLICT(scope_id) DO UPDATE SET
			next_value=node_display_id_sequences.next_value+1,
			updated_at=EXCLUDED.updated_at
		RETURNING next_value-1`, scopeID, updatedAt).Scan(&displayID); err != nil {
		return 0, fmt.Errorf("allocate node display ID: %w", err)
	}
	return displayID, nil
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && pgErr.SQLState() == "23505"
}

// marketSupplyError wraps a market supply guard refusal as ErrSupplyInUse.
func marketSupplyError(err error) error {
	if errors.Is(err, marketsupplyguard.ErrInUse) {
		return fmt.Errorf("%w: %w", ErrSupplyInUse, err)
	}
	return err
}
