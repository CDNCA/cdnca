package l4forward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

type rowScanner interface {
	Scan(dest ...any) error
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type jsonValueScanner struct {
	target any
}

func (scanner *jsonValueScanner) Scan(source any) error {
	var payload []byte
	switch value := source.(type) {
	case []byte:
		payload = value
	case string:
		payload = []byte(value)
	case nil:
		payload = []byte("null")
	default:
		return fmt.Errorf("scan JSON value from %T", source)
	}
	return json.Unmarshal(payload, scanner.target)
}

type storedWrite struct {
	Replayed     bool
	ResponseBody []byte
}

func NewStore(pool *pgxpool.Pool) *Store {
	return NewStoreWithClock(pool, time.Now)
}

func NewStoreWithClock(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.New(pool), now: now}
}

func (s *Store) Create(
	ctx context.Context,
	actor Actor,
	request CreateRequest,
	forwardID uuid.UUID,
	digest [32]byte,
) (WriteResult, error) {
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTarget(ctx, tx, actor, request.TargetScopeID, request.OwnerUserID); err != nil {
			return err
		}
		if err := authorizeAutomaticMutation(ctx, tx, actor, request.TargetScopeID); err != nil {
			return err
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "stream.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(write.ResponseBody, &result.Forward); err != nil {
				return fmt.Errorf("decode stored stream create response: %w", err)
			}
			if err := refreshEligibility(ctx, tx, &result.Forward, false); err != nil {
				return err
			}
			markPublicationUnknown(&result.Forward.PublishIntent)
			result.Replayed = true
			return nil
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, request.TargetScopeID, "stream.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result.Forward); err != nil {
				return fmt.Errorf("decode stored stream create response: %w", err)
			}
			if err := refreshEligibility(ctx, tx, &result.Forward, false); err != nil {
				return err
			}
			markPublicationUnknown(&result.Forward.PublishIntent)
			result.Replayed = true
			return nil
		}
		item, err := s.insertForward(ctx, tx, actor, request, forwardID)
		if err != nil {
			return err
		}
		result.Forward = item
		return s.completeWrite(ctx, tx, actor.UserID, "stream.create", request.IdempotencyKey, item.ID, 201, item)
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("create stream: %w", err)
	}
	return result, nil
}

// insertForward writes one new stream with its listeners, groups, publish
// intent, automatic publication request and stream.create audit event (also
// each line of a 批量添加, whose receipt is the batch's).
func (s *Store) insertForward(ctx context.Context, tx pgx.Tx, actor Actor, request CreateRequest, forwardID uuid.UUID) (Forward, error) {
	const operation = "stream.create"
	if err := requireStreamPorts(ctx, tx, request.TargetScopeID, request.OwnerUserID, request.Fields, nil, s.now().UTC()); err != nil {
		return Forward{}, err
	}
	if err := requireGuardRuleLimit(ctx, tx, request.Fields); err != nil {
		return Forward{}, err
	}
	if err := locateSocketConflict(ctx, tx, request.TargetScopeID, forwardID, &request.Fields); err != nil {
		return Forward{}, err
	}
	dnsJSON, geoJSON, err := encodeRuntimePolicies(request.Fields)
	if err != nil {
		return Forward{}, err
	}
	now := s.now().UTC()
	item, err := scanForwardWithoutIntent(tx.QueryRow(ctx, `
		INSERT INTO l4_forwards (
			id, scope_id, package_subscription_id, owner_user_id, name, remark,
			protocol, listen_address, listen_port, upstream_address, upstream_host, upstream_port,
			dns_policy, geo_policy, connect_timeout_ms, response_timeout_ms,
			max_connections_per_client, proxy_protocol_inbound, proxy_protocol_v1, balance_way, enabled,
			created_by_user_id, updated_by_user_id, created_at, updated_at, tls_passthrough, server_names,
			max_new_connections_per_client_per_second, new_connection_burst, new_connection_ban_seconds, toa,
			session_log_enabled, listen_port_end, upstream_follow_port, guard_rules,
			origins, listen_ipv6, acl_default_action, acl_rules
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::inet, $11, $12,
		          $13::jsonb, $14::jsonb, $15, $16, $17, $18, $19, $20, $21, $22, $22, $23, $23, $24, $25,
		          $26, $27, $28, $29, $30, $31, $32, $33::jsonb, $34::jsonb, $35, $36, $37::jsonb)
		RETURNING `+forwardColumns("l4_forwards")+`,
		          (SELECT display_name FROM users WHERE id = l4_forwards.owner_user_id)`,
		forwardID, request.TargetScopeID, request.Fields.PackageSubscriptionID, request.OwnerUserID,
		request.Fields.Name, request.Fields.Remark, request.Fields.Protocol,
		request.Fields.ListenAddress, request.Fields.ListenPort, nullableString(request.Fields.UpstreamAddress),
		nullableString(request.Fields.UpstreamHost), request.Fields.UpstreamPort, dnsJSON, geoJSON,
		request.Fields.ConnectTimeoutMS, request.Fields.ResponseTimeoutMS, request.Fields.MaxConnectionsPerClient,
		request.Fields.ProxyProtocolInbound, request.Fields.ProxyProtocolV1, request.Fields.BalanceWay,
		request.Fields.Enabled, actor.UserID, now, request.Fields.TLSPassthrough, serverNamesColumn(request.Fields.ServerNames),
		request.Fields.MaxNewConnectionsPerClientPerSecond, request.Fields.NewConnectionBurst, request.Fields.NewConnectionBanSeconds,
		request.Fields.TOA, request.Fields.SessionLogEnabled, nullablePort(request.Fields.ListenPortEnd), request.Fields.UpstreamFollowPort,
		guardRulesColumn(request.Fields.GuardRules), originsColumn(request.Fields.Origins), request.Fields.ListenIPv6,
		aclDefaultColumn(request.Fields.ACL), aclRulesColumn(request.Fields.ACL)))
	if err != nil {
		return Forward{}, classifyConflict(err)
	}
	if err := writeAdditionalListeners(ctx, tx, &item, request.Fields.AdditionalListeners); err != nil {
		return Forward{}, err
	}
	if err := rejectStreamSocketConflict(ctx, tx, item.ScopeID, item.ID); err != nil {
		return Forward{}, err
	}
	if err := replaceGroups(ctx, tx, item.ID, item.ScopeID, request.GroupIDs); err != nil {
		return Forward{}, err
	}
	item.Groups, err = loadGroupReferences(ctx, tx, item.ID)
	if err != nil {
		return Forward{}, err
	}
	item.EligibilityState = EligibilityEligible
	intent, err := s.appendPublishIntent(ctx, tx, actor.UserID, item, "create")
	if err != nil {
		return Forward{}, err
	}
	item.PublishIntent = intent
	if err := enqueueAutomaticMutation(ctx, tx, actor, item.ScopeID, item.ID, intent,
		operation, request.RequestID); err != nil {
		return Forward{}, err
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.TargetScopeID, ActorUserID: &actor.UserID, Action: operation,
		ResourceType: "stream", ResourceID: item.ID.String(), RequestID: request.RequestID, Result: "success",
		Payload: automaticAuditPayload(actor, item.ScopeID, operation, map[string]any{
			"revision": item.Revision, "publish_version": intent.Version, "enabled": item.Enabled,
			"remark": item.Remark, "endpoint_kind": endpointKind(item),
			"package_subscription_id":       optionalUUIDText(item.PackageSubscriptionID),
			"max_connections_per_client":    item.MaxConnectionsPerClient,
			"publish_intent_id":             intent.ID.String(),
			"configuration_source_revision": intent.ConfigurationSourceRevision,
		}),
	}); err != nil {
		return Forward{}, err
	}
	return item, nil
}

func (s *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (WriteResult, error) {
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, err := mutationTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if err := authorizeAutomaticMutation(ctx, tx, actor, targetScopeID); err != nil {
			return err
		}
		current, deleted, err := s.lockForward(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if current.ScopeID != targetScopeID {
			return ErrNotFound
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "stream.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(write.ResponseBody, &result.Forward); err != nil {
				return fmt.Errorf("decode stored stream update response: %w", err)
			}
			if err := refreshEligibility(ctx, tx, &result.Forward, false); err != nil {
				return err
			}
			markPublicationUnknown(&result.Forward.PublishIntent)
			result.Replayed = true
			return nil
		}
		if deleted {
			return ErrNotFound
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, current.ScopeID, "stream.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result.Forward); err != nil {
				return fmt.Errorf("decode stored stream update response: %w", err)
			}
			if err := refreshEligibility(ctx, tx, &result.Forward, false); err != nil {
				return err
			}
			markPublicationUnknown(&result.Forward.PublishIntent)
			result.Replayed = true
			return nil
		}
		if request.Fields.AdditionalListeners == nil {
			request.Fields.AdditionalListeners = &current.AdditionalListeners
		}
		if err := normalizeAdditionalListeners(&request.Fields); err != nil {
			return err
		}
		if err := requireStreamPorts(ctx, tx, current.ScopeID, current.ownerUserID, request.Fields, &current, s.now().UTC()); err != nil {
			return err
		}
		if err := requireGuardRuleLimit(ctx, tx, request.Fields); err != nil {
			return err
		}
		if err := locateSocketConflict(ctx, tx, current.ScopeID, current.ID, &request.Fields); err != nil {
			return err
		}
		// Release extras before changing the primary socket so an extra can become the primary.
		if err := releaseAdditionalListeners(ctx, tx, current.ID); err != nil {
			return err
		}
		dnsJSON, geoJSON, err := encodeRuntimePolicies(request.Fields)
		if err != nil {
			return err
		}
		item, err := scanForwardWithoutIntent(tx.QueryRow(ctx, `
			UPDATE l4_forwards SET
				package_subscription_id = $2, name = $3, remark = $4, protocol = $5,
				listen_address = $6, listen_port = $7, upstream_address = $8::inet, upstream_host = $9,
				upstream_port = $10, dns_policy = $11::jsonb, geo_policy = $12::jsonb,
				connect_timeout_ms = $13, response_timeout_ms = $14, max_connections_per_client = $15,
				proxy_protocol_inbound = $16, proxy_protocol_v1 = $17, balance_way = $18, enabled = $19,
				revision = revision + 1, updated_by_user_id = $20, updated_at = $21,
				tls_passthrough = $23, server_names = $24,
				max_new_connections_per_client_per_second = $25, new_connection_burst = $26, new_connection_ban_seconds = $27,
				toa = $28, session_log_enabled = $29, listen_port_end = $30, upstream_follow_port = $31, guard_rules = $32::jsonb,
				origins = $33::jsonb, listen_ipv6 = $34, acl_default_action = $35, acl_rules = $36::jsonb
			WHERE id = $1 AND revision = $22 AND deleted_at IS NULL
			RETURNING `+forwardColumns("l4_forwards")+`,
			          (SELECT display_name FROM users WHERE id = l4_forwards.owner_user_id)`,
			request.ID, request.Fields.PackageSubscriptionID, request.Fields.Name, request.Fields.Remark,
			request.Fields.Protocol, request.Fields.ListenAddress, request.Fields.ListenPort,
			nullableString(request.Fields.UpstreamAddress), nullableString(request.Fields.UpstreamHost), request.Fields.UpstreamPort,
			dnsJSON, geoJSON, request.Fields.ConnectTimeoutMS, request.Fields.ResponseTimeoutMS,
			request.Fields.MaxConnectionsPerClient, request.Fields.ProxyProtocolInbound, request.Fields.ProxyProtocolV1,
			request.Fields.BalanceWay, request.Fields.Enabled,
			actor.UserID, s.now().UTC(), request.ExpectedRevision,
			request.Fields.TLSPassthrough, serverNamesColumn(request.Fields.ServerNames),
			request.Fields.MaxNewConnectionsPerClientPerSecond, request.Fields.NewConnectionBurst, request.Fields.NewConnectionBanSeconds,
			request.Fields.TOA, request.Fields.SessionLogEnabled, nullablePort(request.Fields.ListenPortEnd), request.Fields.UpstreamFollowPort,
			guardRulesColumn(request.Fields.GuardRules), originsColumn(request.Fields.Origins), request.Fields.ListenIPv6,
			aclDefaultColumn(request.Fields.ACL), aclRulesColumn(request.Fields.ACL)))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			return classifyConflict(err)
		}
		if err := writeAdditionalListeners(ctx, tx, &item, request.Fields.AdditionalListeners); err != nil {
			return err
		}
		if err := rejectStreamSocketConflict(ctx, tx, item.ScopeID, item.ID); err != nil {
			return err
		}
		if request.GroupIDs != nil {
			if err := replaceGroups(ctx, tx, item.ID, item.ScopeID, *request.GroupIDs); err != nil {
				return err
			}
		}
		item.Groups, err = loadGroupReferences(ctx, tx, item.ID)
		if err != nil {
			return err
		}
		item.EligibilityState = EligibilityEligible
		intent, err := s.appendPublishIntent(ctx, tx, actor.UserID, item, "update")
		if err != nil {
			return err
		}
		item.PublishIntent = intent
		result.Forward = item
		if err := enqueueAutomaticMutation(ctx, tx, actor, item.ScopeID, item.ID, intent,
			"stream.update", request.RequestID); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: current.ScopeID, ActorUserID: &actor.UserID, Action: "stream.update",
			ResourceType: "stream", ResourceID: item.ID.String(), RequestID: request.RequestID, Result: "success",
			Payload: automaticAuditPayload(actor, item.ScopeID, "stream.update", map[string]any{
				"revision": item.Revision, "publish_version": intent.Version, "enabled": item.Enabled,
				"remark": item.Remark, "endpoint_kind": endpointKind(item),
				"package_subscription_id":       optionalUUIDText(item.PackageSubscriptionID),
				"max_connections_per_client":    item.MaxConnectionsPerClient,
				"publish_intent_id":             intent.ID.String(),
				"configuration_source_revision": intent.ConfigurationSourceRevision,
			}),
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "stream.update", request.IdempotencyKey, item.ID, 200, item)
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("update stream: %w", err)
	}
	return result, nil
}

func (s *Store) Delete(ctx context.Context, actor Actor, request DeleteRequest, digest [32]byte) (DeleteResult, error) {
	var result DeleteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, err := mutationTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if err := authorizeAutomaticMutation(ctx, tx, actor, targetScopeID); err != nil {
			return err
		}
		item, deleted, err := s.lockForward(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if item.ScopeID != targetScopeID {
			return ErrNotFound
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "stream.delete", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(write.ResponseBody, &result.PublishIntent); err != nil {
				return fmt.Errorf("decode stored stream delete response: %w", err)
			}
			markPublicationUnknown(&result.PublishIntent)
			result.Replayed = true
			return nil
		}
		if deleted {
			return ErrNotFound
		}
		if err := refreshEligibility(ctx, tx, &item, true); err != nil {
			return err
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, item.ScopeID, "stream.delete", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result.PublishIntent); err != nil {
				return fmt.Errorf("decode stored stream delete response: %w", err)
			}
			markPublicationUnknown(&result.PublishIntent)
			result.Replayed = true
			return nil
		}
		now := s.now().UTC()
		command, err := tx.Exec(ctx, `
			UPDATE l4_forwards
			SET deleted_at = $2, updated_at = $2, updated_by_user_id = $3, revision = revision + 1
			WHERE id = $1 AND revision = $4 AND deleted_at IS NULL`, request.ID, now, actor.UserID, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() == 0 {
			return ErrRevisionConflict
		}
		// The stream's own CNAME hostname (migration 505) leaves DNS with it.
		if err := cnameallocation.RetireStreamOwnersTx(ctx, tx, item.ScopeID, item.ID, cnameallocation.RetireStreamDeleted, now); err != nil {
			return err
		}
		item.Revision++
		item.UpdatedAt = now
		intent, err := s.appendPublishIntent(ctx, tx, actor.UserID, item, "delete")
		if err != nil {
			return err
		}
		result.PublishIntent = intent
		if err := enqueueAutomaticMutation(ctx, tx, actor, item.ScopeID, item.ID, intent,
			"stream.delete", request.RequestID); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: item.ScopeID, ActorUserID: &actor.UserID, Action: "stream.delete",
			ResourceType: "stream", ResourceID: item.ID.String(), RequestID: request.RequestID, Result: "success",
			Payload: automaticAuditPayload(actor, item.ScopeID, "stream.delete", map[string]any{
				"deleted_revision": item.Revision, "publish_version": intent.Version,
				"package_subscription_id":       optionalUUIDText(item.PackageSubscriptionID),
				"publish_intent_id":             intent.ID.String(),
				"configuration_source_revision": intent.ConfigurationSourceRevision,
			}),
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "stream.delete", request.IdempotencyKey, item.ID, 204, intent)
	})
	if err != nil {
		return DeleteResult{}, fmt.Errorf("delete stream: %w", err)
	}
	return result, nil
}

func (s *Store) Get(ctx context.Context, actor Actor, id uuid.UUID) (Forward, error) {
	query := forwardSelect + " WHERE f.id = $1 AND f.deleted_at IS NULL"
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND f.scope_id = $2 AND f.owner_user_id = $3"
		args = append(args, actor.ScopeID, actor.UserID)
	}
	item, err := scanForward(s.pool.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return Forward{}, ErrNotFound
	}
	if err != nil {
		return Forward{}, fmt.Errorf("get stream: %w", err)
	}
	if err := refreshEligibility(ctx, s.pool, &item, false); err != nil {
		return Forward{}, fmt.Errorf("get stream eligibility: %w", err)
	}
	return item, nil
}

func (s *Store) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ListResult{}, fmt.Errorf("begin stream list transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	where, args := listWhere(actor, filter)
	var total int64
	if err := tx.QueryRow(ctx, "SELECT count(*) "+forwardFrom+where, args...).Scan(&total); err != nil {
		return ListResult{}, fmt.Errorf("count streams: %w", err)
	}
	args = append(args, filter.Limit, (filter.Page-1)*filter.Limit)
	rows, err := tx.Query(ctx, forwardSelect+where+fmt.Sprintf(" ORDER BY f.created_at DESC, f.id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return ListResult{}, fmt.Errorf("list streams: %w", err)
	}
	defer rows.Close()
	items := make([]Forward, 0, filter.Limit)
	for rows.Next() {
		item, err := scanForward(rows)
		if err != nil {
			return ListResult{}, fmt.Errorf("scan stream: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, fmt.Errorf("iterate streams: %w", err)
	}
	rows.Close()
	for index := range items {
		if err := refreshEligibility(ctx, tx, &items[index], false); err != nil {
			return ListResult{}, fmt.Errorf("list stream eligibility: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ListResult{}, fmt.Errorf("commit stream list transaction: %w", err)
	}
	return ListResult{Items: items, Total: total, Page: filter.Page, Limit: filter.Limit}, nil
}

// loadGroupReferences 读取转发当前所属分组，供 RETURNING 路径补齐分组信息。
func loadGroupReferences(ctx context.Context, tx pgx.Tx, streamID uuid.UUID) ([]GroupReference, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT `+selfGroupReferences+`
		FROM l4_forwards WHERE id = $1`, streamID).Scan(&raw); err != nil {
		return nil, err
	}
	return decodeGroupReferences(&raw)
}

// replaceGroups 用给定的分组集合替换转发的全部所属分组；空列表即清空。
// 成员关系变化会改变下发的边缘配置，故显式推进一次 scope 版本（触发器只认 l4_forwards 行变更）。
func replaceGroups(ctx context.Context, tx pgx.Tx, streamID, scopeID uuid.UUID, groupIDs []uuid.UUID) error {
	groupTexts := make([]string, 0, len(groupIDs))
	for _, id := range groupIDs {
		groupTexts = append(groupTexts, id.String())
	}
	if len(groupIDs) > 0 {
		var missing int64
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM unnest($1::uuid[]) AS candidate(id)
			WHERE NOT EXISTS (
				SELECT 1 FROM l4_stream_groups
				WHERE id = candidate.id AND scope_id = $2 AND deleted_at IS NULL
			)`, groupTexts, scopeID).Scan(&missing); err != nil {
			return err
		}
		if missing > 0 {
			return ErrGroupNotFound
		}
	}
	command, err := tx.Exec(ctx, `DELETE FROM l4_stream_group_members WHERE stream_id = $1`, streamID)
	if err != nil {
		return err
	}
	changed := command.RowsAffected()
	if len(groupIDs) > 0 {
		command, err = tx.Exec(ctx, `
			INSERT INTO l4_stream_group_members (group_id, stream_id, scope_id)
			SELECT member.id, $1, $2 FROM unnest($3::uuid[]) AS member(id)
			ON CONFLICT (group_id, stream_id) DO NOTHING`, streamID, scopeID, groupTexts)
		if err != nil {
			return err
		}
		changed += command.RowsAffected()
	}
	if changed == 0 {
		return nil
	}
	_, err = tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, scopeID)
	return err
}

func (s *Store) lockForward(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (Forward, bool, error) {
	query := `SELECT ` + forwardColumns("f") + `, u.display_name, ` + forwardGroupReferences + `, f.deleted_at
		FROM l4_forwards f JOIN users u ON u.id = f.owner_user_id WHERE f.id = $1`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND f.scope_id = $2 AND f.owner_user_id = $3"
		args = append(args, actor.ScopeID, actor.UserID)
	}
	query += " FOR UPDATE OF f"
	var item Forward
	var ownerName string
	var groupsJSON []byte
	var deletedAt *time.Time
	destinations := forwardScanDestinations(&item, &ownerName, &groupsJSON)
	destinations = append(destinations, &deletedAt)
	err := tx.QueryRow(ctx, query, args...).Scan(destinations...)
	if errors.Is(err, pgx.ErrNoRows) {
		return Forward{}, false, ErrNotFound
	}
	if err != nil {
		return Forward{}, false, err
	}
	groups, err := decodeGroupReferences(&groupsJSON)
	if err != nil {
		return Forward{}, false, err
	}
	item.Groups = groups
	item.Owner = &OwnerReference{ID: item.ownerUserID, DisplayName: ownerName}
	fillOrigins(&item)
	if err := loadAdditionalListeners(ctx, tx, &item); err != nil {
		return Forward{}, false, err
	}
	return item, deletedAt != nil, nil
}

func (s *Store) appendPublishIntent(ctx context.Context, tx pgx.Tx, actorUserID uuid.UUID, item Forward, operation string) (PublishIntent, error) {
	var version int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO l4_scope_publish_counters (scope_id, current_version) VALUES ($1, 1)
		ON CONFLICT (scope_id) DO UPDATE SET current_version = l4_scope_publish_counters.current_version + 1
		RETURNING current_version`, item.ScopeID).Scan(&version); err != nil {
		return PublishIntent{}, err
	}
	desiredState := "enabled"
	if operation == "delete" {
		desiredState = "deleted"
	} else if !item.Enabled || item.AdminStatus != AdminStatusNormal {
		desiredState = "disabled"
	}
	runtime := runtimeSpec(item)
	encoded, err := json.Marshal(runtime)
	if err != nil {
		return PublishIntent{}, err
	}
	intent := PublishIntent{
		ID: uuid.New(), Version: version, Operation: operation, DesiredState: desiredState,
		ResourceRevision: item.Revision, RuntimeSpec: runtime, State: PublicationStateUnknown, CreatedAt: s.now().UTC(),
	}
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
		WHERE scope_id=$1`, item.ScopeID).Scan(&intent.ConfigurationSourceRevision); err != nil {
		return PublishIntent{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO l4_publish_intents (
			id, scope_id, stream_id, version, operation, desired_state, resource_revision,
			configuration_source_revision, runtime_spec, created_by_user_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)`,
		intent.ID, item.ScopeID, item.ID, intent.Version, intent.Operation, intent.DesiredState,
		intent.ResourceRevision, intent.ConfigurationSourceRevision, encoded, actorUserID, intent.CreatedAt); err != nil {
		return PublishIntent{}, err
	}
	return intent, nil
}

func runtimeSpec(item Forward) RuntimeSpec {
	endpoint := RuntimeEndpoint{Address: item.UpstreamAddress, Host: item.UpstreamHost, Port: item.UpstreamPort,
		FollowPort: item.UpstreamFollowPort, Origins: runtimeOrigins(item.Origins)}
	if item.BalanceWay == BalanceWayIPHash {
		endpoint.Balance = edgeconfig.L4BalanceIPHash // 定源
	}
	return RuntimeSpec{
		SchemaVersion: RuntimeSchemaV2, TenantID: item.ScopeID.String(),
		StreamID: item.ID.String(), Revision: item.Revision,
		Listener: RuntimeListener{Protocol: item.Protocol, Address: item.ListenAddress, Port: item.ListenPort,
			PortEnd: item.ListenPortEnd},
		AdditionalListeners: item.AdditionalListeners,
		Endpoint:            endpoint, DNS: item.DNS, Geo: runtimeGeoPolicy(item),
		ConnectTimeoutMS: item.ConnectTimeoutMS, ResponseTimeoutMS: item.ResponseTimeoutMS,
		MaxConnectionsPerClient: item.MaxConnectionsPerClient, DrainTimeoutMS: 30000,
		ProxyProtocolInbound: item.ProxyProtocolInbound, ProxyProtocolOutbound: item.ProxyProtocolV1,
		TLSPassthrough: item.TLSPassthrough, ServerNames: runtimeServerNames(item),
		NewConnRate: newConnRate(item.MaxNewConnectionsPerClientPerSecond, item.NewConnectionBurst, item.NewConnectionBanSeconds),
		TOA:         item.TOA,
		SessionLog:  item.SessionLogEnabled,
		GuardRules:  runtimeGuardRulesWithACL(item),
		ListenIPv6:  item.ListenIPv6,
	}
}

// runtimeOrigins is the origin list of a multi-origin stream (nil for one).
func runtimeOrigins(origins []Origin) []edgeconfig.L4OriginV2 {
	if len(origins) < 2 {
		return nil
	}
	result := make([]edgeconfig.L4OriginV2, len(origins))
	for index, origin := range origins {
		result[index] = edgeconfig.L4OriginV2{Address: origin.Address, Weight: origin.Weight, Down: origin.Down}
	}
	return result
}

// originsColumn writes NULL for a single-origin stream.
func originsColumn(origins []Origin) any {
	if len(origins) < 2 {
		return nil
	}
	encoded, _ := json.Marshal(origins)
	return string(encoded)
}

func aclDefaultColumn(acl *ACL) string {
	if acl == nil {
		return ACLActionAllow
	}
	return acl.DefaultAction
}

// aclRulesColumn writes NULL for a stream without IP rules.
func aclRulesColumn(acl *ACL) any {
	if acl == nil || len(acl.Rules) == 0 {
		return nil
	}
	encoded, _ := json.Marshal(acl.Rules)
	return string(encoded)
}

// guardRulesColumn writes NULL for a stream without rules.
func guardRulesColumn(rules []GuardRule) any {
	if len(rules) == 0 {
		return nil
	}
	encoded, err := json.Marshal(rules)
	if err != nil {
		return nil
	}
	return string(encoded)
}

// runtimeServerNames keeps plain streams' intents free of the passthrough
// keys (omitempty), as 293 requires.
func runtimeServerNames(item Forward) []string {
	if !item.TLSPassthrough {
		return nil
	}
	return append([]string(nil), item.ServerNames...)
}

// serverNamesColumn writes an empty array rather than NULL.
func serverNamesColumn(names []string) []string {
	if names == nil {
		return []string{}
	}
	return names
}

func runtimeGeoPolicy(item Forward) RuntimeGeoPolicy {
	return RuntimeGeoPolicy{
		Enabled: item.Geo.Enabled, TenantID: item.ScopeID.String(),
		StreamID: item.ID.String(), Revision: item.Revision,
		UnknownRegionAction: item.Geo.UnknownRegionAction, TrustedProxyCIDRs: item.Geo.TrustedProxyCIDRs,
		BlockedRegions: item.Geo.BlockedRegions, RegionCIDRs: item.Geo.RegionCIDRs,
	}
}

func encodeRuntimePolicies(fields Fields) ([]byte, []byte, error) {
	dns, err := json.Marshal(fields.DNS)
	if err != nil {
		return nil, nil, err
	}
	geo, err := json.Marshal(fields.Geo)
	if err != nil {
		return nil, nil, err
	}
	return dns, geo, nil
}

func nullablePort(value uint16) any {
	if value == 0 {
		return nil
	}
	return int32(value)
}

// optionalUUIDText is an optional id for an audit payload (nil: no package).
func optionalUUIDText(value *uuid.UUID) any {
	if value == nil {
		return nil
	}
	return value.String()
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func endpointKind(item Forward) string {
	if item.UpstreamHost != "" {
		return "domain"
	}
	return "address"
}

func authorizeAutomaticMutation(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID uuid.UUID) error {
	err := edgeautopublish.AuthorizeMutationTx(ctx, tx, edgeautopublish.Actor{
		UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind,
	}, targetScopeID, edgeautopublish.PermissionStreamsManage)
	if errors.Is(err, edgeautopublish.ErrPermissionDenied) {
		return ErrPermissionDenied
	}
	return err
}

// authorizeAutomaticMutations is authorizeAutomaticMutation for several
// target scopes at once (the IAM lock is taken once, before any row lock).
func authorizeAutomaticMutations(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeIDs []uuid.UUID) error {
	err := edgeautopublish.AuthorizeMutationsTx(ctx, tx, edgeautopublish.Actor{
		UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind,
	}, targetScopeIDs, edgeautopublish.PermissionStreamsManage)
	if errors.Is(err, edgeautopublish.ErrPermissionDenied) {
		return ErrPermissionDenied
	}
	return err
}

func mutationTargetScope(ctx context.Context, tx pgx.Tx, actor Actor, resourceID uuid.UUID) (uuid.UUID, error) {
	if actor.ScopeKind == "tenant" {
		return actor.ScopeID, nil
	}
	var scopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT scope_id FROM l4_forwards WHERE id=$1`, resourceID).Scan(&scopeID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, err
	}
	return scopeID, nil
}

func enqueueAutomaticMutation(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID, resourceID uuid.UUID,
	intent PublishIntent,
	operation, requestID string,
) error {
	_, err := edgeautopublish.EnqueueTx(ctx, tx, edgeautopublish.EnqueueInput{
		Actor:         edgeautopublish.Actor{UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind},
		TargetScopeID: targetScopeID, SourceKind: edgeautopublish.SourceL4,
		SourceResourceID: resourceID, Operation: operation, Reason: edgeautopublish.ReasonResourceMutation,
		Permission: edgeautopublish.PermissionStreamsManage, SourceRequestID: requestID,
		PublishIntentID: intent.ID, ConfigurationSourceRevision: intent.ConfigurationSourceRevision,
	})
	return err
}

func automaticAuditPayload(actor Actor, targetScopeID uuid.UUID, operation string, payload map[string]any) map[string]any {
	payload["actor_scope_id"] = actor.ScopeID.String()
	payload["target_scope_id"] = targetScopeID.String()
	payload["operation"] = operation
	payload["reason"] = edgeautopublish.ReasonResourceMutation
	return payload
}

func authorizeTarget(ctx context.Context, tx pgx.Tx, actor Actor, scopeID, ownerID uuid.UUID) error {
	var kind string
	var ownerMember bool
	if err := tx.QueryRow(ctx, `
		SELECT scope.kind, EXISTS (
			SELECT 1 FROM memberships m
			WHERE m.scope_id = scope.id AND m.user_id = $2 AND m.status = 'active'
		)
		FROM access_scopes scope WHERE scope.id = $1`, scopeID, ownerID).Scan(&kind, &ownerMember); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidInput
		}
		return err
	}
	if kind != "tenant" || !ownerMember {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" && (actor.ScopeID != scopeID || actor.UserID != ownerID) {
		return ErrPermissionDenied
	}
	return nil
}

func refreshEligibility(ctx context.Context, query rowQuerier, item *Forward, lock bool) error {
	if item.PackageSubscriptionID == nil {
		// No package: eligible (community edition, the platform default line group).
		item.EligibilityState = EligibilityEligible
		return nil
	}
	state, err := packageEligibility(ctx, query, item.ScopeID, *item.PackageSubscriptionID, lock)
	if err != nil {
		return err
	}
	item.EligibilityState = state
	return nil
}

func packageEligibility(
	ctx context.Context,
	query rowQuerier,
	scopeID, subscriptionID uuid.UUID,
	lock bool,
) (EligibilityState, error) {
	statement := `SELECT clock_timestamp(),lifecycle_status,starts_at,ends_at,admin_enabled,deleted_at IS NOT NULL
		FROM package_subscriptions WHERE tenant_scope_id=$1 AND id=$2`
	if lock {
		statement += ` FOR UPDATE`
	}
	var evaluatedAt, startsAt, endsAt time.Time
	var lifecycle string
	var adminEnabled, deleted bool
	if err := query.QueryRow(ctx, statement, scopeID, subscriptionID).Scan(
		&evaluatedAt, &lifecycle, &startsAt, &endsAt, &adminEnabled, &deleted,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EligibilityIneligible, nil
		}
		return EligibilityIneligible, err
	}
	if lifecycle != "active" || !adminEnabled || deleted || evaluatedAt.Before(startsAt) || !evaluatedAt.Before(endsAt) {
		return EligibilityIneligible, nil
	}
	var active bool
	if err := query.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM package_subscription_entitlement_versions entitlement
		WHERE entitlement.subscription_id=$1 AND entitlement.tenant_scope_id=$2
		  AND entitlement.revision=package_subscription_effective_entitlement_revision($1,$3)
		  AND entitlement.entitlement_status='active'
	)`, subscriptionID, scopeID, evaluatedAt).Scan(&active); err != nil {
		return EligibilityIneligible, err
	}
	if !active {
		return EligibilityIneligible, nil
	}
	return EligibilityEligible, nil
}

// rejectStreamSocketConflict checks a saved stream's live sockets against its
// scope's websites and other streams under the shared sharing rules
// (edgeconfig.FindPortConflicts, decisions/multitenant-composition-compat-
// 2026-10-16 补充 2). Plain sockets and (port, SNI) are also unique across
// scopes in the database; other scopes' websites are checked per node on
// publication.
func rejectStreamSocketConflict(ctx context.Context, tx pgx.Tx, scopeID, streamID uuid.UUID) error {
	rows, err := tx.Query(ctx, `
		SELECT site.id, site.domain, COALESCE((
		           SELECT array_agg(current_domain.canonical_domain ORDER BY current_domain.canonical_domain)
		           FROM (
		               SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain, fact.action
		               FROM site_domain_facts fact
		               WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
		               ORDER BY fact.canonical_domain, fact.global_sequence DESC
		           ) current_domain WHERE current_domain.action='activate'
		       ), ARRAY[site.domain]::text[]), site.http_ports, site.https_enabled, site.https_ports
		FROM sites site
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL`, scopeID)
	if err != nil {
		return err
	}
	var claims []edgeconfig.PortClaim
	names := map[string]string{} // claim ID -> site domain or forward name
	for rows.Next() {
		var siteID uuid.UUID
		var domain string
		var domains, httpPorts, httpsPorts []string
		var httpsEnabled bool
		if err := rows.Scan(&siteID, &domain, &domains, &httpPorts, &httpsEnabled, &httpsPorts); err != nil {
			rows.Close()
			return err
		}
		names[siteID.String()] = domain
		add := func(ports []string, tls bool) error {
			for _, raw := range ports {
				port, err := strconv.ParseUint(raw, 10, 16)
				if err != nil {
					return err
				}
				claims = append(claims, edgeconfig.SiteListenerPortClaims("site", siteID.String(), uint16(port), tls, tls, domains)...)
			}
			return nil
		}
		if err := add(httpPorts, false); err != nil {
			rows.Close()
			return err
		}
		if httpsEnabled {
			if err := add(httpsPorts, true); err != nil {
				rows.Close()
				return err
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `
		SELECT forward.id, forward.name, listener.protocol, listener.port,
		       COALESCE(listener.port_end, 0), listener.tls_passthrough, listener.server_names,
		       forward.proxy_protocol_inbound OR forward.proxy_protocol_v1
		FROM l4_forward_listeners listener
		JOIN l4_forwards forward ON forward.id=listener.stream_id
		WHERE forward.scope_id=$1 AND forward.deleted_at IS NULL AND listener.retired_at IS NULL`, scopeID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id uuid.UUID
		var passthrough, proxyProtocol bool
		var protocol, name string
		var port, portEnd int
		var serverNames []string
		if err := rows.Scan(&id, &name, &protocol, &port, &portEnd, &passthrough, &serverNames, &proxyProtocol); err != nil {
			rows.Close()
			return err
		}
		names[id.String()] = name
		claim := edgeconfig.PortClaim{Owner: "stream", ID: id.String(), Kind: edgeconfig.PortClaimPlainL4,
			Protocol: edgeconfig.StreamProtocol(protocol), Port: uint16(port), PortEnd: uint16(portEnd), ProxyProtocol: proxyProtocol}
		if passthrough {
			claim.Kind, claim.Names = edgeconfig.PortClaimTLSL4, serverNames
		}
		claims = append(claims, claim)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	self := streamID.String()
	var proxyConflict bool
	for _, conflict := range edgeconfig.FindPortConflicts(claims) {
		if conflict.Claim.ID != self && conflict.Other.ID != self {
			continue
		}
		if !conflict.ProxyProtocol {
			other := conflict.Other
			if other.ID == self {
				other = conflict.Claim
			}
			start, stop := conflict.Overlap()
			located := &PortConflictError{Protocol: string(other.Protocol), Port: start, With: PortConflictStream, Name: names[other.ID]}
			if stop > start {
				located.PortEnd = stop
			}
			if other.Owner == "site" {
				located.With = PortConflictSite
			}
			return located
		}
		proxyConflict = true
	}
	if proxyConflict {
		return ErrSharedPortProxyProtocol
	}
	return nil
}

// 分组与默认设置走 236 自己的幂等收据表，转发的收据表只接受 stream.* 三种操作。
func writeRequestTable(operation string) string {
	if strings.HasPrefix(operation, "stream_group.") || strings.HasPrefix(operation, "stream_default.") {
		return "l4_stream_group_default_write_requests"
	}
	return "l4_write_requests"
}

func (s *Store) findWrite(ctx context.Context, tx pgx.Tx, actorID uuid.UUID, operation, key string, digest [32]byte) (storedWrite, bool, error) {
	var existingDigest, responseBody []byte
	var resourceID *uuid.UUID
	var completedAt *time.Time
	err := tx.QueryRow(ctx, `
		SELECT request_digest, resource_id, response_body, completed_at
		FROM `+writeRequestTable(operation)+` WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3`,
		actorID, operation, key).Scan(&existingDigest, &resourceID, &responseBody, &completedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedWrite{}, false, nil
	}
	if err != nil {
		return storedWrite{}, false, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || resourceID == nil || completedAt == nil {
		return storedWrite{}, false, ErrIdempotencyConflict
	}
	return storedWrite{Replayed: true, ResponseBody: responseBody}, true, nil
}

func (s *Store) claimWrite(ctx context.Context, tx pgx.Tx, actorID, scopeID uuid.UUID, operation, key string, digest [32]byte) (storedWrite, error) {
	command, err := tx.Exec(ctx, `
		INSERT INTO `+writeRequestTable(operation)+` (id, actor_user_id, target_scope_id, operation, idempotency_key, request_digest)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (actor_user_id, operation, idempotency_key) DO NOTHING`, uuid.New(), actorID, scopeID, operation, key, digest[:])
	if err != nil {
		return storedWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, nil
	}
	write, found, err := s.findWrite(ctx, tx, actorID, operation, key, digest)
	if err != nil {
		return storedWrite{}, err
	}
	if !found {
		return storedWrite{}, ErrIdempotencyConflict
	}
	return write, nil
}

func (s *Store) completeWrite(ctx context.Context, tx pgx.Tx, actorID uuid.UUID, operation, key string, resourceID uuid.UUID, status int, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE `+writeRequestTable(operation)+` SET resource_id = $4, response_status = $5, response_body = $6::jsonb, completed_at = $7
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3 AND completed_at IS NULL`,
		actorID, operation, key, resourceID, status, payload, s.now().UTC())
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func classifyConflict(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23514" &&
		(postgresError.ConstraintName == "l4_forwards_tls_passthrough_293" ||
			postgresError.ConstraintName == "l4_forward_listeners_tls_passthrough_293") {
		return ErrInvalidInput
	}
	if errors.As(err, &postgresError) && postgresError.Code == "23P01" &&
		(postgresError.ConstraintName == "l4_forward_listeners_tcp_range_334" ||
			postgresError.ConstraintName == "l4_forward_listeners_udp_range_334") {
		return ErrPortConflict // a concurrent save took the ports after locateSocketConflict
	}
	if errors.As(err, &postgresError) && postgresError.Code == "23514" &&
		(postgresError.ConstraintName == "l4_forwards_port_range_334" ||
			postgresError.ConstraintName == "l4_forward_listeners_port_range_334") {
		return ErrInvalidInput
	}
	if !errors.As(err, &postgresError) || postgresError.Code != "23505" {
		return err
	}
	switch postgresError.ConstraintName {
	case "l4_forwards_scope_name_lower_active_idx":
		return ErrNameConflict
	case "l4_forwards_protocol_port_active_293_idx", "l4_forward_listeners_socket_293_idx",
		"l4_forward_server_names_port_293_idx":
		return ErrPortConflict
	case "l4_forward_listeners_pkey":
		return ErrInvalidInput
	default:
		return err
	}
}

func listWhere(actor Actor, filter ListFilter) (string, []any) {
	conditions := []string{"f.deleted_at IS NULL"}
	args := make([]any, 0, 6)
	add := func(format string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(format, len(args)))
	}
	if actor.ScopeKind == "tenant" {
		add("f.scope_id = $%d", actor.ScopeID)
		add("f.owner_user_id = $%d", actor.UserID)
	}
	if filter.Search != "" {
		args = append(args, strings.ToLower(filter.Search))
		position := len(args)
		conditions = append(conditions, fmt.Sprintf(
			"(position($%d in lower(f.name)) > 0 OR position($%d in lower(f.remark)) > 0 OR "+
				"position($%d in COALESCE(host(f.upstream_address), '')) > 0 OR position($%d in COALESCE(f.upstream_host, '')) > 0 OR "+
				"position($%d in f.display_id::text) > 0 OR position($%d in f.listen_port::text) > 0)",
			position, position, position, position, position, position,
		))
	}
	if filter.Protocol != "" || filter.ListenPort != nil {
		listenerConditions := []string{"listener.stream_id=f.id", "listener.retired_at IS NULL"}
		if filter.Protocol != "" {
			args = append(args, filter.Protocol)
			listenerConditions = append(listenerConditions, fmt.Sprintf("listener.protocol=$%d", len(args)))
		}
		if filter.ListenPort != nil {
			args = append(args, *filter.ListenPort)
			listenerConditions = append(listenerConditions, fmt.Sprintf("$%d BETWEEN listener.port AND COALESCE(listener.port_end, listener.port)", len(args)))
		}
		conditions = append(conditions, "EXISTS (SELECT 1 FROM l4_forward_listeners listener WHERE "+strings.Join(listenerConditions, " AND ")+")")
	}
	if filter.Enabled != nil {
		add("f.enabled = $%d", *filter.Enabled)
	}
	if filter.Upstream != "" {
		args = append(args, filter.Upstream)
		position := len(args)
		// the primary origin, its host, and every origin of the pool
		// (second, down or IPv6 ones too); EXISTS keeps one row per forward
		conditions = append(conditions, fmt.Sprintf(
			"(position($%d in COALESCE(host(f.upstream_address), '')) > 0 OR position($%d in lower(COALESCE(f.upstream_host, ''))) > 0 OR "+
				"EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(f.origins, '[]'::jsonb)) pool_origin "+
				"WHERE position($%d in lower(pool_origin->>'address')) > 0))",
			position, position, position,
		))
	}
	if filter.CNAMEDomain != "" {
		add("position($%d in lower(COALESCE(f.cname_domain, own.domain, cn.domain, ''))) > 0", filter.CNAMEDomain)
	}
	if filter.CNAMEHostname != "" {
		add("position($%d in lower(CASE WHEN f.cname_domain IS NULL AND f.cname_mode IS NULL THEN COALESCE(cn_package.hostname, '') "+
			"ELSE COALESCE(own.lkg_hostname, '') END)) > 0", filter.CNAMEHostname)
	}
	if filter.DisplayID != nil {
		add("f.display_id = $%d", *filter.DisplayID)
	}
	if filter.OwnerDisplayID != nil {
		add("u.display_id = $%d", *filter.OwnerDisplayID)
	}
	if filter.PublicationState != "" {
		add(`CASE WHEN automatic.state IN ('pending','leased','reconciling','succeeded','failed','superseded')
			THEN automatic.state WHEN automatic.state='retry_wait' THEN 'retrying' ELSE 'unknown' END = $%d`, filter.PublicationState)
	}
	if filter.GroupID != nil {
		add(`EXISTS (SELECT 1 FROM l4_stream_group_members member
			JOIN l4_stream_groups stream_group ON stream_group.id=member.group_id AND stream_group.scope_id=member.scope_id
			WHERE member.stream_id=f.id AND member.scope_id=f.scope_id AND stream_group.deleted_at IS NULL AND member.group_id=$%d)`, *filter.GroupID)
	}
	if filter.RegionID != nil {
		add("line.region_id = $%d", *filter.RegionID)
	}
	if filter.NodeGroupID != nil {
		add("line.node_group_id = $%d", *filter.NodeGroupID)
	}
	if filter.SyncState != "" {
		add(syncStateExpression+" = $%d", filter.SyncState)
	}
	if filter.AdminStatus != "" {
		add("f.admin_status = $%d", filter.AdminStatus)
	}
	if filter.PackageProductID != nil {
		add(`EXISTS (SELECT 1 FROM package_subscriptions package_subscription
			WHERE package_subscription.id=f.package_subscription_id AND package_subscription.tenant_scope_id=f.scope_id
			AND package_subscription.product_id=$%d)`, *filter.PackageProductID)
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

var forwardSelect = `SELECT ` +
	// CNAME (no website, migration 506): with the stream's own CNAME domain
	// or mode (migration 499) its own allocation (migration 505): LKG
	// hostname, zone, and the state of its latest intent (pending while
	// queued/running, failed with its code) or else of the allocation.
	// Without one, 按套餐 shows the package's allocation and 按转发 nothing.
	`f.id, f.display_id::text, f.scope_id, ` +
	`CASE WHEN f.cname_domain IS NULL AND f.cname_mode IS NULL THEN COALESCE(cn_package.hostname, '') ELSE COALESCE(own.lkg_hostname, '') END, ` +
	`COALESCE(f.cname_domain, own.domain, cn.domain), NULL::text, ` +
	`CASE WHEN f.cname_domain IS NULL AND f.cname_mode IS NULL THEN cn_package.state ` +
	`WHEN own_intent.state IN ('queued','running') THEN 'pending' WHEN own_intent.state IN ('failed','cancelled') THEN 'failed' ` +
	`ELSE own.state END, ` +
	`f.package_subscription_id, f.owner_user_id, f.name, f.remark, ` +
	`f.protocol, f.listen_address, f.listen_port, COALESCE(host(f.upstream_address), ''), COALESCE(f.upstream_host, ''), ` +
	`f.upstream_port, f.dns_policy, f.geo_policy, f.connect_timeout_ms, f.response_timeout_ms, ` +
	`f.max_connections_per_client, f.proxy_protocol_inbound, f.proxy_protocol_v1, f.tls_passthrough, f.server_names, ` +
	`f.max_new_connections_per_client_per_second, f.new_connection_burst, f.new_connection_ban_seconds, f.toa, f.session_log_enabled, ` +
	`COALESCE(f.listen_port_end, 0), f.upstream_follow_port, f.guard_rules, ` +
	`f.origins, f.listen_ipv6, f.acl_default_action, f.acl_rules, f.admin_status, ` +
	`f.cname_domain, f.cname_mode, f.region_id, f.node_group_id, f.backup_node_group_id, ` +
	`f.balance_way, f.enabled, f.revision, f.created_at, f.updated_at, u.display_name, ` +
	forwardGroupReferences + `, ` +
	`pi.id, pi.version, pi.operation, pi.desired_state, pi.resource_revision, pi.configuration_source_revision, ` +
	`pi.runtime_spec, pi.created_at, automatic.request_id, automatic.state, ` +
	`automatic.publication_id, automatic.rollout_id, subscription.product_snapshot->>'name', subscription.ends_at, ` + additionalListenersJSON + `, ` +
	`line.region_id, COALESCE((SELECT name FROM region_catalog WHERE id=line.region_id), ''), ` +
	`line.node_group_id, COALESCE((SELECT name FROM node_line_groups WHERE id=line.node_group_id AND deleted_at IS NULL LIMIT 1), ''), ` +
	`line.backup_node_group_id, COALESCE((SELECT name FROM node_line_groups WHERE id=line.backup_node_group_id AND deleted_at IS NULL LIMIT 1), ''), ` +
	syncStateExpression + `, ` +
	`CASE WHEN f.cname_domain IS NULL AND f.cname_mode IS NULL THEN NULL ` +
	`WHEN own_intent.state IN ('failed','cancelled') THEN COALESCE(own_intent.error_code, 'cname_allocation_cancelled') ` +
	`WHEN own_intent.state IN ('queued','running') THEN NULL ELSE own.failure_code END ` + forwardFrom

const forwardFrom = `FROM l4_forwards f JOIN users u ON u.id = f.owner_user_id ` +
	`LEFT JOIN package_subscriptions subscription ON subscription.id = f.package_subscription_id AND subscription.tenant_scope_id = f.scope_id ` +
	streamOwnCNAMEJoins +
	`JOIN LATERAL (SELECT * FROM l4_publish_intents WHERE stream_id = f.id AND scope_id=f.scope_id ORDER BY version DESC LIMIT 1) pi ON true ` +
	`LEFT JOIN LATERAL (` +
	`SELECT request_row.id AS request_id, state.state, state.publication_id, state.rollout_id ` +
	`FROM edge_automatic_publication_requests request_row ` +
	`JOIN LATERAL (SELECT state,publication_id,rollout_id ` +
	`FROM edge_automatic_publication_request_state_facts WHERE request_id=request_row.id ` +
	`ORDER BY sequence DESC LIMIT 1) state ON true ` +
	`WHERE request_row.source_kind='l4' AND request_row.publish_intent_id=pi.id AND request_row.target_scope_id=f.scope_id ` +
	`ORDER BY request_row.created_at DESC,request_row.id DESC LIMIT 1` +
	`) automatic ON true ` +
	// 线路: the stream's own region / line group (migration 491), else its
	// package's (region_id, node_group_id, backup_node_group).
	`LEFT JOIN LATERAL (SELECT ` + effectiveLineColumns + `) line ON true ` +
	`LEFT JOIN LATERAL (SELECT ` +
	// The package snapshot names its mode per_site / shared (packagecatalog).
	`COALESCE(f.cname_mode, CASE subscription.product_snapshot#>>'{spec,cname,mode}' WHEN 'shared' THEN 'package' ELSE 'site' END) AS mode, ` +
	`COALESCE(f.cname_domain, NULLIF(subscription.product_snapshot#>>'{spec,cname,domain}','')) AS domain` +
	`) cn ON true ` +
	`LEFT JOIN LATERAL (SELECT claim.hostname, allocation.state FROM cname_allocations allocation ` +
	`LEFT JOIN cname_hostname_claims claim ON claim.id = allocation.lkg_claim_id ` +
	`WHERE cn.mode = 'package' AND allocation.tenant_scope_id = f.scope_id AND allocation.mode = 'package' ` +
	`AND allocation.package_subscription_id = f.package_subscription_id LIMIT 1) cn_package ON true `

// effectiveLineColumns is a stream's line (alias f, its package subscription
// alias subscription): its own region / group / backup group, else the
// package snapshot's.
const effectiveLineColumns = `COALESCE(f.region_id, NULLIF(subscription.product_snapshot#>>'{spec,region_id}','')::uuid) AS region_id, ` +
	`COALESCE(f.node_group_id, NULLIF(subscription.product_snapshot#>>'{spec,node_group_id}','')::uuid, ` +
	// community edition: a stream without a package is on the platform default line group
	`(SELECT platform_default.id FROM node_line_groups platform_default WHERE platform_default.is_platform_default ` +
	`AND platform_default.deleted_at IS NULL AND f.package_subscription_id IS NULL)) AS node_group_id, ` +
	`COALESCE(f.backup_node_group_id, NULLIF(subscription.product_snapshot#>>'{spec,backup_node_group_id}','')::uuid) AS backup_node_group_id`

// streamOwnCNAMEJoins: a stream's own CNAME allocation and latest intent
// (migration 505), joined only while the stream carries its override.
const streamOwnCNAMEJoins = `LEFT JOIN LATERAL (SELECT lkg_claim.hostname AS lkg_hostname, current_claim.domain, ` +
	`allocation.state, allocation.failure_code FROM cname_stream_bindings binding ` +
	`JOIN cname_allocations allocation ON allocation.tenant_scope_id = binding.tenant_scope_id AND allocation.id = binding.allocation_id ` +
	`JOIN cname_hostname_claims current_claim ON current_claim.id = allocation.current_claim_id ` +
	`LEFT JOIN cname_hostname_claims lkg_claim ON lkg_claim.id = allocation.lkg_claim_id ` +
	`WHERE binding.tenant_scope_id = f.scope_id AND binding.stream_id = f.id) own ` +
	`ON (f.cname_domain IS NOT NULL OR f.cname_mode IS NOT NULL) ` +
	`LEFT JOIN LATERAL (SELECT job.state, item.error_code FROM cname_stream_intents intent ` +
	`JOIN background_jobs job ON job.tenant_id = intent.tenant_id AND job.id = intent.job_id ` +
	`LEFT JOIN background_job_items item ON item.tenant_id = job.tenant_id AND item.job_id = job.id AND item.ordinal = 1 ` +
	`WHERE intent.tenant_scope_id = f.scope_id AND intent.stream_id = f.id ` +
	`ORDER BY intent.created_at DESC, intent.job_id DESC LIMIT 1) own_intent ` +
	`ON (f.cname_domain IS NOT NULL OR f.cname_mode IS NOT NULL) `

// syncStateExpression is 同步状态 from the latest intent's automatic
// publication, whose outcome is the rollout's node deployment receipts
// (succeeded = every target node reported healthy): done, failed, or pending
// while it runs or before a publication picked the intent up.
const syncStateExpression = `CASE automatic.state WHEN 'succeeded' THEN 'done' WHEN 'failed' THEN 'failed' ELSE 'pending' END`

func forwardColumns(alias string) string {
	return alias + `.id, ` + alias + `.display_id::text, ` + alias + `.scope_id, ` + alias + `.package_subscription_id, ` +
		alias + `.owner_user_id, ` + alias + `.name, ` + alias + `.remark, ` +
		alias + `.protocol, ` + alias + `.listen_address, ` + alias + `.listen_port, ` +
		`COALESCE(host(` + alias + `.upstream_address), ''), COALESCE(` + alias + `.upstream_host, ''), ` +
		alias + `.upstream_port, ` + alias + `.dns_policy, ` + alias + `.geo_policy, ` + alias + `.connect_timeout_ms, ` +
		alias + `.response_timeout_ms, ` + alias + `.max_connections_per_client, ` +
		alias + `.proxy_protocol_inbound, ` + alias + `.proxy_protocol_v1, ` + alias + `.tls_passthrough, ` + alias + `.server_names, ` +
		alias + `.max_new_connections_per_client_per_second, ` + alias + `.new_connection_burst, ` + alias + `.new_connection_ban_seconds, ` +
		alias + `.toa, ` + alias + `.session_log_enabled, ` +
		`COALESCE(` + alias + `.listen_port_end, 0), ` + alias + `.upstream_follow_port, ` + alias + `.guard_rules, ` +
		alias + `.origins, ` + alias + `.listen_ipv6, ` + alias + `.acl_default_action, ` + alias + `.acl_rules, ` + alias + `.admin_status, ` +
		alias + `.cname_domain, ` + alias + `.cname_mode, ` + alias + `.region_id, ` + alias + `.node_group_id, ` + alias + `.backup_node_group_id, ` +
		alias + `.balance_way, ` + alias + `.enabled, ` +
		alias + `.revision, ` + alias + `.created_at, ` + alias + `.updated_at`
}

// groupReferencesSubquery 聚合出转发的所属分组（可属多个分组，故为数组）。
// 只能用字面量拼接：listWhere/forwardSelect 依赖它必须是编译期常量。
func groupReferencesSubquery(alias string) string {
	return `COALESCE((SELECT jsonb_agg(jsonb_build_object('id', g.id, 'name', g.name, 'remark', g.remark) ` +
		`ORDER BY g.display_id, g.id) FROM l4_stream_group_members m ` +
		`JOIN l4_stream_groups g ON g.id = m.group_id ` +
		`WHERE m.stream_id = ` + alias + `.id AND g.deleted_at IS NULL), '[]'::jsonb)`
}

var forwardGroupReferences = groupReferencesSubquery("f")
var selfGroupReferences = groupReferencesSubquery("l4_forwards")

func scanForward(scanner rowScanner) (Forward, error) {
	var item Forward
	var ownerName string
	var cname string
	var cnameDomain, cnameHostname, cnameState *string
	var runtimeJSON []byte
	var groupsJSON []byte
	var internalState *string
	destinations := forwardScanDestinations(&item, &ownerName, &groupsJSON, &cname, &cnameDomain, &cnameHostname, &cnameState)
	destinations = append(destinations,
		&item.PublishIntent.ID, &item.PublishIntent.Version, &item.PublishIntent.Operation,
		&item.PublishIntent.DesiredState, &item.PublishIntent.ResourceRevision,
		&item.PublishIntent.ConfigurationSourceRevision, &runtimeJSON,
		&item.PublishIntent.CreatedAt, &item.PublishIntent.AutomaticRequestID, &internalState,
		&item.PublishIntent.PublicationID, &item.PublishIntent.RolloutID, &item.PackageName, &item.PackageExpiresAt,
		&jsonValueScanner{target: &item.AdditionalListeners},
		&item.Line.RegionID, &item.Line.RegionName, &item.Line.NodeGroupID, &item.Line.NodeGroupName,
		&item.Line.BackupNodeGroupID, &item.Line.BackupNodeGroupName, &item.SyncState, &item.CNAMEFailureCode,
	)
	if err := scanner.Scan(destinations...); err != nil {
		return Forward{}, err
	}
	if cname != "" {
		item.CNAME = &cname
	}
	item.CNAMEDomain, item.CNAMEHostname, item.CNAMEState = cnameDomain, cnameHostname, cnameState
	groups, err := decodeGroupReferences(&groupsJSON)
	if err != nil {
		return Forward{}, err
	}
	item.Groups = groups
	if err := json.Unmarshal(runtimeJSON, &item.PublishIntent.RuntimeSpec); err != nil {
		return Forward{}, err
	}
	item.Owner = &OwnerReference{ID: item.ownerUserID, DisplayName: ownerName}
	fillOrigins(&item)
	if internalState != nil {
		item.PublishIntent.State = projectPublicationState(*internalState)
	} else {
		item.PublishIntent.State = PublicationStateUnknown
	}
	return item, nil
}

func projectPublicationState(internal string) string {
	switch internal {
	case PublicationStatePending, PublicationStateLeased, PublicationStateReconciling,
		PublicationStateSucceeded, PublicationStateFailed, PublicationStateSuperseded:
		return internal
	case "retry_wait":
		return PublicationStateRetrying
	default:
		return PublicationStateUnknown
	}
}

func markPublicationUnknown(intent *PublishIntent) {
	intent.State = PublicationStateUnknown
	intent.AutomaticRequestID = nil
	intent.PublicationID = nil
	intent.RolloutID = nil
}

func scanForwardWithoutIntent(scanner rowScanner) (Forward, error) {
	var item Forward
	var ownerName string
	if err := scanner.Scan(forwardScanDestinationsWithoutGroups(&item, &ownerName)...); err != nil {
		return Forward{}, err
	}
	item.Owner = &OwnerReference{ID: item.ownerUserID, DisplayName: ownerName}
	fillOrigins(&item)
	return item, nil
}

// fillOrigins lists a single-origin stream's origin (weight 1, up), so the
// 源站列表 always reads as a list.
func fillOrigins(item *Forward) {
	if len(item.Origins) != 0 {
		return
	}
	address := item.UpstreamAddress
	if address == "" {
		address = item.UpstreamHost
	}
	item.Origins = []Origin{{Address: address, Weight: 1}}
}

// decodeGroupReferences 把聚合出来的分组数组还原成切片；缺列（如 RETURNING 路径）时留空。
func decodeGroupReferences(raw *[]byte) ([]GroupReference, error) {
	if raw == nil || len(*raw) == 0 || string(*raw) == "null" {
		return nil, nil
	}
	var refs []GroupReference
	if err := json.Unmarshal(*raw, &refs); err != nil {
		return nil, fmt.Errorf("decode stream group references: %w", err)
	}
	return refs, nil
}

func forwardScanDestinations(item *Forward, ownerName *string, groupsJSON *[]byte, cnameTargets ...any) []any {
	destinations := forwardScanDestinationsWithoutGroups(item, ownerName)
	if len(cnameTargets) == 4 {
		withCNAME := make([]any, 0, len(destinations)+len(cnameTargets))
		// id, display_id, scope_id, then the CNAME columns (forwardSelect).
		withCNAME = append(withCNAME, destinations[:3]...)
		withCNAME = append(withCNAME, cnameTargets...)
		withCNAME = append(withCNAME, destinations[3:]...)
		destinations = withCNAME
	}
	return append(destinations, groupsJSON)
}

// forwardScanDestinationsWithoutGroups 对应不聚合分组的查询：INSERT/UPDATE 的
// RETURNING 没有分组列，分组随后由 loadGroupReferences 单独补齐。
func forwardScanDestinationsWithoutGroups(item *Forward, ownerName *string) []any {
	return []any{
		&item.ID, &item.DisplayID, &item.ScopeID, &item.PackageSubscriptionID, &item.ownerUserID, &item.Name, &item.Remark,
		&item.Protocol, &item.ListenAddress, &item.ListenPort, &item.UpstreamAddress, &item.UpstreamHost,
		&item.UpstreamPort, &jsonValueScanner{target: &item.DNS}, &jsonValueScanner{target: &item.Geo}, &item.ConnectTimeoutMS,
		&item.ResponseTimeoutMS, &item.MaxConnectionsPerClient, &item.ProxyProtocolInbound, &item.ProxyProtocolV1,
		&item.TLSPassthrough, &item.ServerNames, &item.MaxNewConnectionsPerClientPerSecond, &item.NewConnectionBurst,
		&item.NewConnectionBanSeconds, &item.TOA, &item.SessionLogEnabled, &item.ListenPortEnd, &item.UpstreamFollowPort,
		&jsonValueScanner{target: &item.GuardRules},
		&jsonValueScanner{target: &item.Origins}, &item.ListenIPv6, &item.ACL.DefaultAction,
		&jsonValueScanner{target: &item.ACL.Rules}, &item.AdminStatus,
		&item.Overrides.CNAMEDomain, &item.Overrides.CNAMEMode, &item.Overrides.RegionID, &item.Overrides.NodeGroupID,
		&item.Overrides.BackupNodeGroupID,
		&item.BalanceWay, &item.Enabled, &item.Revision,
		&item.CreatedAt, &item.UpdatedAt, ownerName,
	}
}

// requireGuardRuleLimit applies the platform's stream ACL rule limit
// (系统设置 > 资源限制 > 转发 > ACL 规则数量限制, acl_max_limit) to the
// stream's guard rules; the node carries at most edgeconfig.L4GuardRulesMax.
func requireGuardRuleLimit(ctx context.Context, tx pgx.Tx, fields Fields) error {
	count := len(fields.GuardRules)
	if fields.ACL != nil {
		count += len(fields.ACL.Rules)
	}
	if count == 0 {
		return nil
	}
	resources, err := systemconfig.LoadEffectivePlatformResources(ctx, tx, systemconfig.EffectiveResourceTarget{})
	if err != nil {
		return err
	}
	return guardRuleLimitError(count, resources.Resources.MaxACLRulesPerPolicy)
}

func guardRuleLimitError(count, limit int) error {
	if count > limit {
		return ErrGuardRuleLimit
	}
	return nil
}
