package nodemonitoringoverride

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) (*Store, error) {
	if pool == nil || now == nil {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, auditor: audit.NewWithClock(pool, now), now: now}, nil
}

type stored struct {
	revision  int64
	updatedAt time.Time
	fields    Fields
}

func (store *Store) Get(ctx context.Context, actor Actor, nodeID uuid.UUID) (View, error) {
	if store == nil || ctx == nil || !validActor(actor) || nodeID == uuid.Nil {
		return View{}, ErrInvalidInput
	}
	var view View
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		document, _, err := systemconfig.LoadActiveNodeMonitoring(ctx, tx)
		if err != nil {
			return err
		}
		current, delivery, err := loadNode(ctx, tx, actor.ScopeID, nodeID, false)
		if err != nil {
			return err
		}
		view, err = buildView(ctx, tx, actor.ScopeID, nodeID, document, current, delivery)
		return err
	})
	if err != nil {
		return View{}, fmt.Errorf("get node monitoring override: %w", err)
	}
	return view, nil
}

func (store *Store) Put(ctx context.Context, actor Actor, request PutRequest) (View, bool, error) {
	if store == nil || ctx == nil || !validActor(actor) || request.NodeID == uuid.Nil || request.ExpectedRevision < 0 ||
		!validKey(request.IdempotencyKey) || !validKey(request.RequestID) {
		return View{}, false, ErrInvalidInput
	}
	fields, err := normalizeFields(request.Fields)
	if err != nil {
		return View{}, false, err
	}
	digest, err := requestDigest(request.NodeID, request.ExpectedRevision, fields)
	if err != nil {
		return View{}, false, err
	}
	var view View
	replayed := false
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		// Platform/stream locks first, then the node row: activation order.
		document, _, err := systemconfig.LoadActiveNodeMonitoring(ctx, tx)
		if err != nil {
			return err
		}
		claimed, response, err := store.claimWrite(ctx, tx, actor, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if !claimed {
			replayed = true
			return json.Unmarshal(response, &view)
		}
		current, delivery, err := loadNode(ctx, tx, actor.ScopeID, request.NodeID, true)
		if err != nil {
			return err
		}
		if current.revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if document.ActiveRevision > 0 && fields.ProbeTimeoutMS != nil {
			platform, _ := document.Value.(systemconfig.NodeMonitoringConfiguration)
			if *fields.ProbeTimeoutMS > platform.ProbeIntervalMS {
				return ErrTimeoutTooLong
			}
		}
		changed := changedFields(current.fields, fields)
		if len(changed) > 0 {
			if current.revision >= nodemonitoringconfig.MaxOverrideRevision {
				return ErrRevisionExhausted
			}
			now := store.now().UTC()
			if current.revision == 0 {
				_, err = tx.Exec(ctx, `INSERT INTO node_monitoring_overrides(node_id,scope_id,monitor_enabled,protocol,
					probe_timeout_ms,monitor_port,monitor_action,revision,updated_by_user_id,created_at,updated_at)
					VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$9)`, request.NodeID, actor.ScopeID, fields.MonitorEnabled,
					fields.Protocol, fields.ProbeTimeoutMS, fields.MonitorPort, fields.MonitorAction, actor.UserID, now)
			} else {
				_, err = tx.Exec(ctx, `UPDATE node_monitoring_overrides SET monitor_enabled=$2,protocol=$3,
					probe_timeout_ms=$4,monitor_port=$5,monitor_action=$6,revision=revision+1,updated_by_user_id=$7,
					updated_at=GREATEST(updated_at,$8) WHERE node_id=$1`, request.NodeID, fields.MonitorEnabled,
					fields.Protocol, fields.ProbeTimeoutMS, fields.MonitorPort, fields.MonitorAction, actor.UserID, now)
			}
			if err != nil {
				return fmt.Errorf("write node monitoring override: %w", err)
			}
			current, _, err = loadNode(ctx, tx, actor.ScopeID, request.NodeID, false)
			if err != nil {
				return err
			}
		}
		view, err = buildView(ctx, tx, actor.ScopeID, request.NodeID, document, current, delivery)
		if err != nil {
			return err
		}
		if len(changed) > 0 {
			payload := map[string]any{"changed_fields": changed, "revision": view.Revision,
				"delivery_state": view.DeliveryState}
			if view.EffectiveRevision != nil {
				payload["effective_revision"] = *view.EffectiveRevision
			}
			if err := store.auditor.Append(ctx, tx, audit.Event{
				ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "node.monitoring_override.update",
				ResourceType: "node", ResourceID: request.NodeID.String(), RequestID: request.RequestID,
				Result: "success", Payload: payload,
			}); err != nil {
				return err
			}
		}
		return store.completeWrite(ctx, tx, actor, request.IdempotencyKey, request.NodeID, view)
	})
	if err != nil {
		return View{}, false, fmt.Errorf("put node monitoring override: %w", err)
	}
	return view, replayed, nil
}

func loadNode(ctx context.Context, tx pgx.Tx, scopeID, nodeID uuid.UUID, lock bool) (stored, string, error) {
	query := `SELECT CASE
			WHEN node.admin_state<>'active' THEN 'inactive'
			WHEN EXISTS (SELECT 1 FROM node_config_state serving
				WHERE serving.node_id=node.id AND serving.current_config_version_id IS NOT NULL) THEN 'serving'
			ELSE 'awaiting_configuration' END,
		node.admin_state
		FROM nodes node WHERE node.id=$1 AND node.scope_id=$2`
	if lock {
		query += ` FOR UPDATE OF node`
	}
	var delivery, adminState string
	err := tx.QueryRow(ctx, query, nodeID, scopeID).Scan(&delivery, &adminState)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && adminState == "retired" {
		return stored{}, "", ErrNotFound
	}
	if err != nil {
		return stored{}, "", fmt.Errorf("load node monitoring override target: %w", err)
	}
	var current stored
	err = tx.QueryRow(ctx, `SELECT revision,updated_at,monitor_enabled,protocol,probe_timeout_ms,monitor_port,monitor_action
		FROM node_monitoring_overrides WHERE node_id=$1 AND scope_id=$2`, nodeID, scopeID).Scan(&current.revision,
		&current.updatedAt, &current.fields.MonitorEnabled, &current.fields.Protocol, &current.fields.ProbeTimeoutMS,
		&current.fields.MonitorPort, &current.fields.MonitorAction)
	if errors.Is(err, pgx.ErrNoRows) {
		return stored{}, delivery, nil
	}
	if err != nil {
		return stored{}, "", fmt.Errorf("load node monitoring override: %w", err)
	}
	current.updatedAt = current.updatedAt.UTC()
	return current, delivery, nil
}

func buildView(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, nodeID uuid.UUID,
	document systemconfig.CategoryDocument,
	current stored,
	delivery string,
) (View, error) {
	configuration, err := systemconfig.ReadNodeMonitoringConfiguration(ctx, tx, scopeID)
	if err != nil {
		return View{}, err
	}
	view := View{SchemaVersion: 1, NodeID: nodeID, Revision: current.revision, Override: current.fields,
		PlatformState: configuration.State, DeliveryState: delivery}
	if current.revision > 0 {
		updatedAt := current.updatedAt
		view.UpdatedAt = &updatedAt
	}
	if document.ActiveRevision > 0 {
		platformRevision := document.ActiveRevision
		value, ok := document.Value.(systemconfig.NodeMonitoringConfiguration)
		if !ok {
			return View{}, ErrInvalidInput
		}
		effective := nodemonitoringconfig.ApplyOverride(value, current.fields.Override(current.revision))
		policy := systemconfig.MonitoringPolicyFor(effective)
		revision := nodemonitoringconfig.EffectiveRevision(platformRevision, current.revision)
		view.PlatformRevision, view.EffectiveRevision, view.EffectivePolicy = &platformRevision, &revision, &policy
		view.EffectiveAction = "none"
		if effective.MonitorAction == "pause" {
			view.EffectiveAction = "pause"
		}
	}
	return view, nil
}

// Override converts stored fields to the compiler overlay.
func (fields Fields) Override(revision int64) nodemonitoringconfig.Override {
	override := nodemonitoringconfig.Override{Revision: revision, MonitorEnabled: fields.MonitorEnabled}
	if fields.Protocol != nil {
		override.Protocol = *fields.Protocol
	}
	if fields.ProbeTimeoutMS != nil {
		value := *fields.ProbeTimeoutMS
		override.ProbeTimeoutMS = &value
	}
	if fields.MonitorPort != nil {
		value := uint16(*fields.MonitorPort)
		override.MonitorPort = &value
	}
	if fields.MonitorAction != nil {
		override.MonitorAction = *fields.MonitorAction
	}
	return override
}

func normalizeFields(fields Fields) (Fields, error) {
	if fields.Protocol != nil {
		value := strings.TrimSpace(*fields.Protocol)
		if value != "tcp" && value != "http" && value != "ping" {
			return Fields{}, ErrInvalidInput
		}
		fields.Protocol = &value
	}
	if fields.ProbeTimeoutMS != nil && (*fields.ProbeTimeoutMS < 100 || *fields.ProbeTimeoutMS > 60_000) {
		return Fields{}, ErrInvalidInput
	}
	if fields.MonitorPort != nil && (*fields.MonitorPort < 1 || *fields.MonitorPort > 65535) {
		return Fields{}, ErrInvalidInput
	}
	if fields.MonitorAction != nil {
		value := strings.TrimSpace(*fields.MonitorAction)
		if value != "none" && value != "pause" {
			return Fields{}, ErrInvalidInput
		}
		fields.MonitorAction = &value
	}
	return fields, nil
}

func changedFields(before, after Fields) []string {
	changed := make([]string, 0, 5)
	if !sameBool(before.MonitorEnabled, after.MonitorEnabled) {
		changed = append(changed, "monitor_enabled")
	}
	if !sameString(before.Protocol, after.Protocol) {
		changed = append(changed, "protocol")
	}
	if !sameInt(before.ProbeTimeoutMS, after.ProbeTimeoutMS) {
		changed = append(changed, "probe_timeout_ms")
	}
	if !sameInt(before.MonitorPort, after.MonitorPort) {
		changed = append(changed, "monitor_port")
	}
	if !sameString(before.MonitorAction, after.MonitorAction) {
		changed = append(changed, "monitor_action")
	}
	return changed
}

func sameBool(left, right *bool) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func sameString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func sameInt(left, right *int) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (store *Store) claimWrite(ctx context.Context, tx pgx.Tx, actor Actor, key string, digest [32]byte) (bool, []byte, error) {
	command, err := tx.Exec(ctx, `INSERT INTO node_write_requests(
		id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (actor_user_id,operation,idempotency_key) DO NOTHING`,
		uuid.New(), actor.UserID, actor.ScopeID, Operation, key, digest[:], store.now().UTC())
	if err != nil {
		return false, nil, fmt.Errorf("claim node monitoring override write: %w", err)
	}
	if command.RowsAffected() == 1 {
		return true, nil, nil
	}
	var existing, response []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT request_digest,response_body,completed_at FROM node_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`, actor.UserID, Operation, key).Scan(
		&existing, &response, &completedAt); err != nil {
		return false, nil, err
	}
	if !bytes.Equal(existing, digest[:]) || completedAt == nil || len(response) == 0 {
		return false, nil, ErrIdempotencyConflict
	}
	return false, response, nil
}

func (store *Store) completeWrite(ctx context.Context, tx pgx.Tx, actor Actor, key string, nodeID uuid.UUID, view View) error {
	encoded, err := json.Marshal(view)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE node_write_requests SET resource_id=$4,response_body=$5,completed_at=$6
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 AND completed_at IS NULL`,
		actor.UserID, Operation, key, nodeID, string(encoded), store.now().UTC())
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func requestDigest(nodeID uuid.UUID, expected int64, fields Fields) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		NodeID           uuid.UUID `json:"node_id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Fields           Fields    `json:"fields"`
	}{nodeID, expected, fields})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil
}

func validKey(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value
}
