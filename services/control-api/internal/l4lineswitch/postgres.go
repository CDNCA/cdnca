package l4lineswitch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type auditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type PostgresStore struct {
	pool    *pgxpool.Pool
	iam     *iamlock.Authorizer
	auditor auditAppender
}

type PostgresSnapshotResolver struct {
	pool *pgxpool.Pool
	iam  *iamlock.Authorizer
}

type switchDocument struct {
	Value         Switch                  `json:"value"`
	From          Snapshot                `json:"from"`
	To            Snapshot                `json:"to"`
	PrepareNodes  []uuid.UUID             `json:"prepare_nodes"`
	Health        HealthPolicy            `json:"health"`
	Drain         DrainPolicy             `json:"drain"`
	MaxAttempts   uint32                  `json:"max_attempts"`
	Traceparent   string                  `json:"traceparent"`
	DrainCommands map[uuid.UUID]uuid.UUID `json:"drain_commands"`
}

func NewPostgresStore(pool *pgxpool.Pool, iam *iamlock.Authorizer, auditor auditAppender) (*PostgresStore, error) {
	if pool == nil || iam == nil || !iam.Configured() {
		return nil, ErrInvalidInput
	}
	if auditor == nil {
		auditor = audit.New(pool)
	}
	return &PostgresStore{pool: pool, iam: iam, auditor: auditor}, nil
}

func NewPostgresSnapshotResolver(pool *pgxpool.Pool, iam *iamlock.Authorizer) (*PostgresSnapshotResolver, error) {
	if pool == nil || iam == nil || !iam.Configured() {
		return nil, ErrInvalidInput
	}
	return &PostgresSnapshotResolver{pool: pool, iam: iam}, nil
}

func (store *PostgresStore) Claim(ctx context.Context, actor Actor, claim Claim) (Switch, bool, error) {
	if ctx == nil || store == nil || !validActor(actor) || claim.Switch.ID == uuid.Nil ||
		claim.Switch.ConfigurationScopeID == uuid.Nil || !metadataPattern.MatchString(claim.IdempotencyKey) ||
		claim.RequestDigest == ([32]byte{}) {
		return Switch{}, false, ErrInvalidInput
	}
	document, err := encodeSwitch(claim.Switch)
	if err != nil {
		return Switch{}, false, err
	}
	var result Switch
	var replayed bool
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorizeTx(ctx, tx, store.iam, actor, claim.Switch.ConfigurationScopeID, uuid.Nil, PermissionManage); err != nil {
			return err
		}
		lockKey := claim.Switch.ConfigurationScopeID.String() + ":" + claim.IdempotencyKey
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
			return fmt.Errorf("%w: lock idempotency key", ErrPersistence)
		}
		var storedDigest, storedDocument []byte
		err := tx.QueryRow(ctx, `SELECT request_digest,state_document FROM l4_line_switches
			WHERE configuration_scope_id=$1 AND idempotency_key=$2 FOR UPDATE`,
			claim.Switch.ConfigurationScopeID, claim.IdempotencyKey).Scan(&storedDigest, &storedDocument)
		if err == nil {
			if !bytes.Equal(storedDigest, claim.RequestDigest[:]) {
				return ErrIdempotencyConflict
			}
			result, err = decodeSwitch(storedDocument)
			replayed = true
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: read idempotency claim", ErrPersistence)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO l4_line_switches(
			id,configuration_scope_id,idempotency_key,request_digest,state,state_revision,state_document,
			created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)`,
			claim.Switch.ID, claim.Switch.ConfigurationScopeID, claim.IdempotencyKey, claim.RequestDigest[:],
			claim.Switch.State, claim.Switch.StateRevision, document, claim.Switch.CreatedAt); err != nil {
			var databaseError *pgconn.PgError
			if errors.As(err, &databaseError) && databaseError.ConstraintName == "l4_line_switches_one_active_139" {
				return ErrConflict
			}
			return fmt.Errorf("%w: insert switch", ErrPersistence)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO l4_line_switch_workload_grants(
			configuration_scope_id,switch_id,workload_id,created_at) VALUES($1,$2,$3,$4)`,
			claim.Switch.ConfigurationScopeID, claim.Switch.ID, ReconcilerWorkloadID, claim.Switch.CreatedAt); err != nil {
			return fmt.Errorf("%w: create reconciler grant", ErrPersistence)
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: claim.Switch.ConfigurationScopeID, ActorUserID: &actor.UserID,
			Action: "l4_line_switch.create", ResourceType: "l4_line_switch", ResourceID: claim.Switch.ID.String(),
			RequestID: claim.Switch.RequestID.String(), Result: "success", Payload: map[string]any{
				"from_snapshot_id": claim.Switch.From.Reference.ID.String(), "to_snapshot_id": claim.Switch.To.Reference.ID.String(),
				"prepare_node_count": len(claim.Switch.PrepareNodes), "retiring_node_count": len(claim.Switch.RetiringNodes),
			},
		}); err != nil {
			return fmt.Errorf("%w: append create audit", ErrPersistence)
		}
		result = cloneSwitch(claim.Switch)
		return nil
	})
	return result, replayed, err
}

func (store *PostgresStore) Get(ctx context.Context, actor Actor, scopeID, switchID uuid.UUID, permission string) (Switch, error) {
	if ctx == nil || store == nil || !validAuthority(actor) || scopeID == uuid.Nil || switchID == uuid.Nil ||
		(permission != PermissionRead && permission != PermissionManage) {
		return Switch{}, ErrInvalidInput
	}
	var result Switch
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := authorizeTx(ctx, tx, store.iam, actor, scopeID, switchID, permission); err != nil {
			return err
		}
		var document []byte
		if err := tx.QueryRow(ctx, `SELECT state_document FROM l4_line_switches
			WHERE configuration_scope_id=$1 AND id=$2`, scopeID, switchID).Scan(&document); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("%w: get switch", ErrPersistence)
		}
		var err error
		result, err = decodeSwitch(document)
		return err
	})
	return result, err
}

func (store *PostgresStore) Latest(ctx context.Context, actor Actor, scopeID uuid.UUID, permission string) (Switch, error) {
	if ctx == nil || store == nil || !validActor(actor) || scopeID == uuid.Nil ||
		(permission != PermissionRead && permission != PermissionManage) {
		return Switch{}, ErrInvalidInput
	}
	var result Switch
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := authorizeTx(ctx, tx, store.iam, actor, scopeID, uuid.Nil, permission); err != nil {
			return err
		}
		var document []byte
		if err := tx.QueryRow(ctx, `SELECT state_document FROM l4_line_switches
			WHERE configuration_scope_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, scopeID).Scan(&document); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("%w: get latest switch", ErrPersistence)
		}
		var err error
		result, err = decodeSwitch(document)
		return err
	})
	return result, err
}

func (store *PostgresStore) CompareAndSwap(ctx context.Context, actor Actor, before, after Switch) error {
	if ctx == nil || store == nil || !validAuthority(actor) || before.ID == uuid.Nil || before.ID != after.ID ||
		before.ConfigurationScopeID == uuid.Nil || before.ConfigurationScopeID != after.ConfigurationScopeID ||
		after.StateRevision != before.StateRevision+1 || after.UpdatedAt.Before(before.UpdatedAt) {
		return ErrInvalidInput
	}
	document, err := encodeSwitch(after)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorizeTx(ctx, tx, store.iam, actor, before.ConfigurationScopeID, before.ID, PermissionManage); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE l4_line_switches SET state=$1,state_revision=$2,state_document=$3,updated_at=$4
			WHERE configuration_scope_id=$5 AND id=$6 AND state=$7 AND state_revision=$8`,
			after.State, after.StateRevision, document, after.UpdatedAt, before.ConfigurationScopeID,
			before.ID, before.State, before.StateRevision)
		if err != nil {
			return fmt.Errorf("%w: update switch", ErrPersistence)
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: before.ConfigurationScopeID, ActorUserID: auditActorUserID(actor),
			Action: "l4_line_switch.state." + after.State, ResourceType: "l4_line_switch", ResourceID: before.ID.String(),
			RequestID: after.RequestID.String(), Result: "success", Payload: map[string]any{
				"from_state": before.State, "to_state": after.State, "state_revision": after.StateRevision,
				"error_code": after.ErrorCode,
			},
		}); err != nil {
			return fmt.Errorf("%w: append state audit", ErrPersistence)
		}
		return nil
	})
}

func (resolver *PostgresSnapshotResolver) Resolve(ctx context.Context, actor Actor, scopeID uuid.UUID, reference SnapshotReference) (Snapshot, error) {
	if ctx == nil || resolver == nil || !validActor(actor) || scopeID == uuid.Nil || !validSnapshotReference(reference) {
		return Snapshot{}, ErrInvalidInput
	}
	result := Snapshot{Reference: reference}
	err := pgx.BeginTxFunc(ctx, resolver.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := authorizeTx(ctx, tx, resolver.iam, actor, scopeID, uuid.Nil, PermissionRead); err != nil {
			return err
		}
		var digest []byte
		var count int
		if err := tx.QueryRow(ctx, `SELECT node_set_digest,node_count FROM edge_target_snapshots
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 FOR SHARE`, scopeID, reference.ID, reference.Revision).
			Scan(&digest, &count); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("%w: load target snapshot", ErrPersistence)
		}
		if len(digest) != 32 || !bytes.Equal(digest, reference.SHA256[:]) || count < 1 || count > maxSwitchNodes {
			return ErrConflict
		}
		rows, err := tx.Query(ctx, `SELECT node_id FROM edge_target_snapshot_nodes
			WHERE tenant_scope_id=$1 AND snapshot_id=$2 AND snapshot_revision=$3 ORDER BY node_id FOR SHARE`,
			scopeID, reference.ID, reference.Revision)
		if err != nil {
			return fmt.Errorf("%w: load target snapshot nodes", ErrPersistence)
		}
		defer rows.Close()
		for rows.Next() {
			var nodeID uuid.UUID
			if err := rows.Scan(&nodeID); err != nil || nodeID == uuid.Nil {
				return ErrConflict
			}
			result.NodeIDs = append(result.NodeIDs, nodeID)
		}
		if rows.Err() != nil {
			return fmt.Errorf("%w: read target snapshot nodes", ErrPersistence)
		}
		if len(result.NodeIDs) != count || len(slices.Compact(slices.Clone(result.NodeIDs))) != count {
			return ErrConflict
		}
		return nil
	})
	return result, err
}

func (store *PostgresStore) ListActive(ctx context.Context, limit int) ([]ActiveSwitch, error) {
	if ctx == nil || store == nil || limit < 1 || limit > 100 {
		return nil, ErrInvalidInput
	}
	rows, err := store.pool.Query(ctx, `SELECT configuration_scope_id,id FROM l4_line_switches
		WHERE state IN ('preparing','health_gate','draining_old','compensating_old')
		ORDER BY updated_at,configuration_scope_id,id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: list active switches", ErrPersistence)
	}
	defer rows.Close()
	result := make([]ActiveSwitch, 0, limit)
	for rows.Next() {
		var item ActiveSwitch
		if err := rows.Scan(&item.ConfigurationScopeID, &item.SwitchID); err != nil {
			return nil, fmt.Errorf("%w: scan active switch", ErrPersistence)
		}
		result = append(result, item)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("%w: read active switches", ErrPersistence)
	}
	return result, nil
}

func authorizeTx(ctx context.Context, tx pgx.Tx, iam *iamlock.Authorizer, actor Actor, scopeID, switchID uuid.UUID, permission string) error {
	if workloadAuthority(actor) {
		if permission != PermissionManage || switchID == uuid.Nil {
			return ErrPermissionDenied
		}
		if err := iamlock.AcquireShared(ctx, tx); err != nil {
			return fmt.Errorf("%w: lock workload authority", ErrPersistence)
		}
		if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{scopeID}); err != nil {
			return fmt.Errorf("%w: lock workload scope", ErrPersistence)
		}
		var workloadID string
		err := tx.QueryRow(ctx, `SELECT grant.workload_id
			FROM l4_line_switch_workload_grants grant
			JOIN l4_line_switches switch_fact
			  ON switch_fact.configuration_scope_id=grant.configuration_scope_id AND switch_fact.id=grant.switch_id
			WHERE grant.configuration_scope_id=$1 AND grant.switch_id=$2 AND grant.workload_id=$3
			  AND switch_fact.state IN ('preparing','health_gate','draining_old','compensating_old')
			FOR SHARE OF grant,switch_fact`, scopeID, switchID, actor.WorkloadID).Scan(&workloadID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		if err != nil || workloadID != actor.WorkloadID {
			return fmt.Errorf("%w: authorize reconciler workload", ErrPersistence)
		}
		return nil
	}
	authorization, err := iam.AuthorizeSession(ctx, tx, actor.Credential, scopeID, permission)
	if err != nil {
		if errors.Is(err, iamlock.ErrInvalidCredential) {
			return ErrUnauthenticated
		}
		if errors.Is(err, iamlock.ErrPermissionDenied) {
			return ErrPermissionDenied
		}
		return fmt.Errorf("%w: authorize switch", ErrPersistence)
	}
	if authorization.UserID() != actor.UserID || authorization.AuthenticationScopeID() != actor.ScopeID ||
		authorization.CredentialID() != actor.SessionID {
		return ErrUnauthenticated
	}
	return nil
}

func auditActorUserID(actor Actor) *uuid.UUID {
	if !validActor(actor) {
		return nil
	}
	userID := actor.UserID
	return &userID
}

func encodeSwitch(value Switch) ([]byte, error) {
	// The DNS gate is a read-side observation; persisting it would also make
	// the document unreadable to a control plane that predates the field.
	value.DNSGate = nil
	document := switchDocument{Value: value, From: value.From, To: value.To, PrepareNodes: value.PrepareNodes,
		Health: value.Health, Drain: value.Drain, MaxAttempts: value.MaxAttempts, Traceparent: value.Traceparent,
		DrainCommands: value.DrainCommands}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) == 0 || len(encoded) > 8<<20 {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

func decodeSwitch(encoded []byte) (Switch, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document switchDocument
	if err := decoder.Decode(&document); err != nil {
		return Switch{}, fmt.Errorf("%w: decode state document", ErrPersistence)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Switch{}, fmt.Errorf("%w: decode state document", ErrPersistence)
	}
	value := document.Value
	value.From, value.To, value.PrepareNodes = document.From, document.To, document.PrepareNodes
	value.Health, value.Drain, value.MaxAttempts, value.Traceparent = document.Health, document.Drain, document.MaxAttempts, document.Traceparent
	value.DrainCommands = document.DrainCommands
	if value.ID == uuid.Nil || value.ConfigurationScopeID == uuid.Nil || value.StateRevision < 1 || value.State == "" ||
		!validSnapshotReference(value.From.Reference) || !validSnapshotReference(value.To.Reference) {
		return Switch{}, fmt.Errorf("%w: invalid state document", ErrPersistence)
	}
	return cloneSwitch(value), nil
}
