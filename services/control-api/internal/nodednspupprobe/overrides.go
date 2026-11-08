package nodednspupprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ActionOverride audits an override change.
const ActionOverride = "system.probe_dnspup.node_override"

// Override is one node / line group override (node_dnspup_probe_overrides):
// nil fields inherit. A node override wins over its line groups'; of several
// line group overrides the smallest line_group_id applies.
type Override struct {
	ID            uuid.UUID  `json:"id"`
	SubjectKind   string     `json:"subject_kind"` // node / line_group
	NodeID        *uuid.UUID `json:"node_id,omitempty"`
	TenantScopeID *uuid.UUID `json:"tenant_scope_id,omitempty"`
	LineGroupID   *uuid.UUID `json:"line_group_id,omitempty"`
	SubjectName   string     `json:"subject_name"`
	// SubjectDisplayID is the node's or line group's display ID;
	// omitted when the subject no longer exists.
	SubjectDisplayID *int64                 `json:"subject_display_id,omitempty"`
	ProbeType        *string                `json:"probe_type"`
	Selection        *dnspupprobe.Selection `json:"selection"`
	Revision         int64                  `json:"revision"`
}

// readOverrides reads every override (runner and page).
func readOverrides(ctx context.Context, db interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) ([]Override, error) {
	rows, err := db.Query(ctx, `SELECT override.id,override.subject_kind,override.node_id,override.tenant_scope_id,
		override.line_group_id,COALESCE(node.name,line_group.name,''),COALESCE(node.display_id,line_group.display_id),
		override.probe_type,override.selection,override.revision
		FROM node_dnspup_probe_overrides override
		LEFT JOIN nodes node ON node.id=override.node_id
		LEFT JOIN node_line_groups line_group ON line_group.tenant_scope_id=override.tenant_scope_id
		 AND line_group.id=override.line_group_id
		ORDER BY override.subject_kind,override.line_group_id,override.node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Override{}
	for rows.Next() {
		var item Override
		var selection []byte
		if err := rows.Scan(&item.ID, &item.SubjectKind, &item.NodeID, &item.TenantScopeID, &item.LineGroupID,
			&item.SubjectName, &item.SubjectDisplayID, &item.ProbeType, &selection, &item.Revision); err != nil {
			return nil, err
		}
		if selection != nil {
			item.Selection = new(dnspupprobe.Selection)
			if err := json.Unmarshal(selection, item.Selection); err != nil {
				return nil, err
			}
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// Effective is the settings a target is probed with: global, then its
// smallest line group override, then its node override.
func Effective(global Settings, overrides []Override, nodeID uuid.UUID, groups []uuid.UUID) (Settings, string) {
	value, source := global, "global"
	apply := func(item Override) {
		if item.ProbeType != nil {
			value.ProbeType = *item.ProbeType
		}
		if item.Selection != nil {
			value.Selection = item.Selection
		}
	}
	sorted := slices.Clone(groups)
	slices.SortFunc(sorted, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
	found := false
	for _, group := range sorted {
		for _, item := range overrides {
			if !found && item.SubjectKind == "line_group" && item.LineGroupID != nil && *item.LineGroupID == group {
				apply(item)
				source, found = "line_group:"+group.String(), true
			}
		}
	}
	for _, item := range overrides {
		if item.SubjectKind == "node" && item.NodeID != nil && *item.NodeID == nodeID {
			apply(item)
			source = "node"
		}
	}
	return value, source
}

// Overrides serves GET /v1/admin/probe-dnspup/node-monitoring/overrides.
func (store *Store) Overrides(ctx context.Context, actor Actor) (any, error) {
	var items []Override
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, store.clock()); err != nil {
			return err
		}
		var err error
		items, err = readOverrides(ctx, tx)
		return err
	})
	return map[string]any{"items": items}, err
}

// PutOverride serves PUT …/overrides: creates or replaces the override of
// one node ({"node_id"}) or line group ({"tenant_scope_id","line_group_id"}).
func (store *Store) PutOverride(ctx context.Context, actor Actor, key string, body []byte) (any, error) {
	var input struct {
		NodeID        *uuid.UUID             `json:"node_id"`
		TenantScopeID *uuid.UUID             `json:"tenant_scope_id"`
		LineGroupID   *uuid.UUID             `json:"line_group_id"`
		ProbeType     *string                `json:"probe_type"`
		Selection     *dnspupprobe.Selection `json:"selection"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || !validKey(key) ||
		(input.NodeID == nil) == (input.LineGroupID == nil) || (input.LineGroupID == nil) != (input.TenantScopeID == nil) ||
		input.ProbeType == nil && input.Selection == nil ||
		input.ProbeType != nil && !slices.Contains([]string{ProbeTCPing, ProbePing, ProbeHTTP}, *input.ProbeType) ||
		input.Selection != nil && input.Selection.Validate() != nil {
		return nil, ErrInvalidSettings
	}
	digest := sha256.Sum256(append([]byte("override\x00"), body...))
	now := store.clock()
	var result []byte
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, now); err != nil {
			return err
		}
		stored, found, err := replayWrite(ctx, tx, actor, key, digest)
		if err != nil || found {
			result = stored
			return err
		}
		kind, exists := "node", false
		if input.NodeID != nil {
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1)`, *input.NodeID).Scan(&exists)
		} else {
			kind = "line_group"
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_line_groups WHERE tenant_scope_id=$1 AND id=$2
				AND deleted_at IS NULL)`, *input.TenantScopeID, *input.LineGroupID).Scan(&exists)
		}
		if err != nil {
			return err
		}
		if !exists {
			return ErrInvalidSettings
		}
		var selection []byte
		if input.Selection != nil {
			selection, _ = json.Marshal(input.Selection)
		}
		var id uuid.UUID
		if kind == "node" {
			err = tx.QueryRow(ctx, `INSERT INTO node_dnspup_probe_overrides(id,subject_kind,node_id,probe_type,selection,
				updated_by_user_id,updated_at) VALUES($1,'node',$2,$3,$4,$5,$6)
				ON CONFLICT (node_id) WHERE subject_kind='node' DO UPDATE SET probe_type=EXCLUDED.probe_type,
				selection=EXCLUDED.selection,revision=node_dnspup_probe_overrides.revision+1,
				updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at RETURNING id`,
				uuid.New(), *input.NodeID, input.ProbeType, selection, actor.UserID, now).Scan(&id)
		} else {
			err = tx.QueryRow(ctx, `INSERT INTO node_dnspup_probe_overrides(id,subject_kind,tenant_scope_id,line_group_id,
				probe_type,selection,updated_by_user_id,updated_at) VALUES($1,'line_group',$2,$3,$4,$5,$6,$7)
				ON CONFLICT (tenant_scope_id,line_group_id) WHERE subject_kind='line_group' DO UPDATE SET
				probe_type=EXCLUDED.probe_type,selection=EXCLUDED.selection,revision=node_dnspup_probe_overrides.revision+1,
				updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at RETURNING id`,
				uuid.New(), *input.TenantScopeID, *input.LineGroupID, input.ProbeType, selection, actor.UserID, now).Scan(&id)
		}
		if err != nil {
			return err
		}
		items, err := readOverrides(ctx, tx)
		if err != nil {
			return err
		}
		var saved Override
		for _, item := range items {
			if item.ID == id {
				saved = item
			}
		}
		if err := store.auditOverride(ctx, tx, actor, "success", map[string]any{"override_id": id.String(),
			"subject_kind": kind, "probe_type": input.ProbeType, "selection": input.Selection}); err != nil {
			return err
		}
		if result, err = json.Marshal(saved); err != nil {
			return err
		}
		return recordOverrideWrite(ctx, tx, actor, key, digest, result, now)
	})
	if err != nil {
		return nil, err
	}
	var saved Override
	return saved, json.Unmarshal(result, &saved)
}

// DeleteOverride serves DELETE …/overrides/{id} (idempotent per key).
func (store *Store) DeleteOverride(ctx context.Context, actor Actor, key string, id uuid.UUID) error {
	if !validKey(key) {
		return ErrInvalidSettings
	}
	digest := sha256.Sum256(append([]byte("override-delete\x00"), id[:]...))
	now := store.clock()
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, now); err != nil {
			return err
		}
		if _, found, err := replayWrite(ctx, tx, actor, key, digest); err != nil || found {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM node_dnspup_probe_overrides WHERE id=$1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return dnspupprobe.ErrRequestNotFound
		}
		if err := store.auditOverride(ctx, tx, actor, "success", map[string]any{"override_id": id.String(),
			"deleted": true}); err != nil {
			return err
		}
		return recordOverrideWrite(ctx, tx, actor, key, digest, []byte("{}"), now)
	})
}

func (store *Store) auditOverride(ctx context.Context, tx pgx.Tx, actor Actor, result string, payload map[string]any) error {
	payload["ip"] = actor.IP
	return store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
		Action: ActionOverride, ResourceType: "probe_dnspup", ResourceID: "probe_dnspup",
		RequestID: ActionOverride + "." + uuid.NewString(), Result: result, Payload: payload})
}

func replayWrite(ctx context.Context, tx pgx.Tx, actor Actor, key string, digest [32]byte) ([]byte, bool, error) {
	var storedDigest, body []byte
	err := tx.QueryRow(ctx, `SELECT request_digest_sha256,response_body FROM probe_dnspup_write_requests
		WHERE actor_session_id=$1 AND idempotency_key=$2`, actor.SessionID, key).Scan(&storedDigest, &body)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	case !bytes.Equal(storedDigest, digest[:]):
		return nil, false, ErrIdempotency
	}
	return body, true, nil
}

func recordOverrideWrite(ctx context.Context, tx pgx.Tx, actor Actor, key string, digest [32]byte, body []byte, now any) error {
	_, err := tx.Exec(ctx, `INSERT INTO probe_dnspup_write_requests(actor_session_id,idempotency_key,operation,
		request_digest_sha256,response_body,created_at) VALUES($1,$2,'overrides',$3,$4,$5)`,
		actor.SessionID, key, digest[:], body, now)
	return err
}
