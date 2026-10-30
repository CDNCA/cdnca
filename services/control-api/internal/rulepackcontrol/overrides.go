package rulepackcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PutOverride sets the enablement row of a pack (or one exported rule) at a
// level. A row is accepted only where the levels above allow adjustment
// (ErrLocked otherwise). State inherit with no allow_lower / priority /
// params (and every rule-level inherit) removes the row. Conflicts are not
// checked here: they block publication, and the remedy is to switch one side
// off, which must always be possible.
func (s *Service) PutOverride(ctx context.Context, actor Actor, input OverrideInput) (Override, bool, error) {
	record := auditRecord{scopeID: actor.ScopeID, resourceType: "rule_pack_override",
		resourceID: overrideResourceID(input), payload: map[string]any{"pack_id": input.PackID, "rule_id": input.RuleID,
			"level": string(input.Level), "level_object_id": input.LevelObjectID,
			"requested": map[string]any{"state": string(input.State), "allow_lower": input.AllowLower,
				"priority": input.Priority, "params": rawParams(input.Params)}}}
	saved, kept, err := s.putOverride(ctx, actor, input, &record)
	if err != nil {
		return Override{}, false, s.auditDenied(ctx, actor, AuditOverridePut, record, err)
	}
	return saved, kept, nil
}

// overrideResourceID names the row: <level>[:<object>]/<pack>[#<rule>].
func overrideResourceID(input OverrideInput) string {
	id := string(input.Level)
	if input.LevelObjectID != nil {
		id += ":" + input.LevelObjectID.String()
	}
	id += "/" + input.PackID
	if input.RuleID != "" {
		id += "#" + input.RuleID
	}
	return id
}

func (s *Service) putOverride(ctx context.Context, actor Actor, input OverrideInput, record *auditRecord) (Override, bool, error) {
	if input.State != rulepack.StateInherit && input.State != rulepack.StateEnabled && input.State != rulepack.StateDisabled ||
		input.Priority != nil && (*input.Priority < 0 || *input.Priority > rulepack.MaxPriority) {
		return Override{}, false, ErrInvalidInput
	}
	var params rulepack.Params
	if len(input.Params) != 0 && !bytes.Equal(bytes.TrimSpace(input.Params), []byte("null")) {
		if err := json.Unmarshal(input.Params, &params); err != nil || params == nil {
			return Override{}, false, fmt.Errorf("%w: params must be an object", ErrInvalidInput)
		}
	}
	ruleLevel := input.RuleID != ""
	if ruleLevel && (input.AllowLower || input.Priority != nil || len(params) != 0) {
		return Override{}, false, fmt.Errorf("%w: a rule-level row only has a state", ErrInvalidInput)
	}
	remove := input.State == rulepack.StateInherit &&
		(ruleLevel || !input.AllowLower && input.Priority == nil && len(params) == 0)
	var saved Override
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		subject, ref, err := subjectFor(ctx, tx, actor, LevelInput{Level: input.Level, ObjectID: input.LevelObjectID})
		if err != nil {
			return err
		}
		if subject.TenantScopeID != "" {
			// Tenant / site rows are recorded in the tenant's stream.
			record.scopeID = uuid.MustParse(subject.TenantScopeID)
		}
		if _, err := lockPack(ctx, tx, input.PackID); err != nil {
			return err
		}
		packs, err := loadPacks(ctx, tx, input.PackID)
		if err != nil {
			return err
		}
		if len(packs) != 1 || packs[0].compiled == nil {
			return fmt.Errorf("%w: pack has no downloaded current version", ErrInvalidInput)
		}
		compiled := packs[0].compiled
		if ruleLevel && !compiled.Pack.Exported(input.RuleID) {
			return fmt.Errorf("%w: rule %s is not exported by %s %s", ErrInvalidInput, input.RuleID,
				input.PackID, compiled.Pack.Version)
		}
		if len(params) != 0 {
			merged, err := rulepack.MergeParams(compiled.Pack, params, nil)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidInput, err)
			}
			for name := range params {
				params[name] = merged[name]
			}
		}
		overrides, err := loadOverrides(ctx, tx, subject, input.PackID)
		if err != nil {
			return err
		}
		effects := rulepack.Effective([]*rulepack.CompiledPack{compiled}, toLibOverrides(overrides), subject)
		if len(effects) != 1 {
			return ErrNotFound
		}
		adjustable := false
		for _, candidate := range effects[0].Adjustable {
			adjustable = adjustable || candidate == ref
		}
		if !adjustable {
			return ErrLocked
		}
		var ruleID *string
		if ruleLevel {
			ruleID = &input.RuleID
		}
		var id uuid.UUID
		var before Override
		var beforeParams []byte
		err = tx.QueryRow(ctx, `SELECT id, state, allow_lower, priority, params FROM rule_pack_enablements WHERE level=$1 AND
			level_object_id IS NOT DISTINCT FROM $2 AND pack_id=$3 AND rule_id IS NOT DISTINCT FROM $4 FOR UPDATE`,
			input.Level, input.LevelObjectID, input.PackID, ruleID).Scan(&id, &before.State, &before.AllowLower,
			&before.Priority, &beforeParams)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		exists := err == nil
		if !exists {
			before.State = rulepack.StateInherit
		}
		if beforeParams != nil {
			if err := json.Unmarshal(beforeParams, &before.Params); err != nil {
				return err
			}
		}
		record.payload["version"] = compiled.Pack.Version
		record.payload["row_existed"] = exists
		after := Override{State: input.State, AllowLower: input.AllowLower, Priority: input.Priority, Params: params}
		if remove {
			after = Override{State: rulepack.StateInherit}
		}
		record.changes = overrideChanges(before, after)
		record.payload["row_removed"] = remove
		if remove {
			if exists {
				if _, err := tx.Exec(ctx, `DELETE FROM rule_pack_enablements WHERE id=$1`, id); err != nil {
					return err
				}
			}
			return s.appendAudit(ctx, tx, actor, AuditOverridePut, *record, nil)
		}
		var encoded []byte
		if len(params) != 0 {
			encoded, _ = json.Marshal(params)
		}
		now := s.now()
		if exists {
			_, err = tx.Exec(ctx, `UPDATE rule_pack_enablements SET state=$2, allow_lower=$3, priority=$4, params=$5,
				updated_by_user_id=$6, updated_at=$7 WHERE id=$1`, id, input.State, input.AllowLower, input.Priority,
				encoded, actor.UserID, now)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO rule_pack_enablements(id,level,level_object_id,pack_id,rule_id,state,
				allow_lower,priority,params,updated_by_user_id,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
				uuid.New(), input.Level, input.LevelObjectID, input.PackID, ruleID, input.State, input.AllowLower,
				input.Priority, encoded, actor.UserID, now)
		}
		if err != nil {
			return err
		}
		saved = Override{Level: input.Level, LevelObjectID: input.LevelObjectID, PackID: input.PackID, RuleID: input.RuleID,
			State: input.State, AllowLower: input.AllowLower, Priority: input.Priority, Params: params,
			UpdatedBy: &actor.UserID, UpdatedAt: now}
		return s.appendAudit(ctx, tx, actor, AuditOverridePut, *record, nil)
	})
	if err != nil {
		return Override{}, false, err
	}
	return saved, !remove, nil
}

// overrideChanges is the before -> after of the row's fields that changed
// (a missing row is state inherit with nothing else set).
func overrideChanges(before, after Override) map[string]any {
	changes := map[string]any{}
	if before.State != after.State {
		changes["state"] = change(string(before.State), string(after.State))
	}
	if before.AllowLower != after.AllowLower {
		changes["allow_lower"] = change(before.AllowLower, after.AllowLower)
	}
	if !sameJSON(before.Priority, after.Priority) {
		changes["priority"] = change(before.Priority, after.Priority)
	}
	if len(before.Params) != 0 || len(after.Params) != 0 {
		if !sameJSON(before.Params, after.Params) {
			changes["params"] = change(paramsValue(before.Params), paramsValue(after.Params))
		}
	}
	return changes
}

func paramsValue(params rulepack.Params) any {
	if len(params) == 0 {
		return nil
	}
	return params
}

// rawParams is the requested params as the audit payload keeps them: the
// JSON value when it is valid JSON, its text otherwise.
func rawParams(raw json.RawMessage) any {
	trimmed := bytes.TrimSpace(raw)
	switch {
	case len(trimmed) == 0:
		return nil
	case json.Valid(trimmed):
		return json.RawMessage(trimmed)
	}
	return string(trimmed)
}
