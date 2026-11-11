package securitypolicy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// String set conditions: "<field> in_string_set <id>" /
// not_in_string_set on host, path, request_uri, user_agent, referer, header
// (key = header name) or ja4; one set ID per condition, at most
// edgeconfig.MaxWAFStringSetsPerRule per rule.
var stringSetOperators = []string{"in_string_set", "not_in_string_set"}

// IsStringSetCondition reports whether condition references a string set.
func IsStringSetCondition(condition Condition) bool {
	return slices.Contains(stringSetOperators, condition.Operator)
}

var (
	// ErrStringSetUnavailable: a string set condition names a set that does
	// not exist, was deleted, or belongs to another tenant.
	ErrStringSetUnavailable = errors.New("security policy references an unavailable string set")
	// ErrStringSetTargetMismatch: a ja4 condition names a set that is not
	// exact, case sensitive JA4 fingerprints (edgeconfig.StringSetTargetAccepts).
	ErrStringSetTargetMismatch = errors.New("security policy string set does not fit the condition field")
)

// ResolvedStringSets are the current contents of the string sets bound
// policies reference, keyed by set ID.
type ResolvedStringSets map[uuid.UUID]edgeconfig.WAFStringSet

// Condition is the node reference of one string set condition; false when
// the set is not resolved or does not fit the field.
func (sets ResolvedStringSets) Condition(condition Condition) (edgeconfig.WAFStringSetRef, bool) {
	if !IsStringSetCondition(condition) || len(condition.Values) != 1 ||
		!slices.Contains(edgeconfig.StringSetTargets, condition.Field) {
		return edgeconfig.WAFStringSetRef{}, false
	}
	id, err := uuid.Parse(condition.Values[0])
	if err != nil {
		return edgeconfig.WAFStringSetRef{}, false
	}
	set, ok := sets[id]
	if !ok || !edgeconfig.StringSetTargetAccepts(condition.Field, set) {
		return edgeconfig.WAFStringSetRef{}, false
	}
	ref := edgeconfig.WAFStringSetRef{SetID: set.ID, Revision: set.Revision, Target: condition.Field,
		Negate: condition.Operator == "not_in_string_set"}
	if condition.Field == edgeconfig.StringSetTargetHeader {
		ref.Key = condition.Key
	}
	return ref, true
}

// StringSetReferences are the set IDs the rules' string set conditions
// name, in order of first appearance.
func StringSetReferences(rules []Rule) []uuid.UUID {
	var ids []uuid.UUID
	for _, rule := range rules {
		for _, condition := range rule.Conditions {
			if !IsStringSetCondition(condition) || len(condition.Values) != 1 {
				continue
			}
			if id, err := uuid.Parse(condition.Values[0]); err == nil && !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// LoadStringSetsTx resolves ids for the tenant scope scopeID: live sets the
// scope owns, or platform sets, at their current revision. A set that is not
// usable is absent. lock takes FOR SHARE (a policy save: a concurrent
// delete or edit waits for it).
func LoadStringSetsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, ids []uuid.UUID, lock bool) (ResolvedStringSets, error) {
	result := ResolvedStringSets{}
	if len(ids) == 0 {
		return result, nil
	}
	query := `SELECT s.id,s.revision,s.match_mode,s.case_sensitive,s.entries FROM security_string_sets s
		JOIN access_scopes owner ON owner.id=s.owner_scope_id
		WHERE s.id=ANY($1::uuid[]) AND s.deleted_at IS NULL AND (s.owner_scope_id=$2 OR owner.kind='platform')`
	if lock {
		query += ` FOR SHARE OF s`
	}
	rows, err := tx.Query(ctx, query, ids, scopeID)
	if err != nil {
		return nil, fmt.Errorf("read string sets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		set := edgeconfig.WAFStringSet{}
		if err := rows.Scan(&id, &set.Revision, &set.Mode, &set.CaseSensitive, &set.Members); err != nil {
			return nil, fmt.Errorf("scan string set: %w", err)
		}
		set.ID = id.String()
		result[id] = set
	}
	return result, rows.Err()
}

// requireUsableStringSets checks that every set the rules reference is a
// live set of the policy's scope or a platform set, and fits its field.
func requireUsableStringSets(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, rules []Rule) error {
	ids := StringSetReferences(rules)
	if len(ids) == 0 {
		return nil
	}
	sets, err := LoadStringSetsTx(ctx, tx, scopeID, ids, true)
	if err != nil {
		return err
	}
	if len(sets) != len(ids) {
		return ErrStringSetUnavailable
	}
	for _, rule := range rules {
		for _, condition := range rule.Conditions {
			if !IsStringSetCondition(condition) {
				continue
			}
			if _, ok := sets.Condition(condition); !ok {
				return ErrStringSetTargetMismatch
			}
		}
	}
	return nil
}

// requireUsableReferences checks the IP lists and string sets the rules name.
func requireUsableReferences(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, rules []Rule) error {
	if err := requireUsableIPLists(ctx, tx, scopeID, rules); err != nil {
		return err
	}
	return requireUsableStringSets(ctx, tx, scopeID, rules)
}
