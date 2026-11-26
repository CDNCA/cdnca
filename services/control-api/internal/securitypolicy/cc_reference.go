package securitypolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CCReference makes a CC rule of a CC matcher and one or two CC filters of
// the policy's scope. Saves expand it into
// the rule's conditions, action and action config, the same way
// ExpandCCRuleGroup expands catalog rule groups: the nodes only see the
// expanded rule. Versions (set by the server) are the revisions last
// expanded into a change; an edit leaving the expansion equal keeps them.
type CCReference struct {
	MatcherID      uuid.UUID  `json:"matcher_id"`
	MatcherVersion int64      `json:"matcher_version,omitempty"`
	Filter1ID      uuid.UUID  `json:"filter1_id"`
	Filter1Version int64      `json:"filter1_version,omitempty"`
	Filter2ID      *uuid.UUID `json:"filter2_id,omitempty"`
	Filter2Version int64      `json:"filter2_version,omitempty"`
	// Action: block (拦截) or log (仅记录); the rule's flow is the match mode.
	Action string `json:"action"`
}

// Field error reasons of a reference: unavailable (not a live, enabled,
// user-made matcher / filter of the policy's scope), unsupported (the node
// cannot run it).
const (
	CCReferenceUnavailable = "unavailable"
	CCReferenceUnsupported = "unsupported"
)

// ErrCCReferenceRejected: a CC policy that uses an edited matcher / filter
// cannot run its new content; the edit is refused (CCReferenceRejectedError).
var ErrCCReferenceRejected = errors.New("a CC policy using the CC matcher or filter cannot run its new content")

// CCReferenceUser is a live CC policy whose rules use a matcher / filter.
type CCReferenceUser struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// CCReferenceRejectedError names the policy and the refusal reason.
type CCReferenceRejectedError struct {
	Policy CCReferenceUser
	Reason string
}

func (e *CCReferenceRejectedError) Error() string {
	return fmt.Sprintf("%s: policy %s (%s)", ErrCCReferenceRejected, e.Policy.ID, e.Reason)
}

func (e *CCReferenceRejectedError) Unwrap() error { return ErrCCReferenceRejected }

// ccReferenceFilterTypes maps the user CC filter types (过滤器 form) to the
// catalog filter types whose semantics they take (applyCCFilter).
var ccReferenceFilterTypes = map[string]string{
	"req_rate": "req_rate", "browser_verify_auto": "browser_verify_auto", "five_second": "delay_jump_filter",
	"click": "click_filter", "simple_click": "easy_click_filter", "slider": "slide_filter",
	"simple_slider": "easy_slide_filter", "captcha": "captcha_filter", "rotate_image": "rotate_filter",
	"302_challenge": "302_challenge",
}

type ccReferenceRow struct {
	Revision   int64
	Name       string
	Field      string
	Operator   string
	Key        string
	Values     []string
	Type       string
	Parameters []byte
}

type ccReferenceRows struct {
	matchers map[uuid.UUID]ccReferenceRow
	filters  map[uuid.UUID]ccReferenceRow
}

func hasCCReferences(rules []Rule) bool {
	return slices.ContainsFunc(rules, func(rule Rule) bool { return rule.CCReference != nil })
}

// ccReferenceIDs are the matcher and filter IDs the rules use.
func ccReferenceIDs(rules []Rule) (matchers, filters []uuid.UUID) {
	add := func(ids []uuid.UUID, id uuid.UUID) []uuid.UUID {
		if id == uuid.Nil || slices.Contains(ids, id) {
			return ids
		}
		return append(ids, id)
	}
	for _, rule := range rules {
		if ref := rule.CCReference; ref != nil {
			matchers = add(matchers, ref.MatcherID)
			filters = add(filters, ref.Filter1ID)
			if ref.Filter2ID != nil {
				filters = add(filters, *ref.Filter2ID)
			}
		}
	}
	return matchers, filters
}

type ccReferenceQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// loadCCReferences reads the matchers and filters the rules use that are
// usable in scopeID: live, enabled, user-made rows of that scope. lock takes
// FOR SHARE (a policy save: a concurrent edit, disable or delete waits).
func loadCCReferences(ctx context.Context, db ccReferenceQuerier, scopeID uuid.UUID, rules []Rule, lock bool) (ccReferenceRows, error) {
	result := ccReferenceRows{matchers: map[uuid.UUID]ccReferenceRow{}, filters: map[uuid.UUID]ccReferenceRow{}}
	matcherIDs, filterIDs := ccReferenceIDs(rules)
	suffix := ""
	if lock {
		suffix = " ORDER BY id FOR SHARE"
	}
	read := func(query string, ids []uuid.UUID, into map[uuid.UUID]ccReferenceRow, matcher bool) error {
		if len(ids) == 0 {
			return nil
		}
		rows, err := db.Query(ctx, query+suffix, ids, scopeID)
		if err != nil {
			return fmt.Errorf("read CC references: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var row ccReferenceRow
			var values []byte
			if matcher {
				err = rows.Scan(&id, &row.Revision, &row.Name, &row.Field, &row.Operator, &row.Key, &values)
			} else {
				err = rows.Scan(&id, &row.Revision, &row.Name, &row.Type, &row.Parameters)
			}
			if err != nil {
				return fmt.Errorf("scan CC reference: %w", err)
			}
			if len(values) > 0 {
				if err := json.Unmarshal(values, &row.Values); err != nil {
					return fmt.Errorf("decode CC matcher values: %w", err)
				}
			}
			into[id] = row
		}
		return rows.Err()
	}
	const usable = ` WHERE id=ANY($1::uuid[]) AND scope_id=$2 AND deleted_at IS NULL AND enabled AND NOT system_rule`
	if err := read(`SELECT id,revision,name,COALESCE(field,''),COALESCE(operator,''),COALESCE(condition_key,''),values
		FROM cc_reference_matchers`+usable, matcherIDs, result.matchers, true); err != nil {
		return ccReferenceRows{}, err
	}
	if err := read(`SELECT id,revision,name,COALESCE(filter_type,''),parameters FROM cc_reference_filters`+usable,
		filterIDs, result.filters, false); err != nil {
		return ccReferenceRows{}, err
	}
	return result, nil
}

// ccReferenceFilter is the catalog form of a user filter: the type its
// semantics follow, its counts, and its enforcement params (the type's
// catalog defaults with the filter's own params on top). false: the node
// cannot run it (url_auth, an old projected type, a bad parameter).
func ccReferenceFilter(row ccReferenceRow) (rulecatalog.CCFilterBody, rulecatalog.CCFilterParams, bool) {
	catalogType, ok := ccReferenceFilterTypes[row.Type]
	params, known := legacyCCFilterParams[catalogType]
	if !ok || !known {
		return rulecatalog.CCFilterBody{}, rulecatalog.CCFilterParams{}, false
	}
	raw := map[string]json.RawMessage{}
	if len(row.Parameters) > 0 {
		if err := json.Unmarshal(row.Parameters, &raw); err != nil {
			return rulecatalog.CCFilterBody{}, rulecatalog.CCFilterParams{}, false
		}
	}
	body := rulecatalog.CCFilterBody{Type: catalogType}
	for key, into := range map[string]*int{"within_second": &body.WithinSecond, "max_req": &body.MaxReq,
		"max_req_per_uri": &body.MaxReqPerURI} {
		value, present := raw[key]
		if !present {
			continue
		}
		delete(raw, key)
		if err := json.Unmarshal(value, into); err != nil || *into < 0 {
			return rulecatalog.CCFilterBody{}, rulecatalog.CCFilterParams{}, false
		}
	}
	if len(raw) > 0 {
		rest, err := json.Marshal(raw)
		if err != nil {
			return rulecatalog.CCFilterBody{}, rulecatalog.CCFilterParams{}, false
		}
		decoder := json.NewDecoder(bytes.NewReader(rest))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&params); err != nil {
			return rulecatalog.CCFilterBody{}, rulecatalog.CCFilterParams{}, false
		}
	}
	if !rulecatalog.ValidCCFilterParams(catalogType, params) {
		return rulecatalog.CCFilterBody{}, rulecatalog.CCFilterParams{}, false
	}
	return body, params, true
}

// expandCCReferences replaces every reference rule of rules (as sent: rule
// n is rules[n]) with its expansion from rows. A matcher becomes the rule's
// one condition; filter 1 (or the filter 1 → filter 2 pair) its action, as
// applyCCFilter. The rule's own count_by / action_target are dropped (a
// filter counts per client); the versions become the revisions used.
func expandCCReferences(kind string, rules []Rule, rows ccReferenceRows) error {
	for index := range rules {
		ref := rules[index].CCReference
		if ref == nil {
			continue
		}
		path := indexed("rules", index) + ".cc_reference"
		switch {
		case strings.TrimSpace(kind) != KindCC:
			return refuse(path, fielderr.Invalid)
		case ref.Action != ActionBlock && ref.Action != ActionLog:
			return refuse(path+".action", fielderr.Invalid)
		case ref.MatcherID == uuid.Nil:
			return refuse(path+".matcher_id", fielderr.Required)
		case ref.Filter1ID == uuid.Nil:
			return refuse(path+".filter1_id", fielderr.Required)
		case ref.Filter2ID != nil && (*ref.Filter2ID == uuid.Nil || *ref.Filter2ID == ref.Filter1ID):
			return refuse(path+".filter2_id", fielderr.Duplicate)
		}
		matcher, ok := rows.matchers[ref.MatcherID]
		if !ok {
			return refuse(path+".matcher_id", CCReferenceUnavailable)
		}
		condition := Condition{Field: matcher.Field, Operator: matcher.Operator, Key: matcher.Key,
			Values: slices.Clone(matcher.Values)}
		if !runtimeConditionSupported(KindCC, condition) {
			return refuse(path+".matcher_id", CCReferenceUnsupported)
		}
		first, ok := rows.filters[ref.Filter1ID]
		if !ok {
			return refuse(path+".filter1_id", CCReferenceUnavailable)
		}
		config, params, ok := ccReferenceFilter(first)
		if !ok {
			return refuse(path+".filter1_id", CCReferenceUnsupported)
		}
		next := *ref
		next.MatcherVersion, next.Filter1Version, next.Filter2Version = matcher.Revision, first.Revision, 0
		var trigger *rulecatalog.CCFilterBody
		if ref.Filter2ID != nil {
			second, ok := rows.filters[*ref.Filter2ID]
			if !ok {
				return refuse(path+".filter2_id", CCReferenceUnavailable)
			}
			secondConfig, secondParams, ok := ccReferenceFilter(second)
			if !ok || !validCCFilterPair(config, secondConfig) {
				return refuse(path+".filter2_id", CCReferenceUnsupported)
			}
			rate := config
			trigger = &rate
			config, params, next.Filter2Version = secondConfig, secondParams, second.Revision
		}
		rule := rules[index]
		rule.Conditions, rule.CountBy, rule.ActionTarget = []Condition{condition}, nil, ""
		if err := applyCCFilter(&rule, config, params, ref.Action, trigger, nil); err != nil {
			return refuse(path+".filter1_id", CCReferenceUnsupported)
		}
		rule.CCReference = &next
		rules[index] = rule
	}
	return nil
}

var ruleFieldPattern = regexp.MustCompile(`^rules\[(\d+)\]\.(.+)$`)

// locateCCReferenceError moves a refusal of what a reference rule expanded
// to (rules[n].conditions... / action...) onto the reference the client
// chose: the matcher for conditions, filter 1 for the rest. referenced holds
// the indexes (as sent) of the reference rules.
func locateCCReferenceError(err error, referenced map[int]bool) error {
	located, ok := fielderr.As(err)
	if !ok || len(referenced) == 0 {
		return err
	}
	match := ruleFieldPattern.FindStringSubmatch(located.Field)
	if match == nil {
		return err
	}
	index, convErr := strconv.Atoi(match[1])
	if convErr != nil || !referenced[index] {
		return err
	}
	rest := match[2]
	for _, own := range []string{"name", "priority", "enabled", "flow", "comment", "expires_at", "cc_reference"} {
		if rest == own || strings.HasPrefix(rest, own+".") {
			return err
		}
	}
	target := "filter1_id"
	if strings.HasPrefix(rest, "conditions") {
		target = "matcher_id"
	}
	return refuse(indexed("rules", index)+".cc_reference."+target, located.Reason)
}

func ccReferenceIndexes(rules []Rule) map[int]bool {
	indexes := map[int]bool{}
	for index, rule := range rules {
		if rule.CCReference != nil {
			indexes[index] = true
		}
	}
	return indexes
}

// resolveCCReferences expands the reference rules of fields for a policy of
// scopeID (before the rules are checked, so the expansion is checked as
// written inline).
func (s *Service) resolveCCReferences(ctx context.Context, scopeID uuid.UUID, fields *PolicyFields) error {
	if !hasCCReferences(fields.Rules) {
		return nil
	}
	if strings.TrimSpace(fields.Kind) != KindCC {
		return expandCCReferences(fields.Kind, fields.Rules, ccReferenceRows{})
	}
	rows, err := loadCCReferences(ctx, s.store.pool, scopeID, fields.Rules, false)
	if err != nil {
		return err
	}
	return expandCCReferences(fields.Kind, fields.Rules, rows)
}

// requireUsableCCReferences locks (FOR SHARE) the matchers and filters the
// rules use and checks each is still usable at the version expanded; an
// edit since is a revision conflict.
func requireUsableCCReferences(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, rules []Rule) error {
	if !hasCCReferences(rules) {
		return nil
	}
	rows, err := loadCCReferences(ctx, tx, scopeID, rules, true)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		ref := rule.CCReference
		if ref == nil {
			continue
		}
		matcher, matcherOK := rows.matchers[ref.MatcherID]
		first, firstOK := rows.filters[ref.Filter1ID]
		if !matcherOK || !firstOK {
			return ErrRevisionConflict
		}
		if matcher.Revision != ref.MatcherVersion || first.Revision != ref.Filter1Version {
			return ErrRevisionConflict
		}
		if ref.Filter2ID != nil {
			if second, ok := rows.filters[*ref.Filter2ID]; !ok || second.Revision != ref.Filter2Version {
				return ErrRevisionConflict
			}
		}
	}
	return nil
}

// ccReferenceUsesQuery selects the live CC policies of scope $1 whose rules
// use the matcher / filter of $2 (and $3: filter 2).
const ccReferenceUsesQuery = ` FROM security_policies WHERE scope_id=$1 AND kind='cc' AND deleted_at IS NULL
	AND (rules @> $2::jsonb OR rules @> $3::jsonb)`

func ccReferenceUseArgs(scopeID uuid.UUID, kind string, id uuid.UUID) ([]any, error) {
	keys := []string{"matcher_id", "matcher_id"}
	if kind == "filter" {
		keys = []string{"filter1_id", "filter2_id"}
	}
	args := []any{scopeID}
	for _, key := range keys {
		document, err := json.Marshal([]map[string]map[string]string{{"cc_reference": {key: id.String()}}})
		if err != nil {
			return nil, err
		}
		args = append(args, document)
	}
	return args, nil
}

// CCReferenceUsersTx lists the live CC policies of scopeID whose rules use
// the matcher (kind "matcher") or filter ("filter") id: a matcher or filter
// in use cannot be deleted or disabled.
func CCReferenceUsersTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, kind string, id uuid.UUID) ([]CCReferenceUser, error) {
	args, err := ccReferenceUseArgs(scopeID, kind, id)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT id,name`+ccReferenceUsesQuery+` ORDER BY name,id`, args...)
	if err != nil {
		return nil, fmt.Errorf("list CC reference users: %w", err)
	}
	users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (CCReferenceUser, error) {
		var user CCReferenceUser
		return user, row.Scan(&user.ID, &user.Name)
	})
	if err != nil {
		return nil, fmt.Errorf("list CC reference users: %w", err)
	}
	return users, nil
}

// ReexpandCCReferencesTx re-expands, in tx, the reference rules of every
// live CC policy of scopeID using the matcher / filter id whose content an
// edit just changed. A policy whose expansion changes gets a new revision,
// version (by actor) and audit event; the rebind worker then publishes it
// to its sites as after a policy edit. A policy that cannot run the new
// content fails the whole edit (CCReferenceRejectedError).
func (s *Store) ReexpandCCReferencesTx(ctx context.Context, tx pgx.Tx, actor Actor, scopeID uuid.UUID, kind string,
	id uuid.UUID, requestID string) error {
	args, err := ccReferenceUseArgs(scopeID, kind, id)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id`+ccReferenceUsesQuery+` ORDER BY id FOR UPDATE`, args...)
	if err != nil {
		return fmt.Errorf("lock CC reference users: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return fmt.Errorf("lock CC reference users: %w", err)
	}
	now := s.now().UTC()
	for _, policyID := range ids {
		current, err := selectPolicy(ctx, tx, policyID, false)
		if err != nil {
			return err
		}
		reject := func(err error) error {
			reason := fielderr.Invalid
			if located, ok := fielderr.As(err); ok {
				reason = located.Reason
			}
			return &CCReferenceRejectedError{Policy: CCReferenceUser{ID: current.ID, Name: current.Name}, Reason: reason}
		}
		references, err := loadCCReferences(ctx, tx, scopeID, current.Rules, true)
		if err != nil {
			return err
		}
		rules := cloneRules(current.Rules)
		if err := expandCCReferences(current.Kind, rules, references); err != nil {
			return reject(err)
		}
		fields := PolicyFields{Kind: current.Kind, Name: current.Name, Description: current.Description,
			Enabled: current.Enabled, DefaultAction: current.DefaultAction, Rules: rules,
			CCSettings: cloneCCSettings(current.CCSettings), WAFSettings: cloneWAFSettings(current.WAFSettings)}
		if err := normalizePublishableFields(&fields, false); err != nil {
			return reject(err)
		}
		// An edit that leaves the expansion as stored (a renamed matcher, a
		// description) writes nothing.
		unchanged, err := sameStoredContent(current, fields)
		if err != nil {
			return err
		}
		if unchanged {
			continue
		}
		encoded, err := json.Marshal(fields.Rules)
		if err != nil {
			return err
		}
		item, err := scanPolicy(tx.QueryRow(ctx, `
			UPDATE security_policies SET rules=$2, revision=revision+1, updated_by_user_id=$3, updated_at=$4
			WHERE id=$1 AND revision=$5 AND deleted_at IS NULL
			RETURNING `+policyColumns("security_policies")+`,
			          (SELECT display_name FROM users WHERE id=security_policies.owner_user_id)`,
			current.ID, encoded, actor.UserID, now, current.Revision))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, item, requestID, "security_policy.update"); err != nil {
			return err
		}
	}
	return nil
}
