// Package securitystringset holds named string sets:
// members a WAF rule condition "<field> in_string_set <id>" references. A
// tenant set belongs to its tenant scope; a platform set (owned by the
// platform scope, managed by platform administrators) may be referenced by
// every tenant. The site object carries each referenced set once at the
// revision the rules name (security_string_set_revisions keeps every
// revision), so every change republishes the scopes whose bound policies
// reference it (edgeautopublish.RepublishStringSetChangeTx).
package securitystringset

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	PermissionRead   = "security_policies.read"
	PermissionManage = "security_policies.manage"

	AuditCreate = "security.string_set.create"
	AuditUpdate = "security.string_set.update"
	AuditDelete = "security.string_set.delete"
)

var (
	ErrInvalidInput        = errors.New("invalid string set input")
	ErrNotFound            = errors.New("string set not found")
	ErrNameConflict        = errors.New("string set name already exists")
	ErrRevisionConflict    = errors.New("string set revision conflict")
	ErrIdempotencyConflict = errors.New("string set idempotency conflict")
	ErrInUse               = errors.New("string set is referenced by a security policy")
	ErrLimitExceeded       = errors.New("too many string sets")
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

// Summary is a list item (no entries). Platform marks a platform set (read
// only for a tenant). ReferenceCount counts the live security policies, of
// the actor's scope for a tenant (every scope for the platform), whose
// versions reference the set.
type Summary struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	MatchMode      string    `json:"match_mode"`
	CaseSensitive  bool      `json:"case_sensitive"`
	EntryCount     int       `json:"entry_count"`
	ReferenceCount int       `json:"reference_count"`
	Revision       int64     `json:"revision"`
	Platform       bool      `json:"platform"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Set is one set with its canonical entries.
type Set struct {
	Summary
	Entries []string `json:"entries"`
}

// Reference is one policy referencing a set: rule_count of its latest
// referencing version.
type Reference struct {
	PolicyID   uuid.UUID `json:"policy_id"`
	PolicyName string    `json:"policy_name"`
	PolicyKind string    `json:"policy_kind"`
	RuleCount  int       `json:"rule_count"`
}

// Input is a create / update body. MatchMode and CaseSensitive are taken on
// create only (an update sending them is refused by the HTTP layer).
type Input struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	MatchMode     string   `json:"match_mode"`
	CaseSensitive bool     `json:"case_sensitive"`
	Entries       []string `json:"entries"`
}

type WriteRequest struct {
	SetID            uuid.UUID
	ExpectedRevision int64
	Input            Input
	IdempotencyKey   string
	RequestID        string
	SourceIP         string
}

// Normalize checks an input and canonicalizes its entries
// (edgeconfig.CanonicalStringSetMembers): a refused entry is the field error
// entries[i] with the member reason (too_long, control_character,
// wildcard_too_many_stars, ...); a refused set as a whole is entries.
func Normalize(input Input) (Input, int, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if n := utf8.RuneCountInString(input.Name); n < 1 || n > 64 || strings.IndexFunc(input.Name, unicode.IsControl) >= 0 {
		return Input{}, 0, fielderr.New(ErrInvalidInput, "name", fielderr.Invalid)
	}
	if utf8.RuneCountInString(input.Description) > 512 || strings.IndexFunc(input.Description, unicode.IsControl) >= 0 {
		return Input{}, 0, fielderr.New(ErrInvalidInput, "description", fielderr.Invalid)
	}
	if !edgeconfig.ValidStringSetMode(input.MatchMode) {
		return Input{}, 0, fielderr.New(ErrInvalidInput, "match_mode", fielderr.Invalid)
	}
	if len(input.Entries) > edgeconfig.MaxStringSetMembers {
		return Input{}, 0, fielderr.New(ErrInvalidInput, "entries", edgeconfig.StringSetReasonCount)
	}
	members, size, err := edgeconfig.CanonicalStringSetMembers(input.MatchMode, input.CaseSensitive, input.Entries)
	if err != nil {
		var refused *edgeconfig.StringSetEntryError
		if errors.As(err, &refused) {
			if refused.Index >= 0 {
				return Input{}, 0, fielderr.New(ErrInvalidInput, fmt.Sprintf("entries[%d]", refused.Index), refused.Reason)
			}
			return Input{}, 0, fielderr.New(ErrInvalidInput, "entries", refused.Reason)
		}
		return Input{}, 0, fielderr.New(ErrInvalidInput, "entries", fielderr.Invalid)
	}
	input.Entries = members
	return input, size, nil
}

func digest(operation string, request WriteRequest) [32]byte {
	encoded, _ := json.Marshal(struct {
		Operation string    `json:"operation"`
		SetID     uuid.UUID `json:"set_id"`
		Expected  int64     `json:"expected_revision"`
		Input     Input     `json:"input"`
	}{operation, request.SetID, request.ExpectedRevision, request.Input})
	return sha256.Sum256(encoded)
}

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.New(pool), now: now}
}

// referencePath finds the rule conditions naming the set $id.
const referencePath = `$.rules[*].conditions[*] ? ((@.operator == "in_string_set" || @.operator == "not_in_string_set") && @.values[0] == $id)`

// ReferencePath is the jsonb path of a condition referencing set $id
// (edgepublish.StringSetSitesTx reads the active versions with it).
const ReferencePath = referencePath

const setColumns = `s.id,s.name,s.description,s.match_mode,s.case_sensitive,cardinality(s.entries),s.revision,
	owner.kind='platform',s.updated_at`

// referenceCount counts the live policies (of scope $2 unless it is NULL)
// with a version referencing s.
const referenceCount = `(SELECT count(DISTINCT policy.id) FROM security_policies policy
	JOIN security_policy_versions version ON version.policy_id=policy.id
	WHERE policy.deleted_at IS NULL AND ($2::uuid IS NULL OR policy.scope_id=$2) AND jsonb_path_exists(version.document,
	  '` + referencePath + `', jsonb_build_object('id', s.id::text)))`

func scanSummary(row pgx.Row, extra ...any) (Summary, error) {
	var summary Summary
	if err := row.Scan(append([]any{&summary.ID, &summary.Name, &summary.Description, &summary.MatchMode,
		&summary.CaseSensitive, &summary.EntryCount, &summary.Revision, &summary.Platform, &summary.UpdatedAt}, extra...)...); err != nil {
		return Summary{}, err
	}
	summary.UpdatedAt = summary.UpdatedAt.UTC()
	return summary, nil
}

// referenceScope is the scope references are counted in: the tenant's own;
// nil (every scope) for the platform.
func referenceScope(actor Actor) *uuid.UUID {
	if actor.ScopeKind == "platform" {
		return nil
	}
	return &actor.ScopeID
}

// ListAll is the actor's own sets and (for a tenant) the platform's: own
// first, then by name.
func (s *Store) ListAll(ctx context.Context, actor Actor) ([]Summary, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+setColumns+`,`+referenceCount+` FROM security_string_sets s
		JOIN access_scopes owner ON owner.id=s.owner_scope_id
		WHERE s.deleted_at IS NULL AND (s.owner_scope_id=$1 OR owner.kind='platform')
		ORDER BY s.owner_scope_id<>$1, lower(s.name), s.id`, actor.ScopeID, referenceScope(actor))
	if err != nil {
		return nil, fmt.Errorf("list string sets: %w", err)
	}
	defer rows.Close()
	result := []Summary{}
	for rows.Next() {
		var references int
		summary, err := scanSummary(rows, &references)
		if err != nil {
			return nil, fmt.Errorf("scan string set: %w", err)
		}
		summary.ReferenceCount = references
		result = append(result, summary)
	}
	return result, rows.Err()
}

// Get is one set the actor may see (own or platform) with its entries.
func (s *Store) Get(ctx context.Context, actor Actor, id uuid.UUID) (Set, error) {
	var set Set
	var references int
	summary, err := scanSummary(s.pool.QueryRow(ctx, `SELECT `+setColumns+`,`+referenceCount+`,s.entries
		FROM security_string_sets s JOIN access_scopes owner ON owner.id=s.owner_scope_id
		WHERE s.id=$1 AND s.deleted_at IS NULL AND (s.owner_scope_id=$3 OR owner.kind='platform')`,
		id, referenceScope(actor), actor.ScopeID), &references, &set.Entries)
	if errors.Is(err, pgx.ErrNoRows) {
		return Set{}, ErrNotFound
	}
	if err != nil {
		return Set{}, fmt.Errorf("read string set: %w", err)
	}
	summary.ReferenceCount = references
	set.Summary = summary
	return set, nil
}

// References are the live policies (of the actor's scope for a tenant)
// referencing a set the actor may see, by policy name.
func (s *Store) References(ctx context.Context, actor Actor, id uuid.UUID) ([]Reference, error) {
	if _, err := s.Get(ctx, actor, id); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT policy_id,name,kind,rule_count FROM (
		SELECT DISTINCT ON (policy.id) policy.id AS policy_id,policy.name,policy.kind,
		  (SELECT count(*) FROM jsonb_array_elements(version.document->'rules') rule
		   WHERE jsonb_path_exists(rule, '$.conditions[*] ? ((@.operator == "in_string_set" || @.operator == "not_in_string_set") && @.values[0] == $id)',
		     jsonb_build_object('id', $1::text)))::int AS rule_count
		FROM security_policies policy JOIN security_policy_versions version ON version.policy_id=policy.id
		WHERE policy.deleted_at IS NULL AND ($2::uuid IS NULL OR policy.scope_id=$2) AND jsonb_path_exists(version.document,
		  '`+referencePath+`', jsonb_build_object('id', $1::text))
		ORDER BY policy.id, version.revision DESC) refs ORDER BY lower(name), policy_id`, id, referenceScope(actor))
	if err != nil {
		return nil, fmt.Errorf("list string set references: %w", err)
	}
	result, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Reference])
	if err != nil {
		return nil, fmt.Errorf("scan string set references: %w", err)
	}
	return result, nil
}

// Create adds a set owned by the actor's scope (revision 1).
func (s *Store) Create(ctx context.Context, actor Actor, request WriteRequest) (Set, error) {
	input, size, err := Normalize(request.Input)
	if err != nil {
		return Set{}, err
	}
	request.Input = input
	var result Set
	err = s.write(ctx, actor, AuditCreate, request, &result, func(tx pgx.Tx, now time.Time) (map[string]any, error) {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_string_sets WHERE owner_scope_id=$1 AND deleted_at IS NULL`,
			actor.ScopeID).Scan(&count); err != nil {
			return nil, err
		}
		if count >= edgeconfig.MaxStringSetsPerScope {
			return nil, ErrLimitExceeded
		}
		id, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_string_sets(id,owner_scope_id,name,description,match_mode,
			case_sensitive,entries,entries_bytes,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,$9,$9,$10,$10)`, id, actor.ScopeID, input.Name, input.Description,
			input.MatchMode, input.CaseSensitive, input.Entries, size, actor.UserID, now); err != nil {
			return nil, uniqueName(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_string_set_revisions(set_id,revision,entries,created_at)
			VALUES($1,1,$2,$3)`, id, input.Entries, now); err != nil {
			return nil, err
		}
		result = Set{Summary: Summary{ID: id, Name: input.Name, Description: input.Description, MatchMode: input.MatchMode,
			CaseSensitive: input.CaseSensitive, EntryCount: len(input.Entries), Revision: 1,
			Platform: actor.ScopeKind == "platform", UpdatedAt: now}, Entries: input.Entries}
		return map[string]any{"name": input.Name, "match_mode": input.MatchMode, "entries": len(input.Entries), "revision": 1}, nil
	})
	return result, err
}

// Update replaces a set's name, description and entries at ExpectedRevision
// (match mode and case sensitivity stay) and republishes the scopes
// referencing it.
func (s *Store) Update(ctx context.Context, actor Actor, request WriteRequest) (Set, error) {
	var result Set
	err := s.write(ctx, actor, AuditUpdate, request, &result, func(tx pgx.Tx, now time.Time) (map[string]any, error) {
		current, err := s.lockOwn(ctx, tx, actor, request.SetID)
		if err != nil {
			return nil, err
		}
		if current.Revision != request.ExpectedRevision {
			return nil, ErrRevisionConflict
		}
		input := request.Input
		input.MatchMode, input.CaseSensitive = current.MatchMode, current.CaseSensitive
		input, size, err := Normalize(input)
		if err != nil {
			return nil, err
		}
		next := current.Revision + 1
		if _, err := tx.Exec(ctx, `UPDATE security_string_sets SET name=$2,description=$3,entries=$4,entries_bytes=$5,
			revision=$6,updated_by_user_id=$7,updated_at=$8 WHERE id=$1`, request.SetID, input.Name, input.Description,
			input.Entries, size, next, actor.UserID, now); err != nil {
			return nil, uniqueName(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_string_set_revisions(set_id,revision,entries,created_at)
			VALUES($1,$2,$3,$4)`, request.SetID, next, input.Entries, now); err != nil {
			return nil, err
		}
		scopes, err := edgeautopublish.RepublishStringSetChangeTx(ctx, tx, request.SetID, next)
		if err != nil {
			return nil, err
		}
		result = Set{Summary: Summary{ID: request.SetID, Name: input.Name, Description: input.Description,
			MatchMode: current.MatchMode, CaseSensitive: current.CaseSensitive, EntryCount: len(input.Entries),
			Revision: next, Platform: current.Platform, UpdatedAt: now}, Entries: input.Entries}
		return map[string]any{"name": input.Name, "from_revision": current.Revision, "revision": next,
			"entries_before": current.EntryCount, "entries": len(input.Entries), "republished_scopes": len(scopes)}, nil
	})
	return result, err
}

// Delete removes a set no live policy version references (ErrInUse).
func (s *Store) Delete(ctx context.Context, actor Actor, request WriteRequest) error {
	var ignored Set
	return s.write(ctx, actor, AuditDelete, request, &ignored, func(tx pgx.Tx, now time.Time) (map[string]any, error) {
		current, err := s.lockOwn(ctx, tx, actor, request.SetID)
		if err != nil {
			return nil, err
		}
		if current.Revision != request.ExpectedRevision {
			return nil, ErrRevisionConflict
		}
		var used bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM security_policies policy
			JOIN security_policy_versions version ON version.policy_id=policy.id
			WHERE policy.deleted_at IS NULL AND jsonb_path_exists(version.document,
			  '`+referencePath+`', jsonb_build_object('id', $1::text)))`, request.SetID).Scan(&used); err != nil {
			return nil, err
		}
		if used {
			return nil, ErrInUse
		}
		if _, err := tx.Exec(ctx, `UPDATE security_string_sets SET deleted_at=$2,updated_at=$2,updated_by_user_id=$3
			WHERE id=$1`, request.SetID, now, actor.UserID); err != nil {
			return nil, err
		}
		ignored = Set{Summary: current}
		return map[string]any{"name": current.Name, "revision": current.Revision}, nil
	})
}

// lockOwn locks a live set the actor's scope owns.
func (s *Store) lockOwn(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (Summary, error) {
	summary, err := scanSummary(tx.QueryRow(ctx, `SELECT `+setColumns+` FROM security_string_sets s
		JOIN access_scopes owner ON owner.id=s.owner_scope_id
		WHERE s.id=$1 AND s.owner_scope_id=$2 AND s.deleted_at IS NULL FOR UPDATE OF s`, id, actor.ScopeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Summary{}, ErrNotFound
	}
	return summary, err
}

// write runs one idempotent write with its audit event (success in the
// transaction; a refused write in its own).
func (s *Store) write(ctx context.Context, actor Actor, action string, request WriteRequest, result *Set,
	apply func(pgx.Tx, time.Time) (map[string]any, error)) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || strings.TrimSpace(request.IdempotencyKey) == "" ||
		len(request.IdempotencyKey) > 128 {
		return ErrInvalidInput
	}
	sum := digest(action, request)
	now := s.now().UTC().Truncate(time.Microsecond)
	var payload map[string]any
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var stored, storedSum []byte
		err := tx.QueryRow(ctx, `SELECT request_sha256,response FROM security_string_set_write_requests
			WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3`, actor.ScopeID, actor.UserID,
			request.IdempotencyKey).Scan(&storedSum, &stored)
		if err == nil {
			if string(storedSum) != string(sum[:]) {
				return ErrIdempotencyConflict
			}
			return json.Unmarshal(stored, result)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if payload, err = apply(tx, now); err != nil {
			return err
		}
		response, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_string_set_write_requests(actor_scope_id,actor_user_id,idempotency_key,
			request_sha256,set_id,response,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, actor.ScopeID, actor.UserID,
			request.IdempotencyKey, sum[:], result.ID, response, now); err != nil {
			return err
		}
		payload["ip"], payload["actor_scope_kind"], payload["set_id"] = request.SourceIP, actor.ScopeKind, result.ID.String()
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: action,
			ResourceType: "security_string_set", ResourceID: result.ID.String(), RequestID: request.RequestID,
			Result: "success", Payload: payload})
	})
	if err != nil {
		if reason := deniedReason(err); reason != "" {
			if auditErr := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
				resource := ""
				if request.SetID != uuid.Nil {
					resource = request.SetID.String()
				}
				return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
					Action: action, ResourceType: "security_string_set", ResourceID: resource, RequestID: request.RequestID,
					Result: "denied", Payload: map[string]any{"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind,
						"reason_code": reason, "name": request.Input.Name}})
			}); auditErr != nil {
				return fmt.Errorf("%s: %w (audit denied write: %v)", action, err, auditErr)
			}
		}
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}

func deniedReason(err error) string {
	switch {
	case errors.Is(err, ErrNameConflict):
		return "name_conflict"
	case errors.Is(err, ErrRevisionConflict):
		return "version_conflict"
	case errors.Is(err, ErrInUse):
		return "in_use"
	case errors.Is(err, ErrLimitExceeded):
		return "limit_exceeded"
	case errors.Is(err, ErrIdempotencyConflict):
		return "idempotency_conflict"
	}
	return ""
}

func uniqueName(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "security_string_sets_owner_name_key" {
		return ErrNameConflict
	}
	return err
}
