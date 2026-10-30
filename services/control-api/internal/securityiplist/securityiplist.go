// Package securityiplist holds named IP lists (IP 名单):
// sets of addresses and CIDRs a WAF rule condition "ip_list in_ip_list <id>"
// references. A tenant list belongs to its tenant scope; a platform list
// (owned by the platform scope, managed by platform administrators) may be
// referenced by every tenant. Publication expands a list's entries into the
// rules (edgeconfig.WAFIPList), so every change republishes the scopes whose
// bound policies reference it (edgeautopublish.RepublishIPListChangeTx).
package securityiplist

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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	PermissionRead   = "security_policies.read"
	PermissionManage = "security_policies.manage"

	AuditCreate = "security.ip_list.create"
	AuditUpdate = "security.ip_list.update"
	AuditDelete = "security.ip_list.delete"

	// MaxListsPerScope bounds one scope's live lists.
	MaxListsPerScope = 200
)

var (
	ErrInvalidInput        = errors.New("invalid IP list input")
	ErrNotFound            = errors.New("IP list not found")
	ErrNameConflict        = errors.New("IP list name already exists")
	ErrRevisionConflict    = errors.New("IP list revision conflict")
	ErrIdempotencyConflict = errors.New("IP list idempotency conflict")
	ErrInUse               = errors.New("IP list is referenced by a security policy")
	ErrLimitExceeded       = errors.New("too many IP lists")
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

// List is one named IP list. Shared marks a platform list seen by a tenant
// (read only for it).
type List struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Entries     []string  `json:"entries"`
	Revision    int64     `json:"revision"`
	Platform    bool      `json:"platform"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Input is a create / update body. Entries are addresses or CIDRs
// (canonicalized: masked, deduplicated, ordered).
type Input struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Entries     []string `json:"entries"`
}

type WriteRequest struct {
	ListID           uuid.UUID
	ExpectedRevision int64
	Input            Input
	IdempotencyKey   string
	RequestID        string
	SourceIP         string
}

// Normalize checks an input and canonicalizes its entries.
func Normalize(input Input) (Input, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if n := utf8.RuneCountInString(input.Name); n < 1 || n > 64 || strings.IndexFunc(input.Name, unicode.IsControl) >= 0 ||
		utf8.RuneCountInString(input.Description) > 512 || strings.IndexFunc(input.Description, unicode.IsControl) >= 0 ||
		len(input.Entries) == 0 || len(input.Entries) > edgeconfig.MaxWAFIPListEntries {
		return Input{}, ErrInvalidInput
	}
	cidrs, err := edgeconfig.CanonicalIPListCIDRs(input.Entries)
	if err != nil {
		return Input{}, ErrInvalidInput
	}
	input.Entries = cidrs
	return input, nil
}

func digest(operation string, request WriteRequest) [32]byte {
	encoded, _ := json.Marshal(struct {
		Operation string    `json:"operation"`
		ListID    uuid.UUID `json:"list_id"`
		Expected  int64     `json:"expected_revision"`
		Input     Input     `json:"input"`
	}{operation, request.ListID, request.ExpectedRevision, request.Input})
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

const listColumns = `list.id,list.name,list.description,list.entries,list.revision,owner.kind='platform',list.updated_at`

func scanList(row pgx.Row) (List, error) {
	var list List
	if err := row.Scan(&list.ID, &list.Name, &list.Description, &list.Entries, &list.Revision, &list.Platform,
		&list.UpdatedAt); err != nil {
		return List{}, err
	}
	list.UpdatedAt = list.UpdatedAt.UTC()
	return list, nil
}

// ListAll is the actor's own lists and (for a tenant) the platform's, by name.
func (s *Store) ListAll(ctx context.Context, actor Actor) ([]List, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+listColumns+` FROM security_ip_lists list
		JOIN access_scopes owner ON owner.id=list.owner_scope_id
		WHERE list.deleted_at IS NULL AND (list.owner_scope_id=$1 OR owner.kind='platform')
		ORDER BY owner.kind='platform', lower(list.name), list.id`, actor.ScopeID)
	if err != nil {
		return nil, fmt.Errorf("list IP lists: %w", err)
	}
	defer rows.Close()
	result := []List{}
	for rows.Next() {
		list, err := scanList(rows)
		if err != nil {
			return nil, fmt.Errorf("scan IP list: %w", err)
		}
		result = append(result, list)
	}
	return result, rows.Err()
}

// Create adds a list owned by the actor's scope.
func (s *Store) Create(ctx context.Context, actor Actor, request WriteRequest) (List, error) {
	input, err := Normalize(request.Input)
	if err != nil {
		return List{}, err
	}
	request.Input = input
	var result List
	err = s.write(ctx, actor, AuditCreate, request, &result, func(tx pgx.Tx, now time.Time) (map[string]any, error) {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_ip_lists WHERE owner_scope_id=$1 AND deleted_at IS NULL`,
			actor.ScopeID).Scan(&count); err != nil {
			return nil, err
		}
		if count >= MaxListsPerScope {
			return nil, ErrLimitExceeded
		}
		id, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_ip_lists(id,owner_scope_id,name,description,entries,revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,1,$6,$6,$7,$7)`,
			id, actor.ScopeID, input.Name, input.Description, input.Entries, actor.UserID, now); err != nil {
			return nil, uniqueName(err)
		}
		result = List{ID: id, Name: input.Name, Description: input.Description, Entries: input.Entries, Revision: 1,
			Platform: actor.ScopeKind == "platform", UpdatedAt: now}
		return map[string]any{"name": input.Name, "entries": len(input.Entries), "revision": 1}, nil
	})
	return result, err
}

// Update replaces a list's name, description and entries at ExpectedRevision
// and republishes the scopes referencing it.
func (s *Store) Update(ctx context.Context, actor Actor, request WriteRequest) (List, error) {
	input, err := Normalize(request.Input)
	if err != nil {
		return List{}, err
	}
	request.Input = input
	var result List
	err = s.write(ctx, actor, AuditUpdate, request, &result, func(tx pgx.Tx, now time.Time) (map[string]any, error) {
		current, err := s.lockOwn(ctx, tx, actor, request.ListID)
		if err != nil {
			return nil, err
		}
		if current.Revision != request.ExpectedRevision {
			return nil, ErrRevisionConflict
		}
		next := current.Revision + 1
		if _, err := tx.Exec(ctx, `UPDATE security_ip_lists SET name=$2,description=$3,entries=$4,revision=$5,
			updated_by_user_id=$6,updated_at=$7 WHERE id=$1`, request.ListID, input.Name, input.Description, input.Entries,
			next, actor.UserID, now); err != nil {
			return nil, uniqueName(err)
		}
		scopes, err := edgeautopublish.RepublishIPListChangeTx(ctx, tx, request.ListID, next)
		if err != nil {
			return nil, err
		}
		result = List{ID: request.ListID, Name: input.Name, Description: input.Description, Entries: input.Entries,
			Revision: next, Platform: current.Platform, UpdatedAt: now}
		return map[string]any{"name": input.Name, "from_revision": current.Revision, "revision": next,
			"entries_before": len(current.Entries), "entries": len(input.Entries), "republished_scopes": len(scopes)}, nil
	})
	return result, err
}

// Delete removes a list no active policy version references (ErrInUse).
func (s *Store) Delete(ctx context.Context, actor Actor, request WriteRequest) error {
	var ignored List
	return s.write(ctx, actor, AuditDelete, request, &ignored, func(tx pgx.Tx, now time.Time) (map[string]any, error) {
		current, err := s.lockOwn(ctx, tx, actor, request.ListID)
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
			  '$.rules[*].conditions[*] ? (@.field == "ip_list" && @.values[0] == $id)', jsonb_build_object('id', $1::text)))`,
			request.ListID).Scan(&used); err != nil {
			return nil, err
		}
		if used {
			return nil, ErrInUse
		}
		if _, err := tx.Exec(ctx, `UPDATE security_ip_lists SET deleted_at=$2,updated_at=$2,updated_by_user_id=$3
			WHERE id=$1`, request.ListID, now, actor.UserID); err != nil {
			return nil, err
		}
		ignored = current
		return map[string]any{"name": current.Name, "revision": current.Revision}, nil
	})
}

// lockOwn locks a live list the actor's scope owns.
func (s *Store) lockOwn(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (List, error) {
	list, err := scanList(tx.QueryRow(ctx, `SELECT `+listColumns+` FROM security_ip_lists list
		JOIN access_scopes owner ON owner.id=list.owner_scope_id
		WHERE list.id=$1 AND list.owner_scope_id=$2 AND list.deleted_at IS NULL FOR UPDATE OF list`, id, actor.ScopeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return List{}, ErrNotFound
	}
	return list, err
}

// write runs one idempotent write with its audit event (success in the
// transaction; a refused write in its own).
func (s *Store) write(ctx context.Context, actor Actor, action string, request WriteRequest, result *List,
	apply func(pgx.Tx, time.Time) (map[string]any, error)) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || strings.TrimSpace(request.IdempotencyKey) == "" ||
		len(request.IdempotencyKey) > 128 {
		return ErrInvalidInput
	}
	sum := digest(action, request)
	now := s.now().UTC().Truncate(time.Microsecond)
	var payload map[string]any
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var stored []byte
		var storedSum []byte
		err := tx.QueryRow(ctx, `SELECT request_sha256,response FROM security_ip_list_write_requests
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
		if _, err := tx.Exec(ctx, `INSERT INTO security_ip_list_write_requests(actor_scope_id,actor_user_id,idempotency_key,
			request_sha256,list_id,response,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, actor.ScopeID, actor.UserID,
			request.IdempotencyKey, sum[:], result.ID, response, now); err != nil {
			return err
		}
		payload["ip"], payload["actor_scope_kind"], payload["list_id"] = request.SourceIP, actor.ScopeKind, result.ID.String()
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: action,
			ResourceType: "security_ip_list", ResourceID: result.ID.String(), RequestID: request.RequestID,
			Result: "success", Payload: payload})
	})
	if err != nil {
		if reason := deniedReason(err); reason != "" {
			if auditErr := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
				resource := ""
				if request.ListID != uuid.Nil {
					resource = request.ListID.String()
				}
				return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
					Action: action, ResourceType: "security_ip_list", ResourceID: resource, RequestID: request.RequestID,
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
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "security_ip_lists_owner_name_key" {
		return ErrNameConflict
	}
	return err
}
