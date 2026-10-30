package announcement

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// tenantRecipientsSQL resolves the active recipients of one tenant
// announcement version. Publication snapshots exactly this set and the
// audience count reads it, so the preview cannot drift from delivery.
// Parameters: $1 tenant scope, $2 announcement, $3 version, $4 audience mode.
const tenantRecipientsSQL = `
	SELECT membership.user_id FROM memberships membership
	WHERE $4='all' AND membership.scope_id=$1 AND membership.status='active'
	UNION
	SELECT selected.user_id FROM announcement_audience_users selected
	JOIN memberships membership ON membership.scope_id=selected.tenant_scope_id
	 AND membership.user_id=selected.user_id AND membership.status='active'
	WHERE $4='selected' AND selected.tenant_scope_id=$1 AND selected.announcement_id=$2
	 AND selected.announcement_version=$3
	UNION
	SELECT assignment.user_id FROM announcement_audience_groups selected_group
	JOIN role_assignments assignment ON assignment.scope_id=selected_group.tenant_scope_id
	 AND assignment.role_id=selected_group.group_role_id
	JOIN memberships membership ON membership.scope_id=assignment.scope_id
	 AND membership.user_id=assignment.user_id AND membership.status='active'
	WHERE $4='selected' AND selected_group.tenant_scope_id=$1
	 AND selected_group.announcement_id=$2 AND selected_group.announcement_version=$3`

const (
	AudienceKindTenant = "tenant"
	AudienceKindRole   = "role"
	AudienceKindUser   = "user"

	MaxAudienceDirectoryLimit = 50
	MaxAudienceDirectoryIDs   = 100
)

// AudienceCount is the number of recipients publication would deliver to now.
type AudienceCount struct {
	AnnouncementID uuid.UUID `json:"announcement_id"`
	Version        int64     `json:"version,omitempty"`
	RecipientCount int64     `json:"recipient_count"`
}

// AudienceDirectoryRequest either searches by name (Search, Limit) or resolves
// stored target IDs back to names (IDs). ScopeID narrows global role/user
// searches to one tenant; tenant requests always use the actor's own scope.
type AudienceDirectoryRequest struct {
	Kind    string
	Search  string
	ScopeID uuid.UUID
	IDs     []uuid.UUID
	Limit   int
}

type AudienceDirectoryEntry struct {
	ID      uuid.UUID  `json:"id"`
	ScopeID *uuid.UUID `json:"scope_id,omitempty"`
	Name    string     `json:"name"`
	Detail  string     `json:"detail,omitempty"`
	System  bool       `json:"system,omitempty"`
}

type AudienceDirectory struct {
	Items []AudienceDirectoryEntry `json:"items"`
}

func (s *Store) AudienceCount(ctx context.Context, actor Actor, id uuid.UUID) (AudienceCount, error) {
	if id == uuid.Nil {
		return AudienceCount{}, ErrInvalidInput
	}
	var result AudienceCount
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		root, err := lockRoot(ctx, tx, actor.ScopeID, id)
		if err != nil {
			return err
		}
		item, err := loadAnnouncement(ctx, tx, actor.ScopeID, id, root.HeadVersion, false)
		if err != nil {
			return err
		}
		result = AudienceCount{AnnouncementID: id, Version: item.Version}
		return tx.QueryRow(ctx, `SELECT count(*) FROM (`+tenantRecipientsSQL+`) recipient`,
			item.ScopeID, item.ID, item.Version, audienceMode(item.Audience)).Scan(&result.RecipientCount)
	})
	if err != nil {
		return AudienceCount{}, fmt.Errorf("count announcement audience: %w", err)
	}
	return result, nil
}

func (s *Store) GlobalAudienceCount(ctx context.Context, actor Actor, id uuid.UUID) (AudienceCount, error) {
	if id == uuid.Nil {
		return AudienceCount{}, ErrInvalidInput
	}
	var result AudienceCount
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeGlobalManage(ctx, tx, actor); err != nil {
			return err
		}
		item, err := loadGlobalAnnouncement(ctx, tx, actor.ScopeID, id, false)
		if err != nil {
			return err
		}
		recipients, err := resolveGlobalRecipients(ctx, tx, item.Audience)
		if err != nil {
			return err
		}
		result = AudienceCount{AnnouncementID: id, RecipientCount: int64(len(recipients))}
		return nil
	})
	if err != nil {
		return AudienceCount{}, fmt.Errorf("count global announcement audience: %w", err)
	}
	return result, nil
}

// AudienceDirectory lists users and roles of the actor's tenant by name.
func (s *Store) AudienceDirectory(ctx context.Context, actor Actor, request AudienceDirectoryRequest) (AudienceDirectory, error) {
	if request.Kind != AudienceKindUser && request.Kind != AudienceKindRole {
		return AudienceDirectory{}, ErrInvalidInput
	}
	request.ScopeID = actor.ScopeID
	if err := validDirectoryRequest(request); err != nil {
		return AudienceDirectory{}, err
	}
	var result AudienceDirectory
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		var err error
		result, err = queryDirectory(ctx, tx, request, false)
		return err
	})
	if err != nil {
		return AudienceDirectory{}, fmt.Errorf("announcement audience directory: %w", err)
	}
	return result, nil
}

// GlobalAudienceDirectory lists tenants, and the roles and users of one
// tenant, for platform announcement managers.
func (s *Store) GlobalAudienceDirectory(ctx context.Context, actor Actor, request AudienceDirectoryRequest) (AudienceDirectory, error) {
	switch request.Kind {
	case AudienceKindTenant:
		request.ScopeID = uuid.Nil
	case AudienceKindRole, AudienceKindUser:
		if len(request.IDs) == 0 && request.ScopeID == uuid.Nil {
			return AudienceDirectory{}, ErrInvalidInput
		}
	default:
		return AudienceDirectory{}, ErrInvalidInput
	}
	if err := validDirectoryRequest(request); err != nil {
		return AudienceDirectory{}, err
	}
	var result AudienceDirectory
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeGlobalManage(ctx, tx, actor); err != nil {
			return err
		}
		var err error
		result, err = queryDirectory(ctx, tx, request, true)
		return err
	})
	if err != nil {
		return AudienceDirectory{}, fmt.Errorf("global announcement audience directory: %w", err)
	}
	return result, nil
}

func validDirectoryRequest(request AudienceDirectoryRequest) error {
	if len(request.IDs) > 0 {
		if request.Search != "" || len(request.IDs) > MaxAudienceDirectoryIDs {
			return ErrInvalidInput
		}
		for _, id := range request.IDs {
			if id == uuid.Nil {
				return ErrInvalidInput
			}
		}
		return nil
	}
	if request.Limit < 1 || request.Limit > MaxAudienceDirectoryLimit ||
		utf8.RuneCountInString(request.Search) > 128 || strings.ContainsAny(request.Search, "\x00") {
		return ErrInvalidInput
	}
	return nil
}

// queryDirectory runs one directory query. Name lookups (IDs) ignore status so
// an edited draft can still show inactive targets by name; searches only offer
// targets that can currently receive an announcement.
func queryDirectory(ctx context.Context, tx pgx.Tx, request AudienceDirectoryRequest, global bool) (AudienceDirectory, error) {
	lookup := len(request.IDs) > 0
	ids := request.IDs
	if ids == nil {
		ids = []uuid.UUID{}
	}
	scope := &request.ScopeID
	if request.ScopeID == uuid.Nil {
		scope = nil
	}
	search := strings.TrimSpace(request.Search)
	limit := request.Limit
	if lookup {
		limit = len(ids)
	}
	var query string
	switch request.Kind {
	case AudienceKindTenant:
		query = `SELECT scope.id,NULL::uuid,tenant.display_name,tenant.display_id::text,false
			FROM access_scopes scope JOIN tenants tenant ON tenant.id=scope.tenant_id
			WHERE scope.kind='tenant'
			  AND (($1 AND scope.id=ANY($2)) OR (NOT $1 AND tenant.status='active'
			   AND ($3='' OR position(lower($3) IN lower(concat_ws(' ',tenant.display_name,tenant.display_id::text)))>0)))
			  AND ($4::uuid IS NULL OR scope.id=$4)
			ORDER BY tenant.display_name,scope.id LIMIT $5`
	case AudienceKindRole:
		query = `SELECT role.id,role.scope_id,COALESCE(custom_role.current_name,role.name),'',
			role.system_role AND custom_role.id IS NULL
			FROM roles role
			JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='tenant'
			LEFT JOIN custom_roles custom_role ON custom_role.id=role.id AND custom_role.tenant_scope_id=role.scope_id
			WHERE (($1 AND role.id=ANY($2)) OR (NOT $1 AND (custom_role.id IS NULL OR custom_role.deactivated_at IS NULL)
			   AND ($3='' OR position(lower($3) IN lower(COALESCE(custom_role.current_name,role.name)))>0)))
			  AND ($4::uuid IS NULL OR role.scope_id=$4)
			ORDER BY 3,role.id LIMIT $5`
	case AudienceKindUser:
		// Users are global rows; a lookup without scope may match several
		// memberships, so DISTINCT ON keeps one row per user.
		query = `SELECT DISTINCT ON (account.username,account.id) account.id,
			CASE WHEN $4::uuid IS NULL THEN NULL::uuid ELSE membership.scope_id END,
			account.display_name,account.username,false
			FROM memberships membership
			JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='tenant'
			JOIN users account ON account.id=membership.user_id
			WHERE (($1 AND account.id=ANY($2)) OR (NOT $1 AND membership.status='active' AND account.status='active'
			   AND ($3='' OR position(lower($3) IN lower(concat_ws(' ',account.username,account.display_name)))>0)))
			  AND ($4::uuid IS NULL OR membership.scope_id=$4)
			ORDER BY account.username,account.id LIMIT $5`
	default:
		return AudienceDirectory{}, ErrInvalidInput
	}
	if !global && scope == nil {
		return AudienceDirectory{}, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, query, lookup, ids, search, scope, limit)
	if err != nil {
		return AudienceDirectory{}, err
	}
	defer rows.Close()
	result := AudienceDirectory{Items: []AudienceDirectoryEntry{}}
	for rows.Next() {
		var entry AudienceDirectoryEntry
		if err := rows.Scan(&entry.ID, &entry.ScopeID, &entry.Name, &entry.Detail, &entry.System); err != nil {
			return AudienceDirectory{}, err
		}
		if !global {
			entry.ScopeID = nil
		}
		result.Items = append(result.Items, entry)
	}
	return result, rows.Err()
}
