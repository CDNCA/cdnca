package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Tenant members / sub-accounts. A tenant administrator (identity.users.manage, or the tenant
// owner's identity.roles.manage) lists the members of its own tenant scope,
// adds a sub-account (a new user that is a member of this scope only, with the
// tenant viewer role; more permissions come from /v1/custom-rbac grants),
// suspends and resumes members. The scope owner (the user that created the
// tenant) cannot be suspended through this path, and nobody can suspend
// themselves. Every write is audited.

var (
	ErrTenantMemberProtected = errors.New("tenant member is protected")
	ErrTenantMemberShared    = errors.New("tenant member belongs to another scope too")
	// ErrTenantMemberOutranks: the target holds a permission the acting member
	// lacks, so the actor may not manage it (the tenant owner is never bound).
	ErrTenantMemberOutranks      = errors.New("tenant member holds permissions beyond the actor's")
	ErrTenantMemberOwnsResources = errors.New("tenant member still owns resources")
	// ErrTenantMemberTransferTarget: the receiving member is not an active,
	// undeleted member of the scope, or is the member being removed.
	ErrTenantMemberTransferTarget = errors.New("tenant member transfer target is invalid")
)

type TenantMember struct {
	UserID      uuid.UUID `json:"user_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       *string   `json:"email"`
	Status      string    `json:"status"`
	Role        string    `json:"role"`
	Owner       bool      `json:"owner"`
	CreatedAt   time.Time `json:"created_at"`
	// PasswordChangeRequired: must change the password at the next sign-in.
	PasswordChangeRequired bool `json:"password_change_required"`
}

type CreateTenantMemberInput struct {
	Username    string
	DisplayName string
	Email       string
	Password    string
	RequestID   string
}

const tenantMemberPermissionsSQL = `SELECT EXISTS(SELECT 1 FROM role_assignments assignment
	JOIN role_permissions permission ON permission.role_id=assignment.role_id
	WHERE assignment.scope_id=$1 AND assignment.user_id=$2
	  AND permission.permission_name IN ('identity.users.manage','identity.roles.manage'))`

func (s *Store) authorizeTenantMemberAdminTx(ctx context.Context, tx pgx.Tx, actor Principal) error {
	if actor.ScopeKind != "tenant" || actor.TenantID == nil {
		return ErrPermissionDenied
	}
	var allowed bool
	if err := tx.QueryRow(ctx, tenantMemberPermissionsSQL, actor.ScopeID, actor.UserID).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

// tenantOwnerSQL: the scope's owner is its earliest membership.
const tenantOwnerSQL = `(SELECT owner.user_id FROM memberships owner WHERE owner.scope_id=$1 ORDER BY owner.created_at, owner.user_id LIMIT 1)`

// ensureTenantMemberNotOutranksTx refuses a target holding a permission the
// actor does not hold (system roles and custom grants both count, and a
// suspended target is judged by its assigned roles). The tenant owner acts on
// everyone below it.
func ensureTenantMemberNotOutranksTx(ctx context.Context, tx pgx.Tx, actor Principal, userID uuid.UUID) error {
	var actorIsOwner, outranks bool
	err := tx.QueryRow(ctx, `SELECT $2=`+tenantOwnerSQL+`, EXISTS(
		SELECT 1 FROM (
			SELECT permission_name FROM custom_rbac_effective_permissions($1,$3)
			UNION
			SELECT rp.permission_name FROM role_assignments ra JOIN role_permissions rp ON rp.role_id=ra.role_id
			WHERE ra.scope_id=$1 AND ra.user_id=$3
		) target WHERE target.permission_name NOT IN (
			SELECT permission_name FROM custom_rbac_effective_permissions($1,$2)
			UNION
			SELECT rp.permission_name FROM role_assignments ra JOIN role_permissions rp ON rp.role_id=ra.role_id
			WHERE ra.scope_id=$1 AND ra.user_id=$2))`,
		actor.ScopeID, actor.UserID, userID).Scan(&actorIsOwner, &outranks)
	if err != nil {
		return err
	}
	if outranks && !actorIsOwner {
		return ErrTenantMemberOutranks
	}
	return nil
}

func (s *Store) ListTenantMembers(ctx context.Context, actor Principal) ([]TenantMember, error) {
	var members []TenantMember
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTenantMemberAdminTx(ctx, tx, actor); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT u.id,u.username,u.display_name,u.email,
			CASE WHEN u.status<>'active' THEN u.status ELSE m.status END,
			COALESCE((SELECT role.name FROM role_assignments assignment JOIN roles role ON role.id=assignment.role_id
				WHERE assignment.scope_id=m.scope_id AND assignment.user_id=m.user_id ORDER BY role.name LIMIT 1),''),
			u.id=`+tenantOwnerSQL+`, m.created_at, u.password_change_required
			FROM memberships m JOIN users u ON u.id=m.user_id
			WHERE m.scope_id=$1 AND NOT EXISTS(SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id=u.id)
			ORDER BY m.created_at, u.id LIMIT 500`, actor.ScopeID)
		if err != nil {
			return err
		}
		members, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (TenantMember, error) {
			var member TenantMember
			return member, row.Scan(&member.UserID, &member.Username, &member.DisplayName, &member.Email,
				&member.Status, &member.Role, &member.Owner, &member.CreatedAt, &member.PasswordChangeRequired)
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list tenant members: %w", err)
	}
	return members, nil
}

// CreateTenantMember adds a sub-account to the actor's tenant scope.
func (s *Service) CreateTenantMember(ctx context.Context, actor Principal, input CreateTenantMemberInput) (TenantMember, error) {
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if !validUsername(input.Username) || input.DisplayName == "" || len(input.DisplayName) > 128 ||
		len(input.Email) > 254 || len(input.Password) < 12 || len(input.Password) > 1024 || input.RequestID == "" {
		return TenantMember{}, ErrInvalidUserInput
	}
	hash, err := HashPassword(input.Password)
	if err != nil {
		return TenantMember{}, err
	}
	userID, err := newUUID()
	if err != nil {
		return TenantMember{}, err
	}
	var email *string
	if input.Email != "" {
		email = &input.Email
	}
	member := TenantMember{UserID: userID, Username: input.Username, DisplayName: input.DisplayName, Email: email,
		Status: UserStatusActive, Role: UserRoleViewer}
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		if err := s.store.authorizeTenantMemberAdminTx(ctx, tx, actor); err != nil {
			return err
		}
		now := s.now().UTC()
		member.CreatedAt = now
		if _, err := tx.Exec(ctx, `INSERT INTO users(id,username,display_name,email,password_hash,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$6)`, userID, input.Username, input.DisplayName, email, hash, now); err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$3)`, actor.ScopeID, userID, now); err != nil {
			return err
		}
		roleID, err := tenantRoleID(ctx, tx, actor.ScopeID, UserRoleViewer)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`,
			actor.ScopeID, userID, roleID, now); err != nil {
			return err
		}
		return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: "identity.tenant_member.create", ResourceType: "user", ResourceID: userID.String(), RequestID: input.RequestID,
			Result: "success", Changes: []audit.Change{{Field: "username", Before: nil, After: input.Username}, {Field: "role", Before: nil, After: UserRoleViewer}},
			Payload: map[string]any{"role": UserRoleViewer}})
	})
	if err != nil {
		return TenantMember{}, err
	}
	return member, nil
}

// SetTenantMemberStatus suspends (active=false) or resumes a member of the
// actor's tenant scope. Suspending revokes the member's sessions in the scope
// and, with transferTo, first hands the member's transferable resources to
// that member in the same transaction (see transferTenantMemberResourcesTx).
func (s *Service) SetTenantMemberStatus(ctx context.Context, actor Principal, userID uuid.UUID, active bool, transferTo *uuid.UUID, requestID string) (TenantMember, error) {
	if userID == uuid.Nil || requestID == "" {
		return TenantMember{}, ErrInvalidUserInput
	}
	if userID == actor.UserID {
		return TenantMember{}, ErrTenantMemberProtected
	}
	if active && transferTo != nil {
		return TenantMember{}, ErrInvalidUserInput
	}
	from, to, action := MembershipStatusActive, MembershipStatusSuspended, "identity.tenant_member.suspend"
	if active {
		from, to, action = MembershipStatusSuspended, MembershipStatusActive, "identity.tenant_member.resume"
	}
	err := pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		if err := s.store.authorizeTenantMemberAdminTx(ctx, tx, actor); err != nil {
			return err
		}
		var status string
		var owner bool
		err := tx.QueryRow(ctx, `SELECT m.status, m.user_id=`+tenantOwnerSQL+` FROM memberships m
			WHERE m.scope_id=$1 AND m.user_id=$2 FOR UPDATE`, actor.ScopeID, userID).Scan(&status, &owner)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMembershipNotFound
		}
		if err != nil {
			return err
		}
		if owner {
			return ErrTenantMemberProtected
		}
		if err := ensureTenantMemberNotOutranksTx(ctx, tx, actor, userID); err != nil {
			return err
		}
		now := s.now().UTC()
		if transferTo != nil {
			if status != from && status != to {
				return ErrMembershipStatusConflict
			}
			if err := s.transferTenantMemberResourcesTx(ctx, tx, actor, userID, *transferTo, now, requestID); err != nil {
				return err
			}
		}
		if status == to {
			return nil
		}
		if status != from {
			return ErrMembershipStatusConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE memberships SET status=$3 WHERE scope_id=$1 AND user_id=$2`, actor.ScopeID, userID, to); err != nil {
			return err
		}
		if !active {
			if _, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,$3),
				revocation_reason=COALESCE(revocation_reason,'membership_suspended') WHERE scope_id=$1 AND user_id=$2`,
				actor.ScopeID, userID, now); err != nil {
				return err
			}
		}
		return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: action, ResourceType: "user", ResourceID: userID.String(), RequestID: requestID, Result: "success",
			Changes: []audit.Change{{Field: "status", Before: status, After: to}}})
	})
	if err != nil {
		return TenantMember{}, err
	}
	return s.tenantMember(ctx, actor, userID)
}

func (s *Service) tenantMember(ctx context.Context, actor Principal, userID uuid.UUID) (TenantMember, error) {
	members, err := s.store.ListTenantMembers(ctx, actor)
	if err != nil {
		return TenantMember{}, err
	}
	for _, member := range members {
		if member.UserID == userID {
			return member, nil
		}
	}
	return TenantMember{}, ErrMembershipNotFound
}

// ListTenantMembers is the service entry point.
func (s *Service) ListTenantMembers(ctx context.Context, actor Principal) ([]TenantMember, error) {
	return s.store.ListTenantMembers(ctx, actor)
}

// Resources a removed member still owns ($1 scope, $2 user) fall in two kinds.
//
// Not transferable (deletion is refused with tenant_member_owns_resources and
// the counts): the owner is pinned by commercial or durable authority facts,
// so the tenant owner has to delete, or let expire, them first.
//   - active package subscriptions: package_subscriptions.created_by_user_id
//     (028), the state versions (062) and package_monitor_subscription_owners
//     (078, append-only) all record the buyer;
//   - layer-4 forwards: each is bound to a package subscription and every
//     write requires the subscription owner to be the forward owner;
//   - sites bound to a package or a CNAME allocation: cname_allocations
//     owner is immutable (113) and must equal the site owner, and the package
//     owner must equal the site owner on every edit;
//   - sites with a live HTTP policy: http_policies.site_owner_user_id only
//     moves through revisions that must keep it (056).
//
// Transferable (rewritten to the receiving member in the deletion
// transaction): the remaining sites, layer-4 forward groups, security
// policies, URL authentication policies, the tenant's own CC matchers and
// filters (not the platform-managed system rules) and certificates (276
// allows the change only for this handover, migration 404). A site stopped
// by the member's suspension (383 hold) serves again once the account
// suspension pass sees its new, active owner.
const tenantMemberBlockingResourcesSQL = `SELECT
	(SELECT count(*) FROM package_subscriptions s JOIN package_subscription_state_versions o
		ON o.subscription_id=s.id AND o.tenant_scope_id=s.tenant_scope_id AND o.revision=s.revision
		WHERE s.tenant_scope_id=$1 AND o.owner_user_id=$2 AND s.lifecycle_status='active'),
	(SELECT count(*) FROM l4_forwards WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL),
	(SELECT count(*) FROM sites site WHERE site.scope_id=$1 AND site.owner_user_id=$2 AND site.deleted_at IS NULL AND (
		site.package_subscription_id IS NOT NULL OR site.package_id IS NOT NULL OR site.cname_mode IS NOT NULL OR
		EXISTS(SELECT 1 FROM cname_site_bindings binding WHERE binding.tenant_scope_id=site.scope_id AND binding.site_id=site.id) OR
		EXISTS(SELECT 1 FROM http_policies policy WHERE policy.site_id=site.id AND NOT policy.current_deleted)))`

// TenantMemberBlockingResources counts what keeps a member from being deleted.
type TenantMemberBlockingResources struct {
	PackageSubscriptions int64 `json:"package_subscriptions"`
	L4Forwards           int64 `json:"l4_forwards"`
	PackageSites         int64 `json:"package_sites"`
	// Transferable: resources that move with transfer_to (only reported when
	// the deletion named no receiving member).
	Transferable int64 `json:"transferable"`
}

// TenantMemberOwnsResourcesError is ErrTenantMemberOwnsResources with the counts.
type TenantMemberOwnsResourcesError struct {
	Resources TenantMemberBlockingResources
}

func (e *TenantMemberOwnsResourcesError) Error() string { return ErrTenantMemberOwnsResources.Error() }
func (e *TenantMemberOwnsResourcesError) Unwrap() error { return ErrTenantMemberOwnsResources }

// tenantMemberTransfers rewrite owner_user_id from $2 to $3 in scope $1 for
// the transferable resources, in a fixed order, each by its table's write
// rules. Sites, forward groups and certificates advance their revision and
// record the administrator ($4) as the last writer (the 236 and 039 triggers
// require it). Policies and CC references keep their revision: their readers
// join the version row of the current revision and the owner is not part of
// it. A site and its URL authentication policy move together, so the policy
// owner still equals the site owner.
var tenantMemberTransfers = []struct {
	kind    string
	stamped bool // takes $4 (administrator) and $5 (time)
	sql     string
}{
	{"sites", true, `UPDATE sites SET owner_user_id=$3,revision=revision+1,updated_by_user_id=$4,updated_at=$5
		WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL`},
	{"l4_stream_groups", true, `UPDATE l4_stream_groups SET owner_user_id=$3,revision=revision+1,updated_by_user_id=$4,updated_at=$5
		WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL`},
	{"certificates", true, `UPDATE certificate_assets SET owner_user_id=$3,revision=revision+1,updated_by_scope_id=$1,updated_by_user_id=$4,updated_at=$5
		WHERE tenant_scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL`},
	{"security_policies", false, `UPDATE security_policies SET owner_user_id=$3
		WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL`},
	{"url_auth_policies", false, `UPDATE url_auth_policies SET owner_user_id=$3
		WHERE scope_id=$1 AND owner_user_id=$2`},
	{"cc_reference_matchers", false, `UPDATE cc_reference_matchers SET owner_user_id=$3
		WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL AND NOT system_rule`},
	{"cc_reference_filters", false, `UPDATE cc_reference_filters SET owner_user_id=$3
		WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL AND NOT system_rule`},
}

// lockTenantMemberTargetTx locks a deletable/resettable member of the actor's
// scope: not the actor, not the owner, not deleted, and a member of this scope
// only (a user shared with another scope is not this tenant's to delete).
func lockTenantMemberTargetTx(ctx context.Context, tx pgx.Tx, actor Principal, userID uuid.UUID) error {
	if userID == actor.UserID {
		return ErrTenantMemberProtected
	}
	var owner, deleted bool
	var scopes int
	err := tx.QueryRow(ctx, `SELECT m.user_id=`+tenantOwnerSQL+`,
		EXISTS(SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id=m.user_id),
		(SELECT count(*) FROM memberships other WHERE other.user_id=m.user_id)
		FROM memberships m JOIN users u ON u.id=m.user_id
		WHERE m.scope_id=$1 AND m.user_id=$2 FOR UPDATE OF m,u`, actor.ScopeID, userID).Scan(&owner, &deleted, &scopes)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && deleted {
		return ErrMembershipNotFound
	}
	if err != nil {
		return err
	}
	if owner {
		return ErrTenantMemberProtected
	}
	if scopes != 1 {
		return ErrTenantMemberShared
	}
	return ensureTenantMemberNotOutranksTx(ctx, tx, actor, userID)
}

// DeleteTenantMember deletes a sub-account of the actor's tenant scope: the
// user is disabled and marked deleted (identity_user_deletions, the same fact
// the platform user deletion writes), every session is revoked at once, and
// the deletion is audited. With transferTo the member's transferable
// resources go to that member first, in the same transaction. Resources that
// cannot change owner, or transferable ones left without transferTo, refuse
// the deletion (TenantMemberOwnsResourcesError). The user row stays, so audit
// events, ticket messages, grant history and deleted resources keep pointing
// at it; API keys and custom role grants stop working because both require an
// active user.
func (s *Service) DeleteTenantMember(ctx context.Context, actor Principal, userID uuid.UUID, transferTo *uuid.UUID, requestID string) error {
	if userID == uuid.Nil || requestID == "" {
		return ErrInvalidUserInput
	}
	return pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		if err := s.store.authorizeTenantMemberAdminTx(ctx, tx, actor); err != nil {
			return err
		}
		if err := lockTenantMemberTargetTx(ctx, tx, actor, userID); err != nil {
			return err
		}
		now := s.now().UTC()
		if transferTo != nil {
			if err := s.transferTenantMemberResourcesTx(ctx, tx, actor, userID, *transferTo, now, requestID); err != nil {
				return err
			}
		} else {
			blocking, err := tenantMemberBlockingResources(ctx, tx, actor.ScopeID, userID)
			if err != nil {
				return err
			}
			transferable, err := tenantMemberTransferableCount(ctx, tx, actor.ScopeID, userID)
			if err != nil {
				return err
			}
			if transferable > 0 || blocking != (TenantMemberBlockingResources{}) {
				blocking.Transferable = transferable
				return &TenantMemberOwnsResourcesError{Resources: blocking}
			}
		}
		var username string
		var revision int64
		if err := tx.QueryRow(ctx, `UPDATE users SET status='disabled',revision=revision+1,updated_at=$2
			WHERE id=$1 RETURNING username,revision`, userID, now).Scan(&username, &revision); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity_user_deletions(user_id,platform_scope_id,deleted_by_user_id,deleted_at,revision)
			VALUES($1,$2,$3,$4,$5)`, userID, actor.ScopeID, actor.UserID, now, revision); err != nil {
			return err
		}
		if err := revokeUserSessions(ctx, tx, userID, now, "account_deleted"); err != nil {
			return err
		}
		payload := map[string]any{"sessions_revoked": true, "revision": revision}
		if transferTo != nil {
			payload["transferred_to"] = transferTo.String()
		}
		return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: "identity.tenant_member.delete", ResourceType: "user", ResourceID: userID.String(), RequestID: requestID,
			Result: "success", Changes: []audit.Change{{Field: "username", Before: username, After: nil}},
			Payload: payload})
	})
}

func tenantMemberBlockingResources(ctx context.Context, tx pgx.Tx, scopeID, userID uuid.UUID) (TenantMemberBlockingResources, error) {
	var counts TenantMemberBlockingResources
	err := tx.QueryRow(ctx, tenantMemberBlockingResourcesSQL, scopeID, userID).
		Scan(&counts.PackageSubscriptions, &counts.L4Forwards, &counts.PackageSites)
	return counts, err
}

func tenantMemberTransferableCount(ctx context.Context, tx pgx.Tx, scopeID, userID uuid.UUID) (int64, error) {
	var total int64
	err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM sites WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL)+
		(SELECT count(*) FROM l4_stream_groups WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL)+
		(SELECT count(*) FROM certificate_assets WHERE tenant_scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL)+
		(SELECT count(*) FROM security_policies WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL)+
		(SELECT count(*) FROM url_auth_policies WHERE scope_id=$1 AND owner_user_id=$2)+
		(SELECT count(*) FROM cc_reference_matchers WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL AND NOT system_rule)+
		(SELECT count(*) FROM cc_reference_filters WHERE scope_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL AND NOT system_rule)`,
		scopeID, userID).Scan(&total)
	return total, err
}

// transferTenantMemberResourcesTx hands every transferable resource of
// userID to transferTo (an active, undeleted member of the actor's scope
// other than userID) and audits identity.tenant_member.resources.transfer
// with the count per kind. Resources whose owner cannot change refuse the
// handover (TenantMemberOwnsResourcesError), so a deletion or suspension never
// leaves them with a removed owner.
func (s *Service) transferTenantMemberResourcesTx(ctx context.Context, tx pgx.Tx, actor Principal, userID, transferTo uuid.UUID, now time.Time, requestID string) error {
	if transferTo == userID || transferTo == uuid.Nil {
		return ErrTenantMemberTransferTarget
	}
	var eligible bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id
		WHERE m.scope_id=$1 AND m.user_id=$2 AND m.status='active' AND u.status='active'
		  AND NOT EXISTS(SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id=u.id)
		FOR SHARE OF m,u)`, actor.ScopeID, transferTo).Scan(&eligible); err != nil {
		return err
	}
	if !eligible {
		return ErrTenantMemberTransferTarget
	}
	blocking, err := tenantMemberBlockingResources(ctx, tx, actor.ScopeID, userID)
	if err != nil {
		return err
	}
	if blocking != (TenantMemberBlockingResources{}) {
		return &TenantMemberOwnsResourcesError{Resources: blocking}
	}
	// 276 lets exactly this owner pair through, for this transaction only.
	if _, err := tx.Exec(ctx, `SELECT set_config('cdnca.tenant_member_handover',$1,true)`,
		userID.String()+":"+transferTo.String()); err != nil {
		return err
	}
	moved := make(map[string]any, len(tenantMemberTransfers))
	var total int64
	for _, transfer := range tenantMemberTransfers {
		args := []any{actor.ScopeID, userID, transferTo}
		if transfer.stamped {
			args = append(args, actor.UserID, now)
		}
		command, err := tx.Exec(ctx, transfer.sql, args...)
		if err != nil {
			return err
		}
		moved[transfer.kind] = command.RowsAffected()
		total += command.RowsAffected()
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('cdnca.tenant_member_handover','',true)`); err != nil {
		return err
	}
	if total == 0 {
		return nil
	}
	return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
		Action: "identity.tenant_member.resources.transfer", ResourceType: "user", ResourceID: userID.String(),
		RequestID: requestID, Result: "success",
		Changes: []audit.Change{{Field: "owner_user_id", Before: userID.String(), After: transferTo.String()}},
		Payload: map[string]any{"transferred_to": transferTo.String(), "resources": moved, "total": total}})
}
