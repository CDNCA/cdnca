package identity

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/ipallowlist"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Platform administration access allowlist. When
// enabled, every platform-scope sign-in, refresh and session
// request must come from an allowed address or CIDR prefix. Tenant sessions,
// API keys (which have their own allowlist) and tenant impersonation banners
// are not affected.
//
// Not locking yourself out:
//   - loopback (127.0.0.0/8, ::1) is always allowed, so an SSH tunnel to the
//     control host still reaches the console;
//   - saving refuses a policy that would not allow the saving request's own
//     address (ErrAdminAccessSelfLockout);
//   - `control-api admin-access-allowlist disable` (root on the control host,
//     DATABASE_URL) turns the policy off without any session.

const (
	adminAccessMaxEntries = 64
	adminAccessCacheTTL   = 5 * time.Second
)

var (
	ErrAdminAccessDenied       = errors.New("platform administration access denied from this address")
	ErrAdminAccessSelfLockout  = errors.New("platform administration allowlist would exclude the current address")
	ErrAdminAccessUnavailable  = errors.New("platform administration access policy unavailable")
	ErrAdminAccessRevision     = errors.New("platform administration access policy revision conflict")
	ErrAdminAccessInvalidInput = errors.New("platform administration access policy invalid")
)

// AdminAccessPolicy is the stored allowlist.
type AdminAccessPolicy struct {
	Revision  int64      `json:"revision"`
	Enabled   bool       `json:"enabled"`
	Allowlist []string   `json:"allowlist"`
	UpdatedAt *time.Time `json:"updated_at"`
}

type UpdateAdminAccessPolicyInput struct {
	ExpectedRevision int64
	Enabled          bool
	Allowlist        []string
	SourceIP         string
	RequestID        string
}

type adminAccessCache struct {
	mu       sync.Mutex
	policy   AdminAccessPolicy
	loadedAt time.Time
	loaded   bool
}

func readAdminAccessPolicy(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, lock bool) (AdminAccessPolicy, error) {
	policy := AdminAccessPolicy{Allowlist: []string{}}
	statement := `SELECT revision,enabled,allowlist,updated_at FROM platform_admin_access_policy WHERE singleton`
	if lock {
		statement += ` FOR UPDATE`
	}
	var updatedAt time.Time
	err := query.QueryRow(ctx, statement).Scan(&policy.Revision, &policy.Enabled, &policy.Allowlist, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return policy, nil
	}
	if err != nil {
		return AdminAccessPolicy{}, err
	}
	policy.UpdatedAt = &updatedAt
	return policy, nil
}

func (s *Service) cachedAdminAccessPolicy(ctx context.Context) (AdminAccessPolicy, error) {
	cache := &s.adminAccess
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.loaded && s.now().Sub(cache.loadedAt) < adminAccessCacheTTL {
		return cache.policy, nil
	}
	policy, err := readAdminAccessPolicy(ctx, s.store.pool, false)
	if err != nil {
		return AdminAccessPolicy{}, err
	}
	cache.policy, cache.loadedAt, cache.loaded = policy, s.now(), true
	return policy, nil
}

func (s *Service) forgetAdminAccessPolicy() {
	s.adminAccess.mu.Lock()
	s.adminAccess.loaded = false
	s.adminAccess.mu.Unlock()
}

func adminAccessAllows(policy AdminAccessPolicy, source string) bool {
	if !policy.Enabled {
		return true
	}
	address, err := netip.ParseAddr(source)
	if err != nil {
		return false
	}
	if address.Unmap().IsLoopback() {
		return true
	}
	return ipallowlist.Contains(policy.Allowlist, source)
}

// checkAdminAccess enforces the allowlist for a platform-scope principal.
// source is the client address; empty means unknown and is refused when
// the policy is on.
func (s *Service) checkAdminAccess(ctx context.Context, scopeKind, source string) error {
	if scopeKind != "platform" || s.store == nil || s.store.pool == nil {
		return nil
	}
	policy, err := s.cachedAdminAccessPolicy(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAdminAccessUnavailable, err)
	}
	if !adminAccessAllows(policy, source) {
		return ErrAdminAccessDenied
	}
	return nil
}

// checkAdminAccessForScope resolves the scope kind before a session exists.
func (s *Service) checkAdminAccessForScope(ctx context.Context, scopeID uuid.UUID, source string) error {
	if s.store == nil || s.store.pool == nil {
		return nil
	}
	policy, err := s.cachedAdminAccessPolicy(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAdminAccessUnavailable, err)
	}
	if !policy.Enabled {
		return nil
	}
	var kind string
	if err := s.store.pool.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1`, scopeID).Scan(&kind); err != nil {
		return fmt.Errorf("%w: %v", ErrAdminAccessUnavailable, err)
	}
	if kind == "platform" && !adminAccessAllows(policy, source) {
		return ErrAdminAccessDenied
	}
	return nil
}

// GetAdminAccessPolicy reads the stored policy (the HTTP adapter authorizes).
func (s *Service) GetAdminAccessPolicy(ctx context.Context) (AdminAccessPolicy, error) {
	policy, err := readAdminAccessPolicy(ctx, s.store.pool, false)
	if err != nil {
		return AdminAccessPolicy{}, fmt.Errorf("%w: %v", ErrAdminAccessUnavailable, err)
	}
	return policy, nil
}

// UpdateAdminAccessPolicy saves the policy with compare-and-set on revision.
// The caller must hold system_configuration.manage on the platform scope.
func (s *Service) UpdateAdminAccessPolicy(ctx context.Context, actor Principal, input UpdateAdminAccessPolicyInput) (AdminAccessPolicy, error) {
	if actor.ScopeKind != "platform" || actor.UserID == uuid.Nil || input.ExpectedRevision < 0 {
		return AdminAccessPolicy{}, ErrAdminAccessInvalidInput
	}
	allowlist, err := ipallowlist.Normalize(input.Allowlist, adminAccessMaxEntries)
	if err != nil || input.Enabled && len(allowlist) == 0 {
		return AdminAccessPolicy{}, ErrAdminAccessInvalidInput
	}
	next := AdminAccessPolicy{Enabled: input.Enabled, Allowlist: allowlist}
	if !adminAccessAllows(next, input.SourceIP) {
		return AdminAccessPolicy{}, ErrAdminAccessSelfLockout
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		current, err := readAdminAccessPolicy(ctx, tx, true)
		if err != nil {
			return err
		}
		if current.Revision != input.ExpectedRevision {
			return ErrAdminAccessRevision
		}
		next.Revision, next.UpdatedAt = current.Revision+1, &now
		if _, err := tx.Exec(ctx, `INSERT INTO platform_admin_access_policy(singleton,revision,enabled,allowlist,updated_by_user_id,updated_at)
			VALUES(true,$1,$2,$3,$4,$5) ON CONFLICT (singleton) DO UPDATE SET revision=EXCLUDED.revision,enabled=EXCLUDED.enabled,
			allowlist=EXCLUDED.allowlist,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
			next.Revision, next.Enabled, next.Allowlist, actor.UserID, now); err != nil {
			return err
		}
		return s.store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "system.admin_access.update",
			ResourceType: "platform_admin_access_policy", ResourceID: "platform", RequestID: input.RequestID, Result: "success",
			Changes: []audit.Change{
				{Field: "enabled", Before: current.Enabled, After: next.Enabled},
				{Field: "allowlist", Before: current.Allowlist, After: next.Allowlist},
			},
			Payload: map[string]any{"revision": next.Revision},
		})
	})
	if err != nil {
		if errors.Is(err, ErrAdminAccessRevision) {
			return AdminAccessPolicy{}, err
		}
		return AdminAccessPolicy{}, fmt.Errorf("%w: %v", ErrAdminAccessUnavailable, err)
	}
	s.forgetAdminAccessPolicy()
	return next, nil
}

// ReadAdminAccessPolicy reads the stored policy for the recovery CLI.
func (s *Store) ReadAdminAccessPolicy(ctx context.Context) (AdminAccessPolicy, error) {
	return readAdminAccessPolicy(ctx, s.pool, false)
}

// DisableAdminAccessPolicy is the recovery path for the root-local CLI: it
// turns the policy off (keeping the list) and audits a system action.
func (s *Store) DisableAdminAccessPolicy(ctx context.Context, requestID string) (AdminAccessPolicy, error) {
	var result AdminAccessPolicy
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := readAdminAccessPolicy(ctx, tx, true)
		if err != nil {
			return err
		}
		result = current
		if !current.Enabled {
			return nil
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		result.Enabled, result.Revision, result.UpdatedAt = false, current.Revision+1, &now
		if _, err := tx.Exec(ctx, `UPDATE platform_admin_access_policy SET enabled=false,revision=$1,updated_by_user_id=NULL,updated_at=$2 WHERE singleton`,
			result.Revision, now); err != nil {
			return err
		}
		var scopeID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY created_at, id LIMIT 1`).Scan(&scopeID); err != nil {
			return err
		}
		return s.auditor.Append(audit.WithActor(ctx, audit.ContextActor{Kind: audit.ActorSystem, Ref: "cli:admin-access-allowlist"}), tx, audit.Event{
			ScopeID: scopeID, Action: "system.admin_access.disable", ResourceType: "platform_admin_access_policy", ResourceID: "platform",
			RequestID: requestID, Result: "success",
			Changes: []audit.Change{{Field: "enabled", Before: true, After: false}},
			Payload: map[string]any{"revision": result.Revision},
		})
	})
	return result, err
}
