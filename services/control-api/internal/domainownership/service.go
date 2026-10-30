package domainownership

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool      *pgxpool.Pool
	auditor   Auditor
	verifier  Verifier
	notifier  Notifier
	publisher ClaimSuspensionPublisher
	now       func() time.Time
}

func NewService(pool *pgxpool.Pool, auditor Auditor, verifier Verifier, notifier Notifier, now func() time.Time) (*Service, error) {
	if pool == nil || auditor == nil || verifier == nil {
		return nil, ErrUnavailable
	}
	if now == nil {
		now = time.Now
	}
	return &Service{pool: pool, auditor: auditor, verifier: verifier, notifier: notifier,
		publisher: SystemRepublishPublisher{}, now: now}, nil
}

// WithClaimSuspensionPublisher replaces how sites disabled by a claim are
// published (default SystemRepublishPublisher).
func (s *Service) WithClaimSuspensionPublisher(publisher ClaimSuspensionPublisher) *Service {
	if publisher != nil {
		s.publisher = publisher
	}
	return s
}

const ownershipColumns = `id,scope_id,apex,method,status,token,verified_at,last_checked_at,
	last_failure_code,created_at,updated_at,revision`

func scanOwnership(row pgx.Row) (Ownership, error) {
	var item Ownership
	err := row.Scan(&item.ID, &item.ScopeID, &item.Apex, &item.Method, &item.Status, &item.Token,
		&item.VerifiedAt, &item.LastCheckedAt, &item.LastFailureCode, &item.CreatedAt, &item.UpdatedAt, &item.Revision)
	return item, err
}

func (s *Service) clock() time.Time { return s.now().UTC().Truncate(time.Microsecond) }

func validTenant(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.ScopeKind == "tenant"
}

func validPlatform(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.ScopeKind == "platform"
}

// authorizeTenant requires an active member of an active tenant scope holding
// the permission through the tenant's effective (custom) RBAC.
func authorizeTenant(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if !validTenant(actor) {
		return ErrPermissionDenied
	}
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM access_scopes scope
			JOIN tenants tenant ON tenant.id=scope.tenant_id
			JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=$2
			JOIN users account ON account.id=membership.user_id
			WHERE scope.id=$1 AND scope.kind='tenant' AND tenant.status='active' AND
			      membership.status='active' AND account.status='active'
		) AND EXISTS(SELECT 1 FROM custom_rbac_effective_permissions($1,$2) WHERE permission_name=$3)`,
		actor.ScopeID, actor.UserID, permission).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

func authorizePlatform(ctx context.Context, tx pgx.Tx, actor Actor) error {
	if !validPlatform(actor) {
		return ErrPermissionDenied
	}
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM access_scopes scope
			JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=$2
			JOIN users account ON account.id=membership.user_id
			WHERE scope.id=$1 AND scope.kind='platform' AND scope.tenant_id IS NULL AND
			      membership.status='active' AND account.status='active'
		) AND EXISTS(
			SELECT 1 FROM role_assignments assignment
			JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
			JOIN role_permissions grant_row ON grant_row.role_id=role.id
			WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND
			      grant_row.permission_name IN ($3,'platform.admin')
		)`, actor.ScopeID, actor.UserID, PermissionManage).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

func requirePolicy(ctx context.Context, tx pgx.Tx) error {
	policy, err := domaintrust.ReadPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if policy == domaintrust.PolicyOff {
		return ErrPolicyOff
	}
	return nil
}

// normalizeApex accepts any domain under the apex (or a wildcard) and
// returns the apex the proof is bound to.
func normalizeApex(raw string) (string, error) {
	domain, err := domaintrust.Normalize(raw, true)
	if err != nil {
		return "", ErrInvalidInput
	}
	apex, err := domaintrust.Apex(domain)
	if err != nil {
		return "", ErrInvalidInput
	}
	return apex, nil
}

func newToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func validMethod(method string) bool { return method == MethodDNSTXT || method == MethodHTTPFile }

// Start creates or refreshes the caller's challenge for the apex of domain.
// A verified proof is returned unchanged; a revoked one gets a new token.
func (s *Service) Start(ctx context.Context, actor Actor, domain, method, requestID string) (Ownership, error) {
	apex, err := normalizeApex(domain)
	if err != nil || !validMethod(method) || !domaintrust.ValidMetadata(requestID) {
		return Ownership{}, ErrInvalidInput
	}
	var result Ownership
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTenant(ctx, tx, actor, "sites.manage"); err != nil {
			return err
		}
		if err := requirePolicy(ctx, tx); err != nil {
			return err
		}
		if _, blocked, err := domaintrust.BlockedDomain(ctx, tx, []string{apex}); err != nil {
			return err
		} else if blocked {
			return ErrBlocked
		}
		now := s.clock()
		existing, err := scanOwnership(tx.QueryRow(ctx, `SELECT `+ownershipColumns+` FROM domain_ownerships
			WHERE scope_id=$1 AND apex=$2 FOR UPDATE`, actor.ScopeID, apex))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			token, err := newToken()
			if err != nil {
				return err
			}
			result, err = scanOwnership(tx.QueryRow(ctx, `INSERT INTO domain_ownerships(
				id,scope_id,apex,method,token,status,created_by_user_id,created_at,updated_at
			) VALUES($1,$2,$3,$4,$5,'pending',$6,$7,$7) RETURNING `+ownershipColumns,
				uuid.New(), actor.ScopeID, apex, method, token, actor.UserID, now))
			if err != nil {
				return err
			}
		case err != nil:
			return err
		case existing.Status == StatusVerified:
			result = existing
			return nil
		default:
			token := existing.Token
			if existing.Status == StatusRevoked {
				if token, err = newToken(); err != nil {
					return err
				}
			}
			result, err = scanOwnership(tx.QueryRow(ctx, `UPDATE domain_ownerships SET method=$2,token=$3,
				status='pending',last_failure_code='',updated_at=$4,
				revision=revision+1 WHERE id=$1 RETURNING `+ownershipColumns, existing.ID, method, token, now))
			if err != nil {
				return err
			}
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "domain_ownership.start",
			ResourceType: "domain_ownership", ResourceID: result.ID.String(), RequestID: requestID, Result: "success",
			Payload: map[string]any{"apex": apex, "method": method, "revision": result.Revision},
		})
	})
	if err != nil {
		return Ownership{}, fmt.Errorf("start domain ownership: %w", err)
	}
	return withChallenge(result), nil
}

func (s *Service) verify(ctx context.Context, item Ownership) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, verificationBudget)
	defer cancel()
	var ok bool
	var code string
	var err error
	if item.Method == MethodDNSTXT {
		ok, code, err = s.verifier.VerifyTXT(ctx, txtName(item.Apex), item.Token)
	} else {
		ok, code, err = s.verifier.VerifyHTTP(ctx, item.Apex, item.Token)
	}
	if err != nil {
		return false, "check_unavailable"
	}
	if !ok && code == "" {
		code = "verification_failed"
	}
	return ok, code
}

// Check runs the caller's challenge now. A failed check keeps the record and
// reports last_failure_code; a successful one verifies the apex, which then
// stays verified (user decision 10-17: no recheck, only an administrator's
// revoke ends it). Another account's verified proof refuses the apex, except
// that a DNS TXT proof supersedes an HTTP file proof (an HTTP file can be
// answered by whoever the domain's traffic reaches, including a squatter on
// this CDN).
func (s *Service) Check(ctx context.Context, actor Actor, domain, requestID string) (Ownership, error) {
	apex, err := normalizeApex(domain)
	if err != nil || !domaintrust.ValidMetadata(requestID) {
		return Ownership{}, ErrInvalidInput
	}
	var current Ownership
	var holder *Ownership
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTenant(ctx, tx, actor, "sites.manage"); err != nil {
			return err
		}
		if err := requirePolicy(ctx, tx); err != nil {
			return err
		}
		current, err = scanOwnership(tx.QueryRow(ctx, `SELECT `+ownershipColumns+` FROM domain_ownerships
			WHERE scope_id=$1 AND apex=$2 AND status<>'revoked'`, actor.ScopeID, apex))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		other, err := scanOwnership(tx.QueryRow(ctx, `SELECT `+ownershipColumns+` FROM domain_ownerships
			WHERE apex=$1 AND status='verified' AND scope_id<>$2`, apex, actor.ScopeID))
		if err == nil {
			holder = &other
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return nil
	})
	if err != nil {
		return Ownership{}, fmt.Errorf("check domain ownership: %w", err)
	}
	supersede := false
	if holder != nil {
		if current.Method != MethodDNSTXT || holder.Method != MethodHTTPFile {
			return Ownership{}, fmt.Errorf("check domain ownership: %w", ErrVerifiedByOther)
		}
		supersede = true
	}
	ok, code := s.verify(ctx, current)
	if !ok {
		supersede = false
	}
	var result Ownership
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.clock()
		if !ok {
			// A failed check never downgrades a verified proof.
			result, err = scanOwnership(tx.QueryRow(ctx, `UPDATE domain_ownerships SET last_checked_at=$2,
				last_failure_code=$3,updated_at=$2,revision=revision+1
				WHERE id=$1 AND revision=$4 RETURNING `+ownershipColumns, current.ID, now, code, current.Revision))
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrRevisionConflict
			}
			return err
		}
		ids := []uuid.UUID{current.ID}
		if supersede {
			ids = append(ids, holder.ID)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
		if _, err := tx.Exec(ctx, `SELECT 1 FROM domain_ownerships WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, ids); err != nil {
			return err
		}
		if supersede {
			command, err := tx.Exec(ctx, `UPDATE domain_ownerships SET status='expired',
				last_failure_code=$3,updated_at=$2,revision=revision+1
				WHERE id=$1 AND revision=$4 AND status='verified'`, holder.ID, now, failureSuperseded, holder.Revision)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
		}
		result, err = scanOwnership(tx.QueryRow(ctx, `UPDATE domain_ownerships SET status='verified',
			verified_at=CASE WHEN status='verified' THEN verified_at ELSE $2 END,last_checked_at=$2,last_failure_code='',
			updated_at=$2,revision=revision+1 WHERE id=$1 AND revision=$3 AND status<>'revoked'
			RETURNING `+ownershipColumns, current.ID, now, current.Revision))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if uniqueViolation(err) {
			return ErrVerifiedByOther
		}
		if err != nil {
			return err
		}
		events := []audit.Event{{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "domain_ownership.verify",
			ResourceType: "domain_ownership", ResourceID: result.ID.String(), RequestID: requestID, Result: "success",
			Payload: map[string]any{"apex": apex, "method": result.Method, "superseded_other": supersede},
		}}
		if supersede {
			events = append(events, audit.Event{
				ScopeID: holder.ScopeID, ActorUserID: &actor.UserID, Action: "domain_ownership.superseded",
				ResourceType: "domain_ownership", ResourceID: holder.ID.String(), RequestID: requestID, Result: "success",
				Payload: map[string]any{"apex": apex, "method": holder.Method, "superseding_method": result.Method},
			})
		}
		return appendOrdered(ctx, tx, s.auditor, events)
	})
	if err != nil {
		return Ownership{}, fmt.Errorf("check domain ownership: %w", err)
	}
	return withChallenge(result), nil
}

// Revoke withdraws the caller's proof; existing suspensions stay until the
// suspended sites drop the domain or an administrator releases them.
func (s *Service) Revoke(ctx context.Context, actor Actor, domain, requestID string) (Ownership, error) {
	apex, err := normalizeApex(domain)
	if err != nil || !domaintrust.ValidMetadata(requestID) {
		return Ownership{}, ErrInvalidInput
	}
	var result Ownership
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTenant(ctx, tx, actor, "sites.manage"); err != nil {
			return err
		}
		result, err = revokeTx(ctx, tx, s.auditor, actor, actor.ScopeID, apex, requestID, s.clock())
		return err
	})
	if err != nil {
		return Ownership{}, fmt.Errorf("revoke domain ownership: %w", err)
	}
	return result, nil
}

func revokeTx(ctx context.Context, tx pgx.Tx, auditor Auditor, actor Actor, scopeID uuid.UUID, apex, requestID string, now time.Time) (Ownership, error) {
	result, err := scanOwnership(tx.QueryRow(ctx, `UPDATE domain_ownerships SET status='revoked',
		updated_at=$3,revision=revision+1 WHERE scope_id=$1 AND apex=$2 AND status<>'revoked'
		RETURNING `+ownershipColumns, scopeID, apex, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return Ownership{}, ErrNotFound
	}
	if err != nil {
		return Ownership{}, err
	}
	events := []audit.Event{{
		ScopeID: scopeID, ActorUserID: &actor.UserID, Action: "domain_ownership.revoke",
		ResourceType: "domain_ownership", ResourceID: result.ID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{"apex": apex, "actor_scope_id": actor.ScopeID.String()},
	}}
	if actor.ScopeID != scopeID {
		events = append(events, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "domain_ownership.admin_revoke",
			ResourceType: "domain_ownership", ResourceID: result.ID.String(), RequestID: requestID, Result: "success",
			Payload: map[string]any{"apex": apex, "target_scope_id": scopeID.String()},
		})
	}
	return result, appendOrdered(ctx, tx, auditor, events)
}

// List returns the caller's proofs with their challenges.
func (s *Service) List(ctx context.Context, actor Actor) ([]Ownership, error) {
	var items []Ownership
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTenant(ctx, tx, actor, "sites.read"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+ownershipColumns+` FROM domain_ownerships
			WHERE scope_id=$1 AND status<>'revoked' ORDER BY apex LIMIT $2`, actor.ScopeID, maxListLimit)
		if err != nil {
			return err
		}
		items, err = collectOwnerships(rows, true)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list domain ownerships: %w", err)
	}
	return items, nil
}

func collectOwnerships(rows pgx.Rows, challenge bool) ([]Ownership, error) {
	defer rows.Close()
	items := make([]Ownership, 0)
	for rows.Next() {
		item, err := scanOwnership(rows)
		if err != nil {
			return nil, err
		}
		if challenge {
			item = withChallenge(item)
		} else {
			item.Token = ""
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// appendOrdered writes audit events in scope order (audit streams take a
// per-scope advisory lock).
func appendOrdered(ctx context.Context, tx pgx.Tx, auditor Auditor, events []audit.Event) error {
	sort.SliceStable(events, func(i, j int) bool { return events[i].ScopeID.String() < events[j].ScopeID.String() })
	for _, event := range events {
		if err := auditor.Append(ctx, tx, event); err != nil {
			return err
		}
	}
	return nil
}

func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
