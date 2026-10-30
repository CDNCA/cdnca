package domaintrust

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrDomainBlocked         = errors.New("domain is blocked by the platform")
	ErrDomainVerifiedByOther = errors.New("domain apex is verified by another account")
	ErrOwnershipRequired     = errors.New("domain ownership verification is required")
	ErrClaimSuspended        = errors.New("site has a domain suspended by an ownership claim")
)

// DomainError names the domain a site write was refused for. It matches
// ErrDomainBlocked, ErrDomainVerifiedByOther or ErrOwnershipRequired.
type DomainError struct {
	Err    error
	Domain string
	Apex   string
}

func (e *DomainError) Error() string { return e.Err.Error() + ": " + e.Domain }
func (e *DomainError) Unwrap() error { return e.Err }

// CheckSiteDomainsTx validates domains a site write activates (new domains
// only; existing ones are not re-judged, so the policy never retroactively
// disables a site):
//   - the platform blocklist applies to everyone, platform administrators
//     included, and never reveals its reason;
//   - an apex verified by another account refuses the domain (it can only be
//     taken over through that account's claim flow);
//   - with policy wildcard_only (default) a tenant must have verified the apex
//     before adding a wildcard, with policy all before adding any domain.
//
// Platform administrators act as operators and skip the verification step.
func CheckSiteDomainsTx(ctx context.Context, tx pgx.Tx, actorScopeKind string, scopeID uuid.UUID, domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	if domain, blocked, err := BlockedDomain(ctx, tx, domains); err != nil {
		return err
	} else if blocked {
		return &DomainError{Err: ErrDomainBlocked, Domain: domain}
	}
	policy, err := ReadPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if policy == PolicyOff {
		return nil
	}
	apexes := make([]string, 0, len(domains))
	apexOf := make(map[string]string, len(domains))
	for _, domain := range domains {
		apex, err := Apex(domain)
		if err != nil {
			continue
		}
		apexOf[domain] = apex
		apexes = append(apexes, apex)
	}
	if len(apexes) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT apex,scope_id FROM domain_ownerships
		WHERE status='verified' AND apex=ANY($1::text[])`, apexes)
	if err != nil {
		return err
	}
	owners := make(map[string]uuid.UUID, len(apexes))
	for rows.Next() {
		var apex string
		var owner uuid.UUID
		if err := rows.Scan(&apex, &owner); err != nil {
			rows.Close()
			return err
		}
		owners[apex] = owner
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, domain := range domains {
		apex, ok := apexOf[domain]
		if !ok {
			continue
		}
		owner, verified := owners[apex]
		if verified && owner != scopeID {
			return &DomainError{Err: ErrDomainVerifiedByOther, Domain: domain, Apex: apex}
		}
		if verified || actorScopeKind == "platform" {
			continue
		}
		if policy == PolicyAll || IsWildcard(domain) {
			return &DomainError{Err: ErrOwnershipRequired, Domain: domain, Apex: apex}
		}
	}
	return nil
}

// HasOpenSuspension reports whether a site is disabled by an unreleased claim.
func HasOpenSuspension(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (bool, error) {
	var open bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM domain_claim_suspensions
		WHERE scope_id=$1 AND site_id=$2 AND released_at IS NULL)`, scopeID, siteID).Scan(&open)
	return open, err
}
