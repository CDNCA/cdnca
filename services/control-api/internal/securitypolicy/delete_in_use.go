package securitypolicy

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// InUseError names (up to inUseSiteLimit of) the sites a policy still runs
// on. errors.Is(err, ErrInUse) holds.
type InUseError struct {
	Domains []string
	// SiteIDs[i] is the site of Domains[i] (sec-ui-polish: the page links
	// each to its security publish panel).
	SiteIDs []uuid.UUID
}

const inUseSiteLimit = 5

func (e *InUseError) Error() string {
	return ErrInUse.Error() + ": " + strings.Join(e.Domains, ", ")
}

func (e *InUseError) Unwrap() error { return ErrInUse }

// refuseDeleteInUse (D3) refuses to delete a policy a site still enforces
// or is moving to. In use means: a binding's active library is this one and
// its active version is enabled, or an activation claiming this library (a
// publish, a rebind to it) is still in flight. Bindings whose active version
// is disabled do not block, nor do bindings that moved to another library
// or were detached (sec-rebind, migration 470); the page detaches or rebinds
// a site first. An in-flight detach of this library does not block either:
// the delete just lands before the withdrawal does. The caller holds the
// policy row lock, which activation start also takes, so no start races this.
func refuseDeleteInUse(ctx context.Context, tx pgx.Tx, policy Policy) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT site.domain, site.id
		FROM security_policy_site_bindings binding
		JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id
		LEFT JOIN security_policy_versions version
		  ON version.policy_id=binding.policy_id AND version.revision=binding.active_policy_version
		WHERE binding.tenant_scope_id=$1 AND site.deleted_at IS NULL
		  AND ((binding.policy_id=$2 AND COALESCE((version.document->>'enabled')::boolean, false))
		       OR EXISTS (SELECT 1 FROM security_policy_activation_candidates candidate
		                  JOIN security_policy_publications publication
		                    ON publication.tenant_scope_id=candidate.tenant_scope_id
		                   AND publication.id=candidate.last_bundle_id
		                  WHERE candidate.tenant_scope_id=binding.tenant_scope_id
		                    AND candidate.binding_id=binding.id
		                    AND publication.policy_id=$2 AND NOT publication.detach
		                    AND candidate.candidate_status IN ('claimed','canary','expanding','healthy')))
		ORDER BY site.domain LIMIT $3`, policy.ScopeID, policy.ID, inUseSiteLimit)
	if err != nil {
		return err
	}
	inUse := &InUseError{}
	var domain string
	var siteID uuid.UUID
	if _, err := pgx.ForEachRow(rows, []any{&domain, &siteID}, func() error {
		inUse.Domains, inUse.SiteIDs = append(inUse.Domains, domain), append(inUse.SiteIDs, siteID)
		return nil
	}); err != nil {
		return err
	}
	if len(inUse.Domains) > 0 {
		return inUse
	}
	return nil
}
