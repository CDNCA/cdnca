package edgepublish

import (
	"context"
	"fmt"
	"slices"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// attachSiteIPLists gives every ACL / WAF binding whose rules name IP lists
// the lists' current contents. The scope reads its own
// and the platform's lists; an unusable list is left out, and compiling the
// rule then refuses the publication.
func attachSiteIPLists(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, bindings map[uuid.UUID][]securityBindingFact) error {
	var ids []uuid.UUID
	for _, siteBindings := range bindings {
		for _, binding := range siteBindings {
			for _, id := range securitypolicy.IPListReferences(binding.policy.Rules) {
				if !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	lists, err := securitypolicy.LoadIPListsTx(ctx, tx, scopeID, ids)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	for siteID := range bindings {
		for index := range bindings[siteID] {
			if len(securitypolicy.IPListReferences(bindings[siteID][index].policy.Rules)) != 0 {
				bindings[siteID][index].ipLists = lists
			}
		}
	}
	return nil
}

// IPListSite is one site bound to a policy that references an IP list.
type IPListSite struct {
	ScopeID uuid.UUID
	SiteID  uuid.UUID
}

// IPListSitesTx are the tenant sites bound to a policy whose active version
// references the IP list listID, in scope / site order: a list change
// republishes their scopes (system trigger ip_list).
func IPListSitesTx(ctx context.Context, tx pgx.Tx, listID uuid.UUID) ([]IPListSite, error) {
	if ctx == nil || tx == nil || listID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT binding.tenant_scope_id,binding.site_id FROM security_policy_site_bindings binding
		JOIN security_policy_versions version
		  ON version.policy_id=binding.policy_id AND version.revision=binding.active_policy_version
		JOIN access_scopes scope ON scope.id=binding.tenant_scope_id AND scope.kind='tenant'
		WHERE binding.policy_kind IN ('waf','acl') AND jsonb_path_exists(version.document,
		  '$.rules[*].conditions[*] ? (@.field == "ip_list" && @.values[0] == $id)', jsonb_build_object('id', $1::text))
		ORDER BY binding.tenant_scope_id,binding.site_id`, listID)
	if err != nil {
		return nil, fmt.Errorf("%w: read IP list scopes", ErrPersistence)
	}
	sites, err := pgx.CollectRows(rows, pgx.RowToStructByPos[IPListSite])
	if err != nil {
		return nil, fmt.Errorf("%w: scan IP list scopes", ErrPersistence)
	}
	return sites, nil
}
