package edgepublish

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// attachSiteStringSets gives every WAF binding whose rules name string sets
// the sets' current revisions. The scope reads its own and the
// platform's sets; an unusable set is left out, and compiling the rule then
// refuses the publication.
func attachSiteStringSets(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, bindings map[uuid.UUID][]securityBindingFact) error {
	var ids []uuid.UUID
	for _, siteBindings := range bindings {
		for _, binding := range siteBindings {
			for _, id := range securitypolicy.StringSetReferences(binding.policy.Rules) {
				if !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	sets, err := securitypolicy.LoadStringSetsTx(ctx, tx, scopeID, ids, false)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	for siteID := range bindings {
		for index := range bindings[siteID] {
			if len(securitypolicy.StringSetReferences(bindings[siteID][index].policy.Rules)) != 0 {
				bindings[siteID][index].stringSets = sets
			}
		}
	}
	return nil
}

// loadSiteStringSets fills facts[site].StringSets with the string sets the
// site's compiled rules reference (edgeconfig.WAFMatch.StringSets), each set
// once at the referenced revision, in id order: the scope's own and the
// platform's sets. Members come from security_string_set_revisions, so a
// publication rebuilt from an earlier compiled document still gets the
// revision it names; a reference that does not resolve is a refused
// publication (edgesite.Validate would refuse it too).
func loadSiteStringSets(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, source siteObjectsV2Source,
	facts map[string]siteObjectV2Facts) error {
	type key struct {
		id       string
		revision int64
	}
	bySite := map[string][]key{}
	var ids []string
	var revisions []int64
	for _, site := range source.Sites {
		var keys []key
		for _, listener := range site.Runtime.Listeners {
			if listener.Security == nil {
				continue
			}
			for _, policy := range listener.Security.Policies {
				for _, rule := range policy.Rules {
					for _, ref := range rule.Match.StringSets {
						k := key{ref.SetID, ref.Revision}
						if slices.Contains(keys, k) {
							continue
						}
						keys = append(keys, k)
						ids, revisions = append(ids, ref.SetID), append(revisions, ref.Revision)
					}
				}
			}
		}
		if len(keys) != 0 {
			bySite[site.Runtime.ID] = keys
		}
	}
	if len(bySite) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT s.id::text,r.revision,s.match_mode,s.case_sensitive,r.entries
		FROM unnest($1::uuid[],$2::bigint[]) wanted(id,revision)
		JOIN security_string_sets s ON s.id=wanted.id
		JOIN access_scopes owner ON owner.id=s.owner_scope_id
		JOIN security_string_set_revisions r ON r.set_id=wanted.id AND r.revision=wanted.revision
		WHERE s.owner_scope_id=$3 OR owner.kind='platform'`, ids, revisions, scopeID)
	if err != nil {
		return fmt.Errorf("%w: load string sets", ErrPersistence)
	}
	defer rows.Close()
	resolved := map[key]edgesite.StringSet{}
	for rows.Next() {
		var set edgesite.StringSet
		if err := rows.Scan(&set.ID, &set.Revision, &set.Mode, &set.CaseSensitive, &set.Members); err != nil {
			return fmt.Errorf("%w: scan string sets", ErrPersistence)
		}
		resolved[key{set.ID, set.Revision}] = set
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate string sets", ErrPersistence)
	}
	for siteID, keys := range bySite {
		sets := make([]edgesite.StringSet, 0, len(keys))
		for _, k := range keys {
			set, ok := resolved[k]
			if !ok {
				return fmt.Errorf("%w: site %s string set %s revision %d is not available", ErrUnsupportedSecurityPolicy,
					siteID, k.id, k.revision)
			}
			set.Members = slices.Clone(set.Members)
			sets = append(sets, set)
		}
		size := 0
		for _, set := range sets {
			for _, member := range set.Members {
				size += len(member)
			}
		}
		if len(sets) > edgeconfig.MaxSiteStringSets || size > edgeconfig.MaxSiteStringSetBytes {
			// at most 16 sets and 512 KiB of members per site.
			return fmt.Errorf("%w: site %s references %d string sets of %d bytes (at most %d sets, %d bytes)",
				ErrSecurityPolicyBudget, siteID, len(sets), size, edgeconfig.MaxSiteStringSets, edgeconfig.MaxSiteStringSetBytes)
		}
		slices.SortFunc(sets, func(left, right edgesite.StringSet) int { return strings.Compare(left.ID, right.ID) })
		value := facts[siteID]
		value.StringSets = sets
		facts[siteID] = value
	}
	return nil
}

// StringSetSite is one site bound to a policy that references a string set.
type StringSetSite struct {
	ScopeID uuid.UUID
	SiteID  uuid.UUID
}

// StringSetSitesTx are the tenant sites bound to a WAF policy whose active
// version references the string set setID, in scope / site order: a set
// change republishes their scopes (system trigger string_set).
func StringSetSitesTx(ctx context.Context, tx pgx.Tx, setID uuid.UUID) ([]StringSetSite, error) {
	if ctx == nil || tx == nil || setID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT binding.tenant_scope_id,binding.site_id FROM security_policy_site_bindings binding
		JOIN security_policy_versions version
		  ON version.policy_id=binding.policy_id AND version.revision=binding.active_policy_version
		JOIN access_scopes scope ON scope.id=binding.tenant_scope_id AND scope.kind='tenant'
		WHERE binding.policy_kind IN ('waf','acl') AND jsonb_path_exists(version.document,
		  '$.rules[*].conditions[*] ? ((@.operator == "in_string_set" || @.operator == "not_in_string_set") && @.values[0] == $id)',
		  jsonb_build_object('id', $1::text))
		ORDER BY binding.tenant_scope_id,binding.site_id`, setID)
	if err != nil {
		return nil, fmt.Errorf("%w: read string set scopes", ErrPersistence)
	}
	sites, err := pgx.CollectRows(rows, pgx.RowToStructByPos[StringSetSite])
	if err != nil {
		return nil, fmt.Errorf("%w: scan string set scopes", ErrPersistence)
	}
	return sites, nil
}
